# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (c) 2026 CommonHuman-Lab
"""
Local filesystem credential sweep.

Walks home directories and known system paths, checks for credential files
using the commonhuman_payloads.creds.paths catalogue, and pattern-scans text
files using commonhuman_payloads.creds.patterns.
"""

from __future__ import annotations

import logging
import os
import stat

from commonhuman_payloads.creds.paths import (
    ALL_HOME_PATHS,
    ALL_SYSTEM_PATHS,
    INTERESTING_EXTENSIONS,
    INTERESTING_FILENAMES,
    CredPath,
)
from commonhuman_payloads.creds.patterns import ALL_PATTERNS, CredPattern
from commonhuman_payloads.creds.signatures import is_dump_file

from ..reporter import Confidence, FileCredFinding, ScanResult
from .passive import PassiveInfo

log = logging.getLogger("vaultrip.local")

# Content file size limit — don't pattern-scan files larger than this
_MAX_SCAN_BYTES = 512 * 1024  # 512 KB


def run(result: ScanResult, passive: PassiveInfo) -> None:
    """Sweep all accessible home dirs and system paths for credential files."""
    for home in passive.home_dirs:
        _sweep_home(result, home)

    if passive.is_root:
        for cred_path in ALL_SYSTEM_PATHS:
            _check_absolute(result, cred_path)


# ---------------------------------------------------------------------------
# Home directory sweep
# ---------------------------------------------------------------------------

def _sweep_home(result: ScanResult, home: str) -> None:
    for cred_path in ALL_HOME_PATHS:
        full_path = os.path.join(home, cred_path.pattern)
        if os.path.isfile(full_path):
            _record_file(result, full_path, cred_path)
        elif os.path.isdir(full_path):
            _sweep_dir(result, full_path, cred_path)

    # Walk the home dir looking for interesting filenames / extensions
    _walk_interesting(result, home)


def _sweep_dir(result: ScanResult, dirpath: str, cred_path: CredPath) -> None:
    try:
        for entry in os.scandir(dirpath):
            if entry.is_file(follow_symlinks=False):
                _record_file(result, entry.path, cred_path)
    except PermissionError:
        pass


def _walk_interesting(result: ScanResult, home: str) -> None:
    """Walk up to depth 4, flagging files with interesting names/extensions."""
    for dirpath, dirs, files in os.walk(home):
        depth = dirpath[len(home):].count(os.sep)
        if depth >= 4:
            dirs.clear()
            continue
        # Skip hidden dirs deeper than level 1 (already handled by catalogue)
        dirs[:] = [
            d for d in dirs
            if not (depth > 0 and d.startswith("."))
            and d not in (".git", "node_modules", "__pycache__", ".venv", "venv")
        ]
        for fname in files:
            ext = os.path.splitext(fname)[1].lower()
            if fname in INTERESTING_FILENAMES or ext in INTERESTING_EXTENSIONS:
                fpath = os.path.join(dirpath, fname)
                _pattern_scan_file(result, fpath)


# ---------------------------------------------------------------------------
# System paths (absolute)
# ---------------------------------------------------------------------------

def _check_absolute(result: ScanResult, cred_path: CredPath) -> None:
    path = cred_path.pattern
    if os.path.isfile(path):
        _record_file(result, path, cred_path)
    elif os.path.isdir(path):
        _sweep_dir(result, path, cred_path)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _record_file(result: ScanResult, path: str, cred_path: CredPath) -> None:
    try:
        st = os.stat(path)
    except OSError:
        return

    # Check if it's a recognised dump format
    if cred_path.cred_type == "database":
        dump_sig = is_dump_file(path)
        if dump_sig:
            log.info("dump signature found: %s → %s", path, dump_sig.name)

    # Flag passphrase-less private keys with HIGH confidence
    confidence = Confidence.HIGH if cred_path.cred_type == "private_key" else Confidence.MEDIUM
    if cred_path.cred_type == "private_key":
        confidence = _assess_key_confidence(path)

    result.append_file(FileCredFinding(
        path=path,
        service=cred_path.service,
        credential_type=cred_path.cred_type,
        confidence=confidence,
        value=None,
    ))
    log.info("file: [%s] %s → %s", cred_path.service, cred_path.cred_type, path)

    # For text-based config files, also pattern-scan content
    if cred_path.cred_type in ("config", "history", "password") and st.st_size < _MAX_SCAN_BYTES:
        _pattern_scan_file(result, path)


def _assess_key_confidence(path: str) -> Confidence:
    """Return HIGH if the key file appears unencrypted (no ENCRYPTED header)."""
    try:
        with open(path, "rb") as fh:
            header = fh.read(512).decode("ascii", errors="ignore")
        if "ENCRYPTED" in header or "Proc-Type: 4,ENCRYPTED" in header:
            return Confidence.MEDIUM
        return Confidence.HIGH
    except OSError:
        return Confidence.MEDIUM


def _pattern_scan_file(result: ScanResult, path: str) -> None:
    """Scan a text file's content against all credential regex patterns."""
    try:
        st = os.stat(path)
        if st.st_size > _MAX_SCAN_BYTES or not stat.S_ISREG(st.st_mode):
            return
        with open(path, errors="replace") as fh:
            content = fh.read(_MAX_SCAN_BYTES)
    except OSError:
        return

    for pattern in ALL_PATTERNS:
        match = pattern.pattern.search(content)
        if not match:
            continue
        value = match.group(1) if match.lastindex else match.group(0)
        confidence = Confidence.HIGH if pattern.confidence == "high" else Confidence.MEDIUM
        result.append_file(FileCredFinding(
            path=path,
            service=_service_from_pattern(pattern),
            credential_type=pattern.cred_type,
            confidence=confidence,
            value=value[:200],  # truncate to avoid storing huge blobs
        ))
        log.info("pattern match [%s] in %s", pattern.name, path)


def _service_from_pattern(pattern: CredPattern) -> str:
    name = pattern.name.lower()
    for svc in ("aws", "gcp", "azure", "github", "gitlab", "slack", "stripe",
                "postgres", "mysql", "mongodb", "redis", "jwt", "anthropic", "openai"):
        if svc in name:
            return svc
    return "generic"
