# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (c) 2026 CommonHuman-Lab
"""Translate a GloomProxy ScanContext into VaultRip ScanOptions.

VaultRip is a filesystem/post-exploitation tool — not an HTTP scanner.
When running under GloomProxy orchestration:
  - ctx.target.url identifies the target for graph connectivity
  - ctx.config["scan_path"] (default "~") is the actual path to sweep
  - SSH params can be injected via ctx.config if remote sweep is needed
"""
from __future__ import annotations

from gloomproxy_sdk import ScanContext

from vaultrip.engine._scanner.options import ScanOptions


def build_options(ctx: ScanContext) -> ScanOptions:
    """Build VaultRip ScanOptions from a GloomProxy ScanContext."""
    cfg = ctx.config

    ssh_creds: dict = cfg.get("ssh", {})

    return ScanOptions(
        # Scope
        target_user=cfg.get("target_user"),
        # Module toggles
        local=bool(cfg.get("local", True)),
        memory=bool(cfg.get("memory", False)),  # off by default — requires elevated privileges
        browser=bool(cfg.get("browser", True)),
        system=bool(cfg.get("system", True)),
        kerberos=bool(cfg.get("kerberos", False)),
        dumps=bool(cfg.get("dumps", False)),
        # Remote sweep via SSH
        remote=bool(ssh_creds),
        ssh_host=ssh_creds.get("host", ""),
        ssh_user=ssh_creds.get("user", ""),
        ssh_key=ssh_creds.get("key", ""),
        ssh_password=ssh_creds.get("password", ""),
        ssh_port=int(ssh_creds.get("port", 22)),
        # Never write output files in distributed mode
        output="",
        timeout=int(cfg.get("timeout", 60)),
    )
