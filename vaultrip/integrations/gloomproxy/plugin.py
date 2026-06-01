# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (c) 2026 CommonHuman-Lab
"""GloomProxy plugin wrapper for VaultRip.

Thin adapter only — all harvesting logic lives in vaultrip.engine.

VaultRip is a post-exploitation tool that sweeps a host for credential
material. Under GloomProxy orchestration it should be used after gaining
access to a target host, either locally or via SSH.

The scan target URL is used for graph connectivity (findings.target) only.
The actual sweep path is controlled via ctx.config["scan_path"].
"""
from __future__ import annotations

import asyncio
import logging

from gloomproxy_sdk import BaseScanner, Finding, ScanContext, Target, ScanOptionDef
from gloomproxy_sdk.capabilities import PluginCapabilities
from gloomproxy_sdk.manifest import PluginManifest, TrustLevel

from .adapter import build_options
from .mapper import map_results
from .metadata import CAPABILITIES

log = logging.getLogger(__name__)


class VaultRipPlugin(BaseScanner):
    name = "vaultrip"
    version = "0.1.0"
    description = "Post-exploitation credential harvesting and extraction engine"
    author = "CommonHuman-Lab"
    tags = ["credentials", "post-exploitation", "passive"]

    @classmethod
    def capabilities(cls) -> PluginCapabilities:
        return CAPABILITIES

    @classmethod
    def manifest(cls) -> PluginManifest:
        return {
            "trust_level": TrustLevel.CORE,
            "resources": {"max_runtime": 600, "max_findings": 5000},
            "sdk_min_version": "0.1.0",
        }

    @classmethod
    def option_schema(cls) -> list[ScanOptionDef]:
        return [
            {"key": "memory",   "label": "Memory dump",      "type": "bool", "default": False, "description": "Dump process memory (requires elevated privileges)"},
            {"key": "kerberos", "label": "Kerberos tickets", "type": "bool", "default": False, "description": "Extract cached Kerberos tickets"},
            {"key": "dumps",    "label": "Crash dumps",       "type": "bool", "default": False, "description": "Parse crash/minidump files"},
            {"key": "browser",  "label": "Browser creds",    "type": "bool", "default": True,  "description": "Extract browser saved passwords and cookies"},
        ]

    def initialize(self, context: ScanContext) -> None:
        self._options = build_options(context)
        # Scan path for the actual filesystem sweep
        self._scan_path: str = context.config.get("scan_path", "~")

    async def scan(self, target: Target) -> list[Finding]:
        from vaultrip.engine.scanner import scan as vaultrip_scan

        options = self._options
        scan_path = self._scan_path

        await self.ctx.events.progress("Starting VaultRip credential sweep", 0.0)

        try:
            result = await asyncio.get_event_loop().run_in_executor(
                None, vaultrip_scan, scan_path, options
            )
        except Exception as exc:
            log.exception("VaultRip engine error for path %s", scan_path)
            await self.ctx.events.debug(f"VaultRip engine error: {exc}")
            return []

        # Use target.url so findings link to the target node in the graph
        findings = map_results(result, target.url)

        await self.ctx.events.progress(
            f"VaultRip complete — {len(findings)} credential(s) found", 1.0
        )
        log.info("VaultRip: %d finding(s) for path %s", len(findings), scan_path)
        return findings
