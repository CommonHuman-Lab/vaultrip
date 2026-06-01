# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (c) 2026 CommonHuman-Lab
"""Map native VaultRip findings → GloomProxy SDK Finding objects."""
from __future__ import annotations

from gloomproxy_sdk import Finding

from vaultrip.engine.reporter import (
    BrowserCredFinding,
    FileCredFinding,
    ScanResult,
    SystemCredFinding,
)

_SCANNER = "vaultrip"

# Confidence enum → float
_CONF_MAP = {"high": 0.95, "medium": 0.75, "low": 0.50}


def _map_file_cred(f: FileCredFinding, target_url: str) -> Finding:
    masked = "***" if f.value else "(unparsed)"
    return Finding(
        scanner=_SCANNER,
        type="file_credential",
        severity="high",
        target=target_url,
        evidence=f"{f.credential_type} for {f.service} found at {f.path}",
        title=f"Credential File — {f.service} ({f.credential_type})",
        description=f"Credential material for '{f.service}' located at '{f.path}'.",
        confidence=_CONF_MAP.get(str(f.confidence).lower(), 0.75),
        extra={"path": f.path, "service": f.service, "credential_type": f.credential_type, "value": masked},
        tags=["credential", "file", f"service:{f.service}"],
    )


def _map_browser_cred(f: BrowserCredFinding, target_url: str) -> Finding:
    return Finding(
        scanner=_SCANNER,
        type="browser_credential",
        severity="high",
        target=target_url,
        evidence=f"Saved login for {f.url} in {f.browser} credential store (user: {f.username})",
        title=f"Browser Credential — {f.browser}",
        description=f"Saved credential recovered from {f.browser} for {f.url}.",
        confidence=0.95,
        extra={"browser": f.browser, "url": f.url, "username": f.username, "password": "***" if f.password else None},
        tags=["credential", "browser", f"browser:{f.browser}"],
    )


def _map_system_cred(f: SystemCredFinding, target_url: str) -> Finding:
    return Finding(
        scanner=_SCANNER,
        type="system_credential",
        severity="high",
        target=target_url,
        evidence=f"Credential from {f.store} keyring — label: {f.label}",
        title=f"System Keyring Credential — {f.store}",
        description=f"Credential recovered from system keyring '{f.store}'.",
        confidence=0.90,
        extra={"store": f.store, "label": f.label, "username": f.username, "secret": "***" if f.secret else None},
        tags=["credential", "keyring", f"store:{f.store}"],
    )


_GENERIC_MAPPERS = {
    "file_creds": ("file_credential", "high"),
    "browser_creds": ("browser_credential", "high"),
    "system_creds": ("system_credential", "high"),
    "memory_creds": ("memory_credential", "critical"),
    "kerberos_tickets": ("kerberos_ticket", "critical"),
    "dump_creds": ("dump_credential", "critical"),
    "dcsync_creds": ("dcsync_credential", "critical"),
    "pth_results": ("pth_result", "critical"),
    "forged_tickets": ("forged_ticket", "critical"),
}


def _map_generic(attr: str, ftype: str, severity: str, f: object, target_url: str) -> Finding | None:
    evidence = getattr(f, "evidence", None) or str(f)[:200]
    return Finding(
        scanner=_SCANNER,
        type=ftype,
        severity=severity,
        target=target_url,
        evidence=evidence,
        confidence=0.80,
        tags=["credential", attr.rstrip("s")],
    )


def map_results(result: ScanResult, target_url: str) -> list[Finding]:
    """Convert a VaultRip ScanResult into a list of SDK Finding objects.

    target_url is the GloomProxy scan target (used for graph connectivity).
    """
    findings: list[Finding] = []

    for f in result.file_creds:
        try:
            findings.append(_map_file_cred(f, target_url).validate())
        except Exception:
            pass

    for f in result.browser_creds:
        try:
            findings.append(_map_browser_cred(f, target_url).validate())
        except Exception:
            pass

    for f in result.system_creds:
        try:
            findings.append(_map_system_cred(f, target_url).validate())
        except Exception:
            pass

    for attr, (ftype, severity) in _GENERIC_MAPPERS.items():
        if attr in ("file_creds", "browser_creds", "system_creds"):
            continue
        for f in getattr(result, attr, []):
            try:
                ff = _map_generic(attr, ftype, severity, f, target_url)
                if ff:
                    findings.append(ff.validate())
            except Exception:
                pass

    return findings
