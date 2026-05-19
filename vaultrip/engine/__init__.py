# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (c) 2026 CommonHuman-Lab
"""VaultRip engine — public API."""

from ._scanner.options import ScanOptions
from .reporter import (
    BrowserCredFinding,
    Confidence,
    DumpCredFinding,
    FileCredFinding,
    FindingType,
    KerberosTicketFinding,
    MemoryCredFinding,
    ScanResult,
    SystemCredFinding,
)
from .scanner import scan

__all__ = [
    "scan",
    "ScanOptions",
    "ScanResult",
    "Confidence",
    "FindingType",
    "FileCredFinding",
    "MemoryCredFinding",
    "BrowserCredFinding",
    "SystemCredFinding",
    "KerberosTicketFinding",
    "DumpCredFinding",
]
