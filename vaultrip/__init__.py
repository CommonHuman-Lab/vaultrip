# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (c) 2026 CommonHuman-Lab
"""
VaultRip — post-exploitation credential harvesting and extraction engine.

Quick start:

    from vaultrip import scan, ScanOptions

    result = scan("~", options=ScanOptions(memory=False, browser=False))
    for f in result.files:
        print(f.service, f.credential_type, f.path)
"""

from .engine._scanner.options import ScanOptions
from .engine.reporter import (
    BrowserCredFinding,
    Confidence,
    DCSyncFinding,
    DumpCredFinding,
    FileCredFinding,
    FindingType,
    ForgedTicketFinding,
    KerberosTicketFinding,
    MemoryCredFinding,
    PTHFinding,
    ScanResult,
    SystemCredFinding,
)
from .engine.scanner import scan

__version__ = "0.1.1"

BANNER = r"""
 _    __            ____  ____  _
| |  / /___ ___  __/ / /_/ __ \(_)___
| | / / __ `/ / / / / __/ /_/ / / __ \
| |/ / /_/ / /_/ / / /_/ _, _/ / /_/ /
|___/\__,_/\__,_/_/\__/_/ |_/_/ .___/
                              /_/
"""

__all__ = [
    "__version__",
    "BANNER",
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
    "DCSyncFinding",
    "PTHFinding",
    "ForgedTicketFinding",
]
