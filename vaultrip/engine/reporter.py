# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (c) 2026 CommonHuman-Lab
"""VaultRip — engine/reporter.py — scan result dataclasses and serialisation."""

from __future__ import annotations

import dataclasses
from dataclasses import dataclass, field
from enum import Enum
from typing import Any

from commonhuman_cli.reporter import ScanResultBase

# ---------------------------------------------------------------------------
# Enums
# ---------------------------------------------------------------------------

class Confidence(str, Enum):
    HIGH   = "high"
    MEDIUM = "medium"
    LOW    = "low"


class FindingType(str, Enum):
    FILE_CRED       = "file_credential"
    MEMORY_CRED     = "memory_credential"
    BROWSER_CRED    = "browser_credential"
    SYSTEM_CRED     = "system_credential"
    KERBEROS_TICKET = "kerberos_ticket"
    DUMP_CRED       = "dump_credential"
    DCSYNC_CRED     = "dcsync_credential"
    PTH_RESULT      = "pth_result"
    FORGED_TICKET   = "forged_ticket"


# ---------------------------------------------------------------------------
# Finding dataclasses
# ---------------------------------------------------------------------------

@dataclass
class FileCredFinding:
    """Credential material found in a file on the filesystem."""
    path:            str
    service:         str            # "ssh", "aws", "docker", "git", etc.
    credential_type: str            # "private_key", "access_token", "password", "config"
    confidence:      Confidence
    value:           str | None = None    # extracted value; None if binary/unparsed


@dataclass
class MemoryCredFinding:
    """Credential pattern matched in a process's memory region."""
    pid:             int
    process_name:    str
    credential_type: str
    value:           str
    offset:          int
    confidence:      Confidence = Confidence.MEDIUM


@dataclass
class BrowserCredFinding:
    """Saved login recovered from a browser credential store."""
    browser:  str                   # "chrome", "firefox", "edge", "brave"
    url:      str
    username: str
    password: str | None = None  # None if decryption key not found on this host


@dataclass
class SystemCredFinding:
    """Credential recovered from a system keyring or credential manager."""
    store:    str                   # "gnome-keyring", "kwallet", "git", "docker"
    label:    str
    username: str | None = None
    secret:   str | None = None


@dataclass
class KerberosTicketFinding:
    """Kerberos ticket (TGT or service ticket) extracted from a ccache or keytab."""
    source_path:   str
    source_type:   str              # "ccache", "keytab"
    principal:     str
    service:       str
    expires:       str
    ticket_bytes:  bytes = field(default_factory=bytes, repr=False)


@dataclass
class DumpCredFinding:
    """Credential extracted from an offline dump file (LSASS, SAM, NTDS)."""
    dump_path:  str
    dump_type:  str                 # "lsass", "sam", "ntds"
    username:   str
    domain:     str | None       = None
    nt_hash:    str | None       = None
    lm_hash:    str | None       = None
    plaintext:  str | None       = None


@dataclass
class DCSyncFinding:
    """Credential replicated from Active Directory via DCSync (DRSUAPI)."""
    dc_host:   str
    domain:    str
    username:  str
    nt_hash:   str | None = None
    lm_hash:   str | None = None
    plaintext: str | None = None


@dataclass
class PTHFinding:
    """Result of a Pass-the-Hash command execution."""
    target:    str
    username:  str
    nt_hash:   str
    command:   str
    stdout:    str
    exit_code: int
    success:   bool


@dataclass
class ForgedTicketFinding:
    """Kerberos ticket forged locally via impacket ticketer."""
    ticket_type: str            # "golden" | "silver"
    domain:      str
    username:    str
    ticket_path: str            # path to written .ccache file
    injected:    bool           # True if KRB5CCNAME env var was updated
    spn:         str | None = None   # service principal (silver tickets only)


# ---------------------------------------------------------------------------
# Finding type → list attribute mapping (for serialisation)
# ---------------------------------------------------------------------------

_FINDING_LISTS: list[tuple[str, FindingType]] = [
    ("files",          FindingType.FILE_CRED),
    ("memory",         FindingType.MEMORY_CRED),
    ("browser",        FindingType.BROWSER_CRED),
    ("system",         FindingType.SYSTEM_CRED),
    ("kerberos",       FindingType.KERBEROS_TICKET),
    ("dumps",          FindingType.DUMP_CRED),
    ("dcsync",         FindingType.DCSYNC_CRED),
    ("pth_results",    FindingType.PTH_RESULT),
    ("forged_tickets", FindingType.FORGED_TICKET),
]


# ---------------------------------------------------------------------------
# Top-level ScanResult
# ---------------------------------------------------------------------------

@dataclass
class ScanResult(ScanResultBase):
    """Aggregated result for a VaultRip run."""

    files:          list[FileCredFinding]       = field(default_factory=list)
    memory:         list[MemoryCredFinding]     = field(default_factory=list)
    browser:        list[BrowserCredFinding]    = field(default_factory=list)
    system:         list[SystemCredFinding]     = field(default_factory=list)
    kerberos:       list[KerberosTicketFinding] = field(default_factory=list)
    dumps:          list[DumpCredFinding]       = field(default_factory=list)
    dcsync:         list[DCSyncFinding]         = field(default_factory=list)
    pth_results:    list[PTHFinding]            = field(default_factory=list)
    forged_tickets: list[ForgedTicketFinding]   = field(default_factory=list)

    # --- Append helpers -------------------------------------------------------

    def append_file(self, f: FileCredFinding)           -> None: self._append("files",          f)
    def append_memory(self, f: MemoryCredFinding)       -> None: self._append("memory",         f)
    def append_browser(self, f: BrowserCredFinding)     -> None: self._append("browser",        f)
    def append_system(self, f: SystemCredFinding)       -> None: self._append("system",         f)
    def append_kerberos(self, f: KerberosTicketFinding) -> None: self._append("kerberos",       f)
    def append_dump(self, f: DumpCredFinding)           -> None: self._append("dumps",          f)
    def append_dcsync(self, f: DCSyncFinding)           -> None: self._append("dcsync",         f)
    def append_pth(self, f: PTHFinding)                 -> None: self._append("pth_results",    f)
    def append_forged(self, f: ForgedTicketFinding)     -> None: self._append("forged_tickets", f)

    # --- Computed properties --------------------------------------------------

    @property
    def total_findings(self) -> int:
        return sum(len(getattr(self, attr)) for attr, _ in _FINDING_LISTS)

    def to_dict(self) -> dict[str, Any]:
        findings: list[dict[str, Any]] = []
        for attr, ftype in _FINDING_LISTS:
            for item in getattr(self, attr):
                d = dataclasses.asdict(item)
                # ticket_bytes not JSON-serialisable — convert to hex string
                if "ticket_bytes" in d and isinstance(d["ticket_bytes"], bytes):
                    d["ticket_bytes"] = d["ticket_bytes"].hex()
                d["type"] = ftype.value
                findings.append(d)

        result = self._base_dict()
        result["total_findings"] = self.total_findings
        result["findings"] = findings
        return result
