# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (c) 2026 CommonHuman-Lab
"""
Kerberos ticket extraction from ccache files and keytab files.

Parses the ccache binary format (RFC 4120) and keytab format without
external dependencies. Reports ticket metadata and raw bytes for export.
"""

from __future__ import annotations

import glob
import logging
import os
import struct
from datetime import datetime, timezone

from ...creds.signatures import identify_dump

from ..reporter import KerberosTicketFinding, ScanResult
from .passive import PassiveInfo

log = logging.getLogger("vaultrip.kerberos")

# Standard ccache locations
_CCACHE_PATTERNS = [
    "/tmp/krb5cc_*",
    "/tmp/krb5cc.*",
    "/run/user/*/krb5cc",
    "/var/lib/sss/db/ccache_*",
]

# Keytab locations
_KEYTAB_PATHS = [
    "/etc/krb5.keytab",
    "/etc/krb5/krb5.keytab",
    "/usr/local/etc/krb5.keytab",
]


def parse_ccache(result: ScanResult, path: str) -> None:
    """Public entry point — parse a single ccache file and append findings."""
    _parse_ccache(result, path)


def run(result: ScanResult, passive: PassiveInfo) -> None:
    """Extract Kerberos tickets from ccache files and keytabs."""
    ccache_paths = _find_ccache_files(passive)
    for ccache_path in ccache_paths:
        _parse_ccache(result, ccache_path)

    for keytab_path in _KEYTAB_PATHS:
        if os.path.isfile(keytab_path):
            _parse_keytab(result, keytab_path)

    # User-specific keytabs
    for home in passive.home_dirs:
        user_keytab = os.path.join(home, ".keytab")
        if os.path.isfile(user_keytab):
            _parse_keytab(result, user_keytab)
        for kt in glob.glob(os.path.join(home, "*.keytab")):
            _parse_keytab(result, kt)


# ---------------------------------------------------------------------------
# ccache discovery
# ---------------------------------------------------------------------------

def _find_ccache_files(passive: PassiveInfo) -> list[str]:
    paths = []

    # KRB5CCNAME env var takes priority
    ccname = passive.krb5ccname
    if ccname:
        if ccname.startswith("FILE:"):
            ccname = ccname[5:]
        if os.path.isfile(ccname):
            paths.append(ccname)

    # Standard glob patterns
    for pattern in _CCACHE_PATTERNS:
        for match in glob.glob(pattern):
            if os.path.isfile(match) and match not in paths:
                paths.append(match)

    # User-specific: /tmp/krb5cc_<uid>
    uid = os.getuid()
    uid_path = f"/tmp/krb5cc_{uid}"
    if os.path.isfile(uid_path) and uid_path not in paths:
        paths.append(uid_path)

    return paths


# ---------------------------------------------------------------------------
# ccache parser (minimal — enough to extract principal and expiry)
# ---------------------------------------------------------------------------

def _parse_ccache(result: ScanResult, path: str) -> None:
    try:
        with open(path, "rb") as fh:
            data = fh.read()
    except OSError as exc:
        log.debug("kerberos: cannot read ccache %s: %s", path, exc)
        return

    sig = identify_dump(data)
    if sig is None or sig.dump_type != "ccache":
        log.debug("kerberos: %s does not appear to be a ccache file", path)
        return

    tickets = _extract_ccache_tickets(data)
    for principal, service, expires_ts, raw in tickets:
        expires_str = _ts_to_iso(expires_ts)
        result.append_kerberos(KerberosTicketFinding(
            source_path=path,
            source_type="ccache",
            principal=principal,
            service=service,
            expires=expires_str,
            ticket_bytes=raw,
        ))
        log.info("kerberos: ccache ticket %s → %s (expires %s)", principal, service, expires_str)


def _extract_ccache_tickets(
    data: bytes,
) -> list[tuple[str, str, int, bytes]]:
    """Parse ccache v4 format and return (client, service, end_time, raw) tuples."""
    results = []
    if len(data) < 4:
        return results

    version = struct.unpack(">H", data[:2])[0]
    if version not in (0x0504, 0x0503):
        return results

    # Skip header tags (v4)
    offset = 4
    if version == 0x0504:
        tag_len = struct.unpack(">H", data[2:4])[0]
        offset = 4 + tag_len

    # Primary principal
    client, offset = _read_principal(data, offset)

    # Credentials
    while offset < len(data) - 4:
        try:
            cred, new_offset = _read_credential(data, offset)
            if cred:
                results.append(cred)
            offset = new_offset
        except (struct.error, IndexError):
            break

    return results


def _read_principal(data: bytes, offset: int) -> tuple[str, int]:
    if offset + 8 > len(data):
        return "", offset
    name_type, = struct.unpack(">I", data[offset:offset + 4])
    num_components, = struct.unpack(">I", data[offset + 4:offset + 8])
    offset += 8
    realm, offset = _read_counted_string(data, offset)
    components = []
    for _ in range(num_components):
        comp, offset = _read_counted_string(data, offset)
        components.append(comp)
    principal = "/".join(components) + ("@" + realm if realm else "")
    return principal, offset


def _read_credential(
    data: bytes, offset: int
) -> tuple[tuple[str, str, int, bytes] | None, int]:
    client, offset = _read_principal(data, offset)
    service, offset = _read_principal(data, offset)
    # keyblock (etype + key data)
    if offset + 4 > len(data):
        return None, len(data)
    offset += 2  # etype
    key_len, = struct.unpack(">H", data[offset:offset + 2])
    offset += 2 + key_len
    # times: authtime, starttime, endtime, renewtime (each 4 bytes)
    if offset + 16 > len(data):
        return None, len(data)
    _auth, _start, end_time, _renew = struct.unpack(">IIII", data[offset:offset + 16])
    offset += 16
    # is_skey + ticket_flags
    offset += 5
    # addresses
    offset = _skip_addresses(data, offset)
    # authdata
    offset = _skip_authdata(data, offset)
    # ticket
    ticket_raw, offset = _read_counted_bytes(data, offset)
    # second_ticket
    _, offset = _read_counted_bytes(data, offset)
    return (client, service, end_time, ticket_raw), offset


def _read_counted_string(data: bytes, offset: int) -> tuple[str, int]:
    if offset + 4 > len(data):
        return "", offset
    length, = struct.unpack(">I", data[offset:offset + 4])
    offset += 4
    text = data[offset:offset + length].decode("utf-8", errors="replace")
    return text, offset + length


def _read_counted_bytes(data: bytes, offset: int) -> tuple[bytes, int]:
    if offset + 4 > len(data):
        return b"", offset
    length, = struct.unpack(">I", data[offset:offset + 4])
    offset += 4
    return data[offset:offset + length], offset + length


def _skip_addresses(data: bytes, offset: int) -> int:
    if offset + 4 > len(data):
        return offset
    count, = struct.unpack(">I", data[offset:offset + 4])
    offset += 4
    for _ in range(count):
        if offset + 6 > len(data):
            return offset
        offset += 2  # addr_type
        addr_len, = struct.unpack(">I", data[offset:offset + 4])
        offset += 4 + addr_len
    return offset


def _skip_authdata(data: bytes, offset: int) -> int:
    if offset + 4 > len(data):
        return offset
    count, = struct.unpack(">I", data[offset:offset + 4])
    offset += 4
    for _ in range(count):
        if offset + 6 > len(data):
            return offset
        offset += 2  # ad_type
        data_len, = struct.unpack(">I", data[offset:offset + 4])
        offset += 4 + data_len
    return offset


# ---------------------------------------------------------------------------
# Keytab parser (minimal)
# ---------------------------------------------------------------------------

def _parse_keytab(result: ScanResult, path: str) -> None:
    try:
        with open(path, "rb") as fh:
            data = fh.read()
    except OSError as exc:
        log.debug("kerberos: cannot read keytab %s: %s", path, exc)
        return

    sig = identify_dump(data)
    if sig is None or sig.dump_type != "keytab":
        log.debug("kerberos: %s does not appear to be a keytab", path)
        return

    entries = _extract_keytab_entries(data)
    for principal, timestamp in entries:
        result.append_kerberos(KerberosTicketFinding(
            source_path=path,
            source_type="keytab",
            principal=principal,
            service="keytab",
            expires="never",
            ticket_bytes=data,
        ))
        log.info("kerberos: keytab entry for %s (ts=%d)", principal, timestamp)


def _extract_keytab_entries(data: bytes) -> list[tuple[str, int]]:
    """Parse MIT keytab format (version 2) and return (principal, timestamp) pairs."""
    results = []
    if len(data) < 2:
        return results
    version = struct.unpack(">H", data[:2])[0]
    if version not in (0x0502, 0x0501):
        return results

    offset = 2
    while offset + 4 < len(data):
        entry_len = struct.unpack(">i", data[offset:offset + 4])[0]
        offset += 4
        if entry_len <= 0 or offset + entry_len > len(data):
            break
        entry_data = data[offset:offset + entry_len]
        offset += entry_len

        try:
            principal, ts = _parse_keytab_entry(entry_data)
            results.append((principal, ts))
        except (struct.error, IndexError):
            continue

    return results


def _parse_keytab_entry(entry: bytes) -> tuple[str, int]:
    pos = 0
    num_components, = struct.unpack(">H", entry[pos:pos + 2])
    pos += 2
    realm_len, = struct.unpack(">H", entry[pos:pos + 2])
    pos += 2
    realm = entry[pos:pos + realm_len].decode("utf-8", errors="replace")
    pos += realm_len

    components = []
    for _ in range(num_components):
        comp_len, = struct.unpack(">H", entry[pos:pos + 2])
        pos += 2
        components.append(entry[pos:pos + comp_len].decode("utf-8", errors="replace"))
        pos += comp_len

    pos += 1  # name_type byte
    timestamp, = struct.unpack(">I", entry[pos:pos + 4])
    principal = "/".join(components) + "@" + realm
    return principal, timestamp


def _ts_to_iso(timestamp: int) -> str:
    if timestamp == 0:
        return "never"
    try:
        return datetime.fromtimestamp(timestamp, tz=timezone.utc).isoformat()
    except (OSError, OverflowError, ValueError):
        return str(timestamp)
