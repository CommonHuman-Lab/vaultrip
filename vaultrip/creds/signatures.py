# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (c) 2026 CommonHuman-Lab
"""Binary magic-byte signatures for credential dump file formats."""

from __future__ import annotations

from typing import List, NamedTuple, Optional


class DumpSignature(NamedTuple):
    name: str           # human-readable format name
    magic: bytes        # leading bytes to match
    dump_type: str      # "lsass", "sam", "ntds", "ccache", "keytab", "ntds"
    description: str
    offset: int = 0     # byte offset where magic appears


DUMP_SIGNATURES: List[DumpSignature] = [
    # LSASS minidump (Windows MiniDump format)
    DumpSignature(
        name="LSASS Minidump",
        magic=b"MDMP",
        dump_type="lsass",
        description="Windows MiniDump — contains LSASS process memory with credential material",
    ),
    # Windows registry hive (SAM, SYSTEM, SECURITY, NTDS)
    DumpSignature(
        name="Windows Registry Hive",
        magic=b"regf",
        dump_type="sam",
        description="Windows registry hive file — SAM/SYSTEM/SECURITY hives contain NTLM hashes",
    ),
    # Kerberos ccache (credential cache)
    DumpSignature(
        name="Kerberos ccache v4",
        magic=b"\x05\x04",
        dump_type="ccache",
        description="Kerberos v4 credential cache — contains TGTs and service tickets",
    ),
    DumpSignature(
        name="Kerberos ccache v3",
        magic=b"\x05\x03",
        dump_type="ccache",
        description="Kerberos v3 credential cache",
    ),
    # Kerberos keytab
    DumpSignature(
        name="Kerberos keytab v2",
        magic=b"\x05\x02",
        dump_type="keytab",
        description="Kerberos keytab — contains long-term keys for principals",
    ),
    DumpSignature(
        name="Kerberos keytab v1",
        magic=b"\x05\x01",
        dump_type="keytab",
        description="Kerberos keytab v1",
    ),
    # NTDS.dit (Active Directory database — SQLite/ESE format)
    DumpSignature(
        name="NTDS.dit (ESE)",
        magic=b"\xef\xcd\xab\x89",
        dump_type="ntds",
        description="Extensible Storage Engine database — used by NTDS.dit",
        offset=4,
    ),
    # Firefox key database (NSS key4.db)
    DumpSignature(
        name="SQLite3 (Firefox key4.db / Chrome Login Data)",
        magic=b"SQLite format 3\x00",
        dump_type="browser",
        description="SQLite3 database — used by Firefox key4.db and Chrome Login Data",
    ),
    # PFX / PKCS#12 archive
    DumpSignature(
        name="PKCS#12 / PFX",
        magic=b"\x30\x82",
        dump_type="certificate",
        description="PKCS#12 certificate bundle — may contain private keys",
    ),
    # Java KeyStore
    DumpSignature(
        name="Java KeyStore (JKS)",
        magic=b"\xfe\xed\xfe\xed",
        dump_type="keystore",
        description="Java KeyStore — contains certificates and private keys",
    ),
]

_MAGIC_INDEX: dict[bytes, DumpSignature] = {s.magic: s for s in DUMP_SIGNATURES}


def identify_dump(data: bytes, max_bytes: int = 64) -> Optional[DumpSignature]:
    """Return the matching DumpSignature for the leading bytes of *data*, or None."""
    sample = data[:max_bytes]
    for sig in DUMP_SIGNATURES:
        start = sig.offset
        end = sig.offset + len(sig.magic)
        if len(sample) >= end and sample[start:end] == sig.magic:
            return sig
    return None


def is_dump_file(path: str) -> Optional[DumpSignature]:
    """Open *path* and return its DumpSignature if recognised, else None."""
    try:
        with open(path, "rb") as fh:
            return identify_dump(fh.read(64))
    except OSError:
        return None
