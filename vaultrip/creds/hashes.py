# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (c) 2026 CommonHuman-Lab
"""Hash type detection — identify hash formats by length and character set."""

from __future__ import annotations

import re
from typing import List, NamedTuple, Optional


class HashType(NamedTuple):
    name: str           # display name
    algorithm: str      # canonical algorithm ID
    pattern: re.Pattern[str]
    crackable: bool     # whether common crackers (hashcat/john) support it
    hashcat_mode: Optional[int] = None  # hashcat -m value


def _h(name: str, algo: str, regex: str, crackable: bool = True, mode: Optional[int] = None) -> HashType:
    return HashType(name, algo, re.compile(regex), crackable, mode)


HASH_TYPES: List[HashType] = [
    # Windows
    _h("NTLM",          "ntlm",     r"^[0-9a-fA-F]{32}$",                        mode=1000),
    _h("LM",            "lm",       r"^[0-9a-fA-F]{32}$",                        mode=3000),
    _h("NTLMv2",        "ntlmv2",   r"^[^:]+::[^:]+:[0-9a-fA-F]{16}:[0-9a-fA-F]{32}:[0-9a-fA-F]+$", mode=5600),
    _h("Net-NTLMv1",    "ntlmv1",   r"^[^:]+::[^:]+:[0-9a-fA-F]{48}:[0-9a-fA-F]{48}:[0-9a-fA-F]{16}$", mode=5500),
    # Unix crypt
    _h("bcrypt",        "bcrypt",   r"^\$2[aby]\$\d{2}\$[./A-Za-z0-9]{53}$",     mode=3200),
    _h("SHA-512 crypt", "sha512crypt", r"^\$6\$[./A-Za-z0-9]{8,16}\$[./A-Za-z0-9]{86}$", mode=1800),
    _h("SHA-256 crypt", "sha256crypt", r"^\$5\$[./A-Za-z0-9]{8,16}\$[./A-Za-z0-9]{43}$", mode=7400),
    _h("MD5 crypt",     "md5crypt",  r"^\$1\$[./A-Za-z0-9]{8}\$[./A-Za-z0-9]{22}$", mode=500),
    _h("Apache MD5",    "apr1",      r"^\$apr1\$[./A-Za-z0-9]{8}\$[./A-Za-z0-9]{22}$", mode=1600),
    # Raw hex digests (ordered longest first to avoid mismatching SHA1 as MD5)
    _h("SHA-512",       "sha512",   r"^[0-9a-fA-F]{128}$",                       mode=1700),
    _h("SHA-384",       "sha384",   r"^[0-9a-fA-F]{96}$",                        mode=10800),
    _h("SHA-256",       "sha256",   r"^[0-9a-fA-F]{64}$",                        mode=1400),
    _h("SHA-1",         "sha1",     r"^[0-9a-fA-F]{40}$",                        mode=100),
    _h("MD5",           "md5",      r"^[0-9a-fA-F]{32}$",                        mode=0),
    _h("MD4",           "md4",      r"^[0-9a-fA-F]{32}$",                        mode=900),
    # Salted / Django
    _h("Django SHA1",   "django_sha1",  r"^sha1\$[A-Za-z0-9]+\$[0-9a-fA-F]{40}$",     mode=124),
    _h("Django PBKDF2", "django_pbkdf2",r"^pbkdf2_sha256\$\d+\$[^$]+\$.+$",            crackable=False),
    # Argon2
    _h("Argon2",        "argon2",   r"^\$argon2(?:id|i|d)\$",                    mode=25700),
    # MySQL
    _h("MySQL 3.x",     "mysql3",   r"^[0-9a-fA-F]{16}$",                       mode=200),
    _h("MySQL 4.1+",    "mysql41",  r"^\*[0-9a-fA-F]{40}$",                     mode=300),
    # Kerberos
    _h("Kerberos AS-REP", "krb5asrep",
       r"^\$krb5asrep\$\d+\$[^:]+:[0-9a-fA-F]+\$[0-9a-fA-F]+$",               mode=18200),
    _h("Kerberos TGS (kerberoast)", "krb5tgs",
       r"^\$krb5tgs\$\d+\$\*[^*]+\*\$[0-9a-fA-F]+\$[0-9a-fA-F]+$",           mode=13100),
]

# NTLM and MD5 both match 32 hex chars — use a separate check for context
_NTLM_PATTERN = re.compile(r"^[0-9a-fA-F]{32}$")


def identify_hash(value: str) -> List[HashType]:
    """Return all HashType entries whose pattern matches *value*.

    Multiple results are possible (e.g. NTLM vs MD5 are the same format).
    Ordered by most specific first (longer patterns before shorter).
    """
    value = value.strip()
    return [ht for ht in HASH_TYPES if ht.pattern.match(value)]


def is_hash(value: str) -> bool:
    """Return True if *value* looks like any recognised hash format."""
    return bool(identify_hash(value))


def likely_ntlm(value: str) -> bool:
    """Heuristic: 32 hex chars from an NTLM auth context is likely NTLM."""
    return bool(_NTLM_PATTERN.match(value.strip()))
