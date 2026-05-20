# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (c) 2026 CommonHuman-Lab
"""VaultRip credential data — paths, patterns, dump signatures, and hash detection."""

from .hashes import HashType, HASH_TYPES, identify_hash, is_hash, likely_ntlm
from .paths import (
    CredPath,
    ALL_HOME_PATHS,
    ALL_SYSTEM_PATHS,
    BY_SERVICE,
    INTERESTING_EXTENSIONS,
    INTERESTING_FILENAMES,
)
from .patterns import CredPattern, ALL_PATTERNS, HIGH_CONFIDENCE
from .signatures import DumpSignature, DUMP_SIGNATURES, identify_dump, is_dump_file

__all__ = [
    # hashes
    "HashType",
    "HASH_TYPES",
    "identify_hash",
    "is_hash",
    "likely_ntlm",
    # paths
    "CredPath",
    "ALL_HOME_PATHS",
    "ALL_SYSTEM_PATHS",
    "BY_SERVICE",
    "INTERESTING_EXTENSIONS",
    "INTERESTING_FILENAMES",
    # patterns
    "CredPattern",
    "ALL_PATTERNS",
    "HIGH_CONFIDENCE",
    # signatures
    "DumpSignature",
    "DUMP_SIGNATURES",
    "identify_dump",
    "is_dump_file",
]
