# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (c) 2026 CommonHuman-Lab
"""Compiled regex patterns for extracting credentials from text."""

from __future__ import annotations

import re
from typing import List, NamedTuple


class CredPattern(NamedTuple):
    name: str
    pattern: re.Pattern[str]
    cred_type: str      # "password", "token", "api_key", "private_key", "connection_string"
    confidence: str     # "high", "medium", "low"


def _c(name: str, regex: str, cred_type: str, confidence: str) -> CredPattern:
    return CredPattern(name, re.compile(regex, re.IGNORECASE | re.MULTILINE), cred_type, confidence)


# ---------------------------------------------------------------------------
# Private keys (PEM / PPK headers)
# ---------------------------------------------------------------------------

PRIVATE_KEY_PATTERNS: List[CredPattern] = [
    _c("pem_rsa_key",      r"-----BEGIN RSA PRIVATE KEY-----",     "private_key", "high"),
    _c("pem_ec_key",       r"-----BEGIN EC PRIVATE KEY-----",      "private_key", "high"),
    _c("pem_private_key",  r"-----BEGIN PRIVATE KEY-----",         "private_key", "high"),
    _c("pem_openssh_key",  r"-----BEGIN OPENSSH PRIVATE KEY-----", "private_key", "high"),
    _c("pem_dsa_key",      r"-----BEGIN DSA PRIVATE KEY-----",     "private_key", "high"),
    _c("putty_ppk",        r"PuTTY-User-Key-File-\d",              "private_key", "high"),
]

# ---------------------------------------------------------------------------
# Cloud provider tokens / keys
# ---------------------------------------------------------------------------

CLOUD_PATTERNS: List[CredPattern] = [
    # AWS
    _c("aws_access_key",   r"(?:AKIA|ASIA|AROA|AIDA|ANPA)[A-Z0-9]{16}", "api_key", "high"),
    _c("aws_secret_key",   r"""(?:aws_secret|secret_access_key|aws_secret_access_key)\s*[=:]\s*["']?([A-Za-z0-9/+=]{40})""", "token", "high"),
    # GCP
    _c("gcp_service_account", r'"type"\s*:\s*"service_account"',  "token", "high"),
    _c("gcp_api_key",      r"AIza[0-9A-Za-z\-_]{35}",             "api_key", "high"),
    # Azure
    _c("azure_client_secret", r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}", "token", "low"),
    _c("azure_storage_key",   r"AccountKey=([A-Za-z0-9+/]{86}==)", "token", "high"),
    # GitHub
    _c("github_token",     r"gh[pousr]_[A-Za-z0-9]{36}",          "token", "high"),
    _c("github_fine_grained", r"github_pat_[A-Za-z0-9_]{82}",     "token", "high"),
    # GitLab
    _c("gitlab_token",     r"glpat-[A-Za-z0-9\-_]{20}",           "token", "high"),
    # Slack
    _c("slack_token",      r"xox[baprs]-[A-Za-z0-9\-]+",          "token", "high"),
    # Stripe
    _c("stripe_key",       r"(?:sk|pk)_(?:live|test)_[A-Za-z0-9]{24,}","api_key", "high"),
    # Twilio — word-boundary guard prevents matching hex substrings in cert hashes / binary templates
    _c("twilio_sid",       r"(?<![a-fA-F0-9])AC[a-f0-9]{32}(?![a-fA-F0-9])", "api_key", "medium"),
    # SendGrid
    _c("sendgrid_key",     r"SG\.[A-Za-z0-9\-_]{22}\.[A-Za-z0-9\-_]{43}", "api_key", "high"),
    # NPM
    _c("npm_token",        r"npm_[A-Za-z0-9]{36}",                 "token", "high"),
    # Anthropic
    _c("anthropic_key",    r"sk-ant-[A-Za-z0-9\-_]{90,}",         "api_key", "high"),
    # OpenAI
    _c("openai_key",       r"sk-[A-Za-z0-9]{48}",                 "api_key", "high"),
]

# ---------------------------------------------------------------------------
# Generic credential patterns in config / env files
# ---------------------------------------------------------------------------

GENERIC_PATTERNS: List[CredPattern] = [
    # (?!/\w) excludes values that start with a path separator (e.g. PWD=/home/user)
    _c("env_password",
       r"""(?:password|passwd|pwd|pass|secret)\s*[=:]\s*["']?(?!/\w)([^\s"'\n]{4,})""",
       "password", "medium"),
    _c("env_api_key",
       r"""(?:api[_\-]?key|apikey|auth[_\-]?key)\s*[=:]\s*["']?([A-Za-z0-9\-_/.+=]{8,})""",
       "api_key", "medium"),
    _c("env_token",
       r"""(?:token|access[_\-]?token|auth[_\-]?token|bearer)\s*[=:]\s*["']?([A-Za-z0-9\-_/.+=]{8,})""",
       "token", "medium"),
    _c("env_secret",
       r"""(?:secret[_\-]?key|secret|private[_\-]?key)\s*[=:]\s*["']?([A-Za-z0-9\-_/.+=]{8,})""",
       "token", "medium"),
    _c("basic_auth_url",
       r"https?://[^:@\s]+:[^@\s]+@",
       "password", "high"),
    # (?!/\w) same path-value guard as env_password
    _c("connection_string_pw",
       r"""(?:password|pwd)=(?!/\w)([^;'">\s]{4,})""",
       "password", "high"),
    # Docker config.json — "auth": "<base64(user:pass)>"
    _c("docker_auth",
       r'"auth"\s*:\s*"([A-Za-z0-9+/]{20,}={0,2})"',
       "password", "high"),
    # .pgpass — hostname:port:database:username:password (5th colon-separated field)
    _c("pgpass_password",
       r"(?m)^[^#\n][^:\n]*:\d+:[^:\n]*:[^:\n]+:([^\n]{4,})",
       "password", "high"),
    # .netrc — "machine host login user password VALUE" (space-separated)
    _c("netrc_password",
       r"(?m)password\s+(\S{4,})",
       "password", "high"),
]

# ---------------------------------------------------------------------------
# JWT tokens
# ---------------------------------------------------------------------------

JWT_PATTERNS: List[CredPattern] = [
    _c("jwt_token",
       r"eyJ[A-Za-z0-9\-_=]+\.eyJ[A-Za-z0-9\-_=]+\.[A-Za-z0-9\-_.+/=]*",
       "token", "high"),
]

# ---------------------------------------------------------------------------
# Database connection strings
# ---------------------------------------------------------------------------

DATABASE_PATTERNS: List[CredPattern] = [
    _c("postgres_dsn",
       r"postgres(?:ql)?://[^:]+:[^@\s]+@[^\s]+",
       "connection_string", "high"),
    _c("mysql_dsn",
       r"mysql(?:\+[a-z]+)?://[^:]+:[^@\s]+@[^\s]+",
       "connection_string", "high"),
    _c("mongodb_dsn",
       r"mongodb(?:\+srv)?://[^:]+:[^@\s]+@[^\s]+",
       "connection_string", "high"),
    _c("redis_auth_dsn",
       r"redis://:?[^@\s]+@[^\s]+",
       "connection_string", "medium"),
    _c("mssql_dsn",
       r"(?:mssql|sqlserver)://[^:]+:[^@\s]+@[^\s]+",
       "connection_string", "high"),
]

# ---------------------------------------------------------------------------
# Aggregated
# ---------------------------------------------------------------------------

ALL_PATTERNS: List[CredPattern] = (
    PRIVATE_KEY_PATTERNS
    + CLOUD_PATTERNS
    + GENERIC_PATTERNS
    + JWT_PATTERNS
    + DATABASE_PATTERNS
)

HIGH_CONFIDENCE: List[CredPattern] = [p for p in ALL_PATTERNS if p.confidence == "high"]
