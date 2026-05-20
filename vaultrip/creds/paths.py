# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (c) 2026 CommonHuman-Lab
"""Known credential file and directory paths catalogued by service."""

from __future__ import annotations

from typing import Dict, List, NamedTuple


class CredPath(NamedTuple):
    pattern: str    # glob-style path relative to home dir or absolute
    service: str    # service name for reporting
    cred_type: str  # "private_key", "token", "password", "config", "database"
    absolute: bool = False  # True if pattern is absolute (not relative to ~)


# ---------------------------------------------------------------------------
# SSH
# ---------------------------------------------------------------------------

SSH_PATHS: List[CredPath] = [
    CredPath(".ssh/id_rsa",         "ssh", "private_key"),
    CredPath(".ssh/id_ecdsa",       "ssh", "private_key"),
    CredPath(".ssh/id_ed25519",     "ssh", "private_key"),
    CredPath(".ssh/id_dsa",         "ssh", "private_key"),
    CredPath(".ssh/id_ecdsa_sk",    "ssh", "private_key"),
    CredPath(".ssh/id_ed25519_sk",  "ssh", "private_key"),
    CredPath(".ssh/config",         "ssh", "config"),
    CredPath(".ssh/authorized_keys","ssh", "config"),
    CredPath(".ssh/known_hosts",    "ssh", "config"),
]

# ---------------------------------------------------------------------------
# Cloud providers
# ---------------------------------------------------------------------------

AWS_PATHS: List[CredPath] = [
    CredPath(".aws/credentials",                        "aws", "token"),
    CredPath(".aws/config",                             "aws", "config"),
    CredPath(".aws/cli/cache",                          "aws", "token"),
    CredPath(".config/aws/credentials",                 "aws", "token"),
]

GCP_PATHS: List[CredPath] = [
    CredPath(".config/gcloud/credentials.db",           "gcp", "token"),
    CredPath(".config/gcloud/application_default_credentials.json", "gcp", "token"),
    CredPath(".config/gcloud/legacy_credentials",       "gcp", "token"),
]

AZURE_PATHS: List[CredPath] = [
    CredPath(".azure/accessTokens.json",                "azure", "token"),
    CredPath(".azure/azureProfile.json",                "azure", "config"),
    CredPath(".config/azure-cli/accessTokens.json",     "azure", "token"),
]

# ---------------------------------------------------------------------------
# Kubernetes / Docker
# ---------------------------------------------------------------------------

K8S_PATHS: List[CredPath] = [
    CredPath(".kube/config",                            "kubernetes", "config"),
    CredPath(".kube/cache",                             "kubernetes", "token"),
]

DOCKER_PATHS: List[CredPath] = [
    CredPath(".docker/config.json",                     "docker", "token"),
    CredPath(".docker/daemon.json",                     "docker", "config"),
]

# ---------------------------------------------------------------------------
# Git
# ---------------------------------------------------------------------------

GIT_PATHS: List[CredPath] = [
    CredPath(".gitconfig",                              "git", "config"),
    CredPath(".git-credentials",                        "git", "password"),
    CredPath(".config/git/credentials",                 "git", "password"),
    CredPath(".netrc",                                  "git", "password"),
]

# ---------------------------------------------------------------------------
# Shell history
# ---------------------------------------------------------------------------

SHELL_HISTORY_PATHS: List[CredPath] = [
    CredPath(".bash_history",    "shell", "history"),
    CredPath(".zsh_history",     "shell", "history"),
    CredPath(".zshrc",           "shell", "config"),
    CredPath(".bashrc",          "shell", "config"),
    CredPath(".bash_profile",    "shell", "config"),
    CredPath(".profile",         "shell", "config"),
    CredPath(".config/fish/history", "shell", "history"),
]

# ---------------------------------------------------------------------------
# Password managers
# ---------------------------------------------------------------------------

PASSWORD_MANAGER_PATHS: List[CredPath] = [
    CredPath(".local/share/keyrings",              "gnome-keyring", "database"),
    CredPath(".password-store",                    "pass", "password"),
    CredPath("snap/keepassxc/current/.config/keepassxc", "keepassxc", "database"),
    CredPath(".var/app/org.keepassxc.KeePassXC/config/keepassxc", "keepassxc", "database"),
]

# ---------------------------------------------------------------------------
# Browser profile locations
# ---------------------------------------------------------------------------

BROWSER_PATHS: List[CredPath] = [
    # Chrome / Chromium
    CredPath(".config/google-chrome/Default/Login Data",       "chrome", "database"),
    CredPath(".config/google-chrome/Default/Cookies",          "chrome", "database"),
    CredPath(".config/chromium/Default/Login Data",            "chromium", "database"),
    CredPath(".config/microsoft-edge/Default/Login Data",      "edge", "database"),
    CredPath(".config/BraveSoftware/Brave-Browser/Default/Login Data", "brave", "database"),
    # Firefox
    CredPath(".mozilla/firefox",                               "firefox", "database"),
    CredPath("snap/firefox/common/.mozilla/firefox",           "firefox", "database"),
]

# ---------------------------------------------------------------------------
# Database / service credentials
# ---------------------------------------------------------------------------

DATABASE_PATHS: List[CredPath] = [
    CredPath(".pgpass",                          "postgresql", "password"),
    CredPath(".my.cnf",                          "mysql", "password"),
    CredPath(".mycli.cfg",                       "mysql", "password"),
    CredPath(".config/dbcli/mycli",              "mysql", "config"),
    CredPath(".config/dbcli/pgcli",              "postgresql", "config"),
    CredPath(".redis_cli_history",               "redis", "history"),
    CredPath(".influxdbv2/credentials",          "influxdb", "token"),
]

# ---------------------------------------------------------------------------
# Terraform / Ansible / Vault
# ---------------------------------------------------------------------------

INFRA_PATHS: List[CredPath] = [
    CredPath(".terraform.d/credentials.tfrc.json", "terraform", "token"),
    CredPath(".vault-token",                        "vault", "token"),
    CredPath(".ansible/vault-pass",                 "ansible", "password"),
]

# ---------------------------------------------------------------------------
# Absolute system paths (not relative to home)
# ---------------------------------------------------------------------------

SYSTEM_PATHS: List[CredPath] = [
    CredPath("/etc/shadow",         "linux", "password", absolute=True),
    CredPath("/etc/passwd",         "linux", "config",   absolute=True),
    CredPath("/etc/krb5.keytab",    "kerberos", "keytab", absolute=True),
    CredPath("/etc/krb5.conf",      "kerberos", "config",  absolute=True),
    CredPath("/var/lib/sss/db",     "sssd",     "database", absolute=True),
    CredPath("/etc/ssh/ssh_host_rsa_key",     "ssh", "private_key", absolute=True),
    CredPath("/etc/ssh/ssh_host_ecdsa_key",   "ssh", "private_key", absolute=True),
    CredPath("/etc/ssh/ssh_host_ed25519_key", "ssh", "private_key", absolute=True),
]

# ---------------------------------------------------------------------------
# Aggregated index
# ---------------------------------------------------------------------------

ALL_HOME_PATHS: List[CredPath] = (
    SSH_PATHS
    + AWS_PATHS
    + GCP_PATHS
    + AZURE_PATHS
    + K8S_PATHS
    + DOCKER_PATHS
    + GIT_PATHS
    + SHELL_HISTORY_PATHS
    + PASSWORD_MANAGER_PATHS
    + BROWSER_PATHS
    + DATABASE_PATHS
    + INFRA_PATHS
)

ALL_SYSTEM_PATHS: List[CredPath] = SYSTEM_PATHS

BY_SERVICE: Dict[str, List[CredPath]] = {}
for _p in ALL_HOME_PATHS + ALL_SYSTEM_PATHS:
    BY_SERVICE.setdefault(_p.service, []).append(_p)

# Glob patterns that warrant content-scanning even if not in the above list
INTERESTING_EXTENSIONS = frozenset({
    ".env", ".pem", ".key", ".p12", ".pfx", ".ovpn", ".ppk",
    ".json", ".yaml", ".yml", ".toml", ".ini", ".conf", ".cfg",
})

INTERESTING_FILENAMES = frozenset({
    ".env", ".env.local", ".env.production", ".env.staging",
    "id_rsa", "id_ecdsa", "id_ed25519", "id_dsa",
    "credentials", "secrets", "secret.yaml", "secret.yml",
    "terraform.tfvars", "terraform.tfvars.json",
    "secrets.json", "service-account.json", "serviceaccount.json",
    ".netrc", ".pgpass", ".my.cnf",
})
