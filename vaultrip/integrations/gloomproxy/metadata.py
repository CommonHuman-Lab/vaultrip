# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (c) 2026 CommonHuman-Lab
from gloomproxy_sdk import PluginCapabilities

CAPABILITIES: PluginCapabilities = {
    "name": "vaultrip",
    "modes": ["post-exploitation"],
    "protocols": ["filesystem", "ssh"],
    "auth_required": False,
    "distributed_safe": False,  # assumes local or SSH-accessible filesystem
    "vuln_types": [
        "credential_exposure",
        "file_credential",
        "browser_credential",
        "system_credential",
        "kerberos_ticket",
    ],
    "proxy_aware": False,
    "min_timeout": 60,
}
