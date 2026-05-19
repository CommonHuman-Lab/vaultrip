# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (c) 2026 CommonHuman-Lab
"""Scan configuration for VaultRip."""

from __future__ import annotations


class ScanOptions:
    """Configuration for a VaultRip scan run."""

    def __init__(
        self,
        # --- Scope ----------------------------------------------------------------
        target_user:  str | None  = None,    # restrict to a specific Unix user's home dir
        target_pid:   int | None  = None,    # restrict memory scan to a single PID
        dump_path:    str | None  = None,    # path to offline dump (LSASS/SAM/NTDS)
        # --- Module toggles -------------------------------------------------------
        local:        bool = True,              # filesystem sweep
        memory:       bool = True,              # /proc memory scan
        browser:      bool = True,              # browser credential stores
        system:       bool = True,              # system keyrings + git + Docker
        kerberos:     bool = True,              # ccache / keytab extraction
        dumps:        bool = True,              # offline dump parsing (if dump_path set)
        remote:       bool = False,             # SSH remote harvesting
        # --- Remote options -------------------------------------------------------
        ssh_host:     str | None  = None,
        ssh_user:     str | None  = None,
        ssh_key:      str | None  = None,    # path to SSH private key
        ssh_password: str | None  = None,
        ssh_port:     int            = 22,
        # --- Attack modules (explicit opt-in — active operations) -----------------
        dcsync:          bool = False,          # DCSync via DRSUAPI
        pth:             bool = False,          # Pass-the-Hash command execution
        ptt:             bool = False,          # Pass-the-Ticket ccache injection
        forge_golden:    bool = False,          # forge a Kerberos golden ticket
        forge_silver:    bool = False,          # forge a Kerberos silver ticket
        # --- Attack parameters ----------------------------------------------------
        dc_host:         str = "",              # DC IP/hostname (dcsync, forge)
        ad_domain:       str = "",              # Active Directory domain name
        domain_sid:      str = "",              # S-1-5-21-... (ticket forging)
        krbtgt_hash:     str = "",              # NT hash of krbtgt account (golden)
        attack_user:     str = "",              # username to impersonate
        attack_hash:     str = "",              # NT hash for PTH / silver ticket
        attack_cmd:      str = "whoami",        # command to run after PTH
        ptt_ticket:      str = "",              # path to .ccache or .kirbi to inject
        forge_silver_spn: str = "",             # SPN for silver ticket, e.g. cifs/host.domain
        # --- Output ---------------------------------------------------------------
        output:       str            = "",      # JSON output file path
        verbose:      bool           = False,
        timeout:      int            = 30,
    ) -> None:
        self.target_user  = target_user
        self.target_pid   = target_pid
        self.dump_path    = dump_path

        self.local        = local
        self.memory       = memory
        self.browser      = browser
        self.system       = system
        self.kerberos     = kerberos
        self.dumps        = dumps and bool(dump_path)
        self.remote       = remote and bool(ssh_host)

        self.ssh_host     = ssh_host or ""
        self.ssh_user     = ssh_user or ""
        self.ssh_key      = ssh_key or ""
        self.ssh_password = ssh_password or ""
        self.ssh_port     = max(1, min(ssh_port, 65535))

        # Attack flags — guard: disable if required params are missing
        self.dcsync       = dcsync and bool(dc_host and ad_domain and attack_hash)
        self.pth          = pth and bool(dc_host and attack_hash)
        self.ptt          = ptt and bool(ptt_ticket)
        self.forge_golden = forge_golden and bool(ad_domain and domain_sid and krbtgt_hash)
        self.forge_silver = forge_silver and bool(ad_domain and domain_sid and attack_hash and forge_silver_spn)

        self.dc_host          = dc_host.strip()
        self.ad_domain        = ad_domain.strip()
        self.domain_sid       = domain_sid.strip()
        self.krbtgt_hash      = krbtgt_hash.strip()
        self.attack_user      = attack_user.strip()
        self.attack_hash      = attack_hash.strip()
        self.attack_cmd       = attack_cmd.strip() or "whoami"
        self.ptt_ticket       = ptt_ticket.strip()
        self.forge_silver_spn = forge_silver_spn.strip()

        self.output       = output.strip()
        self.verbose      = verbose
        self.timeout      = max(5, min(timeout, 300))
