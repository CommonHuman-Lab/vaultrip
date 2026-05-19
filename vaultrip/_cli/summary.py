# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (c) 2026 CommonHuman-Lab
"""Terminal output helpers for VaultRip scan results."""

from __future__ import annotations

from commonhuman_cli.colour import BOLD, CYAN, DIM, GREEN, RED, YELLOW

from ..engine.reporter import (
    BrowserCredFinding,
    Confidence,
    DCSyncFinding,
    DumpCredFinding,
    FileCredFinding,
    ForgedTicketFinding,
    KerberosTicketFinding,
    MemoryCredFinding,
    PTHFinding,
    ScanResult,
    SystemCredFinding,
)

_CONF_COLOR = {
    Confidence.HIGH:   RED,
    Confidence.MEDIUM: YELLOW,
    Confidence.LOW:    DIM,
}


def print_summary(result: ScanResult, verbose: bool = False) -> None:
    """Print a human-readable summary of *result* to stdout."""
    _header(result)
    if result.files:
        _section_files(result.files, verbose)
    if result.memory:
        _section_memory(result.memory, verbose)
    if result.browser:
        _section_browser(result.browser, verbose)
    if result.system:
        _section_system(result.system, verbose)
    if result.kerberos:
        _section_kerberos(result.kerberos, verbose)
    if result.dumps:
        _section_dumps(result.dumps, verbose)
    if result.dcsync:
        _section_dcsync(result.dcsync, verbose)
    if result.pth_results:
        _section_pth(result.pth_results, verbose)
    if result.forged_tickets:
        _section_forged(result.forged_tickets, verbose)
    _footer(result)


def _header(result: ScanResult) -> None:
    print()
    print(BOLD(CYAN("╔══════════════════════════════════════════╗")))
    print(BOLD(CYAN("║           VaultRip — Results             ║")))
    print(BOLD(CYAN("╚══════════════════════════════════════════╝")))
    print(f"  Target : {CYAN(result.target)}")
    print(f"  Time   : {result.duration_s:.1f}s")
    print(f"  Found  : {BOLD(str(result.total_findings))} credential(s)")
    print()


def _section_files(findings: list[FileCredFinding], verbose: bool) -> None:  # noqa: ARG001
    print(BOLD("  [FILES]"))
    for f in findings:
        color = _CONF_COLOR[f.confidence]
        tag   = f"[{f.service}/{f.credential_type}]"
        val   = f"  value={f.value[:60]}..." if f.value else ""
        print(f"    {color(tag):<30} {DIM(f.path)}{val}")
    print()


def _section_memory(findings: list[MemoryCredFinding], verbose: bool) -> None:
    print(BOLD("  [MEMORY]"))
    for f in findings:
        color = _CONF_COLOR[f.confidence]
        print(
            f"    {color('[' + f.credential_type + ']'):<30} "
            f"pid={f.pid} ({f.process_name}) "
            f"{DIM('offset=0x' + hex(f.offset)[2:])}"
        )
        if verbose and f.value:
            print(f"      {DIM(f.value[:80])}")
    print()


def _section_browser(findings: list[BrowserCredFinding], verbose: bool) -> None:
    print(BOLD("  [BROWSER]"))
    for f in findings:
        decrypted = GREEN("decrypted") if f.password else YELLOW("encrypted")
        print(f"    [{f.browser}] {CYAN(f.url)}")
        print(f"      user={f.username}  pass={decrypted}")
        if verbose and f.password:
            print(f"      {DIM(f.password[:80])}")
    print()


def _section_system(findings: list[SystemCredFinding], verbose: bool) -> None:
    print(BOLD("  [SYSTEM STORES]"))
    for f in findings:
        has_secret = GREEN("yes") if f.secret else YELLOW("no")
        print(f"    [{f.store}] {CYAN(f.label)}  user={f.username or '-'}  secret={has_secret}")
        if verbose and f.secret:
            print(f"      {DIM(f.secret[:80])}")
    print()


def _section_kerberos(findings: list[KerberosTicketFinding], verbose: bool) -> None:
    print(BOLD("  [KERBEROS]"))
    for f in findings:
        src = DIM(f"({f.source_type}: {f.source_path})")
        print(f"    {RED(f.principal)} → {CYAN(f.service)}")
        print(f"      expires={f.expires}  {src}")
        if verbose and f.ticket_bytes:
            print(f"      {DIM(len(f.ticket_bytes))} bytes of ticket material")
    print()


def _section_dumps(findings: list[DumpCredFinding], verbose: bool) -> None:
    print(BOLD("  [DUMP]"))
    for f in findings:
        domain_str = f"{f.domain}\\" if f.domain else ""
        print(f"    [{f.dump_type}] {RED(domain_str + f.username)}")
        if f.nt_hash:
            print(f"      NT={YELLOW(f.nt_hash)}", end="")
            if f.lm_hash:
                print(f"  LM={DIM(f.lm_hash)}", end="")
            print()
        if f.plaintext and verbose:
            print(f"      plaintext={GREEN(f.plaintext)}")
    print()


def _section_dcsync(findings: list[DCSyncFinding], verbose: bool) -> None:
    print(BOLD("  [DCSYNC]"))
    for f in findings:
        domain_str = f"{f.domain}\\" if f.domain else ""
        print(f"    {RED(domain_str + f.username)}")
        if f.nt_hash:
            print(f"      NT={YELLOW(f.nt_hash)}", end="")
            if f.lm_hash:
                print(f"  LM={DIM(f.lm_hash)}", end="")
            print()
        if f.plaintext and verbose:
            print(f"      plaintext={GREEN(f.plaintext)}")
    print()


def _section_pth(findings: list[PTHFinding], verbose: bool) -> None:
    print(BOLD("  [PASS-THE-HASH]"))
    for f in findings:
        status = GREEN("success") if f.success else RED(f"exit={f.exit_code}")
        print(f"    {CYAN(f.target)}  user={f.username}  cmd={DIM(f.command)}  {status}")
        if f.stdout and verbose:
            for line in f.stdout.splitlines()[:10]:
                print(f"      {DIM(line)}")
    print()


def _section_forged(findings: list[ForgedTicketFinding], verbose: bool) -> None:
    print(BOLD("  [FORGED TICKETS]"))
    for f in findings:
        injected_str = GREEN("injected → KRB5CCNAME") if f.injected else DIM("not injected")
        if f.ticket_type == "injected":
            print(f"    [ptt] {injected_str}  path={DIM(f.ticket_path)}")
        else:
            domain_str = f"{f.domain}\\{f.username}" if f.username else f.domain
            spn_str    = f"  spn={CYAN(f.spn)}" if f.spn else ""
            print(f"    [{f.ticket_type}] {RED(domain_str)}{spn_str}  {injected_str}")
            if verbose:
                print(f"      ccache={DIM(f.ticket_path)}")
    print()


def _footer(result: ScanResult) -> None:
    if result.errors:
        print(YELLOW("  Errors:"))
        for err in result.errors:
            print(f"    {DIM(err)}")
        print()
    total = result.total_findings
    if total == 0:
        print(DIM("  No credentials found."))
    else:
        print(BOLD(f"  {RED(str(total))} credential finding(s) — review and remediate."))
    print()
