# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (c) 2026 CommonHuman-Lab
from __future__ import annotations

import argparse

from commonhuman_cli.colour import CYAN, DIM
from commonhuman_cli.prompts import (
    prompt as _prompt,
)
from commonhuman_cli.prompts import (
    prompt_bool as _prompt_bool,
)
from commonhuman_cli.prompts import (
    safe_int as _safe_int,
)
from commonhuman_cli.prompts import (
    section as _section,
)

try:
    from vaultrip import BANNER, __version__
except ImportError:
    __version__ = "0.1.0"
    BANNER = ""


def interactive_prompts() -> argparse.Namespace:
    """Walk the user through all scan options interactively."""
    print(CYAN(BANNER))
    print(DIM("  No arguments supplied — entering interactive mode."))
    print(DIM("  Press Enter to accept defaults. Ctrl+C to exit.\n"))

    _section("Target")
    target = _prompt("  Sweep directory", default="~", hint="absolute path or ~ (default: ~)")

    _section("Modules")
    local    = _prompt_bool("  Filesystem sweep",        default=True)
    memory   = _prompt_bool("  Process memory scan",     default=True)
    browser  = _prompt_bool("  Browser credential stores", default=True)
    system   = _prompt_bool("  System keyrings",         default=True)
    kerberos = _prompt_bool("  Kerberos ticket extraction", default=True)

    _section("Scope")
    target_user = _prompt("  Restrict to user", hint="Unix username  (blank = current user)")
    pid_str     = _prompt("  Restrict memory to PID", hint="process PID  (blank = all)")

    _section("Offline dump")
    dump_path = _prompt("  Dump file path", hint="LSASS.dmp / SAM / NTDS.dit  (blank to skip)")

    _section("Remote (SSH)")
    ssh_host = _prompt("  SSH host", hint="blank to skip remote mode")
    if ssh_host:
        ssh_user = _prompt("  SSH user")
        ssh_key  = _prompt("  SSH key path", hint="~/.ssh/id_rsa")
        ssh_pass = _prompt("  SSH password", hint="blank if using key")
        ssh_port_str = _prompt("  SSH port", default="22")
    else:
        ssh_user = ssh_key = ssh_pass = ""
        ssh_port_str = "22"

    _section("Output")
    output  = _prompt("  JSON output file", hint="path to .json  (blank to skip)")
    verbose = _prompt_bool("  Verbose output", default=False)
    print()

    return argparse.Namespace(
        target=target or "~",
        no_local=not local,
        no_memory=not memory,
        no_browser=not browser,
        no_system=not system,
        no_kerberos=not kerberos,
        target_user=target_user or None,
        target_pid=_safe_int(pid_str, 0, 1, 999999) or None,
        dumps=dump_path or None,
        remote=ssh_host or None,
        ssh_user=ssh_user,
        ssh_key=ssh_key,
        ssh_pass=ssh_pass,
        ssh_port=_safe_int(ssh_port_str, 22, 1, 65535),
        # Attack modules — interactive mode always runs passive only
        dcsync=False, pth=False, ptt=False, forge_golden=False, forge_silver=False,
        dc_host="", ad_domain="", domain_sid="", krbtgt_hash="",
        attack_user="", attack_hash="", attack_cmd="whoami",
        ptt_ticket="", forge_silver_spn="",
        output=output,
        verbose=verbose,
        timeout=30,
    )


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="vaultrip",
        description="VaultRip — post-exploitation credential harvesting and extraction engine",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "Examples:\n"
            "  vaultrip ~                              # sweep current user's home\n"
            "  vaultrip --no-memory --no-system        # file + browser only\n"
            "  vaultrip --dumps /tmp/lsass.dmp         # parse offline LSASS dump\n"
            "  vaultrip --remote 192.168.1.10 --ssh-user root --ssh-key ~/.ssh/id_rsa\n"
        ),
    )
    p.add_argument("-V", "--version", action="version", version=f"%(prog)s {__version__}")
    p.add_argument("target", nargs="?", default="~",
                   help="Directory to sweep, or dump file path (default: ~)")

    # Module toggles
    mods = p.add_argument_group("module flags")
    mods.add_argument("--no-local",    action="store_true", dest="no_local",
                      help="Skip filesystem sweep")
    mods.add_argument("--no-memory",   action="store_true", dest="no_memory",
                      help="Skip process memory scan")
    mods.add_argument("--no-browser",  action="store_true", dest="no_browser",
                      help="Skip browser credential stores")
    mods.add_argument("--no-system",   action="store_true", dest="no_system",
                      help="Skip system keyrings (GNOME, kwallet, git, Docker)")
    mods.add_argument("--no-kerberos", action="store_true", dest="no_kerberos",
                      help="Skip Kerberos ticket extraction")
    mods.add_argument("--dumps",       default=None, metavar="PATH", dest="dumps",
                      help="Parse offline dump file (LSASS minidump / SAM / NTDS.dit)")

    # Scope
    scope = p.add_argument_group("scope")
    scope.add_argument("--user", default=None, metavar="USER", dest="target_user",
                       help="Restrict sweep to this Unix user's home directory")
    scope.add_argument("--pid",  default=None, type=int, metavar="PID", dest="target_pid",
                       help="Restrict memory scan to a single process PID")

    # Remote mode
    rem = p.add_argument_group("remote mode")
    rem.add_argument("--remote",   default=None, metavar="HOST",
                     help="SSH target for remote harvesting")
    rem.add_argument("--ssh-user", default="",   metavar="USER", dest="ssh_user",
                     help="SSH username")
    rem.add_argument("--ssh-key",  default="",   metavar="PATH", dest="ssh_key",
                     help="Path to SSH private key")
    rem.add_argument("--ssh-pass", default="",   metavar="PASS", dest="ssh_pass",
                     help="SSH password (prefer --ssh-key)")
    rem.add_argument("--ssh-port", default=22,   type=int, metavar="PORT", dest="ssh_port",
                     help="SSH port (default: 22)")

    # Attack modules
    atk = p.add_argument_group(
        "attack modules  ⚠  active operations — explicit opt-in required"
    )
    atk.add_argument("--dcsync",        action="store_true",
                     help="DCSync — replicate AD credentials via DRSUAPI")
    atk.add_argument("--pth",           action="store_true",
                     help="Pass-the-Hash — authenticate with --attack-hash")
    atk.add_argument("--ptt",           action="store_true",
                     help="Pass-the-Ticket — inject the ticket at --ptt-ticket")
    atk.add_argument("--forge-golden",  action="store_true", dest="forge_golden",
                     help="Forge a Kerberos golden ticket (requires --krbtgt-hash)")
    atk.add_argument("--forge-silver",  action="store_true", dest="forge_silver",
                     help="Forge a Kerberos silver ticket (requires --forge-silver-spn)")
    atk.add_argument("--dc",            default="", metavar="HOST", dest="dc_host",
                     help="Domain Controller address (dcsync, pth, forge)")
    atk.add_argument("--domain",        default="", metavar="DOMAIN", dest="ad_domain",
                     help="Active Directory domain name")
    atk.add_argument("--domain-sid",    default="", metavar="SID", dest="domain_sid",
                     help="Domain SID S-1-5-21-... (ticket forging)")
    atk.add_argument("--krbtgt-hash",   default="", metavar="HASH", dest="krbtgt_hash",
                     help="krbtgt NT hash (golden ticket)")
    atk.add_argument("--attack-user",   default="", metavar="USER", dest="attack_user",
                     help="Username to impersonate in attack modules")
    atk.add_argument("--attack-hash",   default="", metavar="HASH", dest="attack_hash",
                     help="NT hash for PTH / DCSync / silver ticket")
    atk.add_argument("--attack-cmd",    default="whoami", metavar="CMD", dest="attack_cmd",
                     help="Command to run after PTH (default: whoami)")
    atk.add_argument("--ptt-ticket",    default="", metavar="PATH", dest="ptt_ticket",
                     help="Path to .ccache or .kirbi to inject via PTT")
    atk.add_argument("--forge-silver-spn", default="", metavar="SPN", dest="forge_silver_spn",
                     help="SPN for silver ticket, e.g. cifs/host.domain.local")

    # Output
    out = p.add_argument_group("output")
    out.add_argument("-o", "--output",  default="", metavar="FILE",
                     help="Write JSON results to FILE")
    out.add_argument("-v", "--verbose", action="store_true",
                     help="Verbose output")
    out.add_argument("--timeout",       type=int, default=30,
                     help="Operation timeout seconds (default: 30)")

    return p
