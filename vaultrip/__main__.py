# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (c) 2026 CommonHuman-Lab
"""
VaultRip — __main__.py
CLI entry point.

Usage:
    python -m vaultrip ~
    vaultrip --dumps /tmp/lsass.dmp
    vaultrip --remote 192.168.1.10 --ssh-user root --ssh-key ~/.ssh/id_rsa
"""

from __future__ import annotations

import os
import sys

_HERE   = os.path.dirname(os.path.abspath(__file__))
_PARENT = os.path.dirname(_HERE)
for _p in (_PARENT, _HERE):
    if _p not in sys.path:
        sys.path.insert(0, _p)

from commonhuman_cli.colour import CYAN  # noqa: E402
from commonhuman_cli.logging import setup_logging  # noqa: E402

from vaultrip import BANNER  # noqa: E402
from vaultrip._cli.args import build_parser, interactive_prompts  # noqa: E402
from vaultrip._cli.summary import print_summary  # noqa: E402
from vaultrip.engine import ScanOptions, scan  # noqa: E402
from vaultrip.engine.log import get_logger  # noqa: E402

_cli_logger = get_logger("vaultrip")


def main() -> None:
    parser = build_parser()
    args   = parser.parse_args()

    # No target and no special flags → interactive mode
    interactive = (
        args.target == "~"
        and not args.dumps
        and not args.remote
        and not args.no_local
        and not args.no_memory
        and not args.no_browser
        and not args.no_system
        and not args.no_kerberos
        and len(sys.argv) == 1
    )
    if interactive:
        args = interactive_prompts()
    else:
        print(CYAN(BANNER))

    setup_logging(verbose=args.verbose, quiet=False, logger_name="vaultrip")

    target = os.path.expanduser(args.target or "~")

    options = ScanOptions(
        target_user  = args.target_user,
        target_pid   = args.target_pid,
        dump_path    = args.dumps,
        local        = not args.no_local,
        memory       = not args.no_memory,
        browser      = not args.no_browser,
        system       = not args.no_system,
        kerberos     = not args.no_kerberos,
        dumps        = bool(args.dumps),
        remote       = bool(args.remote),
        ssh_host     = args.remote or "",
        ssh_user     = args.ssh_user or "",
        ssh_key      = args.ssh_key or "",
        ssh_password = args.ssh_pass or "",
        ssh_port     = args.ssh_port,
        # Attack modules
        dcsync           = getattr(args, "dcsync", False),
        pth              = getattr(args, "pth", False),
        ptt              = getattr(args, "ptt", False),
        forge_golden     = getattr(args, "forge_golden", False),
        forge_silver     = getattr(args, "forge_silver", False),
        dc_host          = getattr(args, "dc_host", ""),
        ad_domain        = getattr(args, "ad_domain", ""),
        domain_sid       = getattr(args, "domain_sid", ""),
        krbtgt_hash      = getattr(args, "krbtgt_hash", ""),
        attack_user      = getattr(args, "attack_user", ""),
        attack_hash      = getattr(args, "attack_hash", ""),
        attack_cmd       = getattr(args, "attack_cmd", "whoami"),
        ptt_ticket       = getattr(args, "ptt_ticket", ""),
        forge_silver_spn = getattr(args, "forge_silver_spn", ""),
        output       = args.output,
        verbose      = args.verbose,
        timeout      = args.timeout,
    )

    _cli_logger.info("Starting VaultRip against: %s", target)

    result = scan(target=target, options=options)

    if args.output:
        pass  # scan() already wrote the JSON file
    else:
        print_summary(result, verbose=args.verbose)

    sys.exit(0 if result.total_findings == 0 else 1)


if __name__ == "__main__":
    main()
