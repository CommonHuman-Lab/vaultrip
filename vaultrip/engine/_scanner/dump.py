# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (c) 2026 CommonHuman-Lab
"""
Offline dump file parsing — LSASS minidumps, SAM/SYSTEM hives, NTDS.dit.

Uses impacket when available (pip install vaultrip[impacket]) for full
credential extraction. Without impacket, reports dump type + metadata only.
"""

from __future__ import annotations

import logging
import os

from ...creds.signatures import identify_dump

from ..reporter import DumpCredFinding, ScanResult

log = logging.getLogger("vaultrip.dump")


def run(result: ScanResult, dump_path: str) -> None:
    """Identify and parse the dump file at *dump_path*."""
    if not os.path.isfile(dump_path):
        log.warning("dump: path not found: %s", dump_path)
        return

    try:
        with open(dump_path, "rb") as fh:
            header = fh.read(64)
    except OSError as exc:
        log.warning("dump: cannot read %s: %s", dump_path, exc)
        return

    sig = identify_dump(header)
    if sig is None:
        log.warning("dump: unrecognised file format: %s", dump_path)
        return

    log.info("dump: identified %s in %s", sig.name, dump_path)

    dispatch = {
        "lsass": _parse_lsass,
        "sam":   _parse_sam,
        "ntds":  _parse_ntds,
    }
    handler = dispatch.get(sig.dump_type)
    if handler:
        handler(result, dump_path)
    else:
        log.info("dump: no parser for dump type '%s' (%s)", sig.dump_type, sig.name)


# ---------------------------------------------------------------------------
# LSASS minidump
# ---------------------------------------------------------------------------

def _parse_lsass(result: ScanResult, dump_path: str) -> None:
    _parse_lsass_impacket(result, dump_path)


def _parse_lsass_impacket(result: ScanResult, dump_path: str) -> None:
    try:
        from pypykatz.pypykatz import pypykatz as _pypykatz  # type: ignore[import]
        mimi = _pypykatz.parse_minidump_file(dump_path)
        for luid, session in mimi.logon_sessions.items():
            for msv in session.msv_creds:
                result.append_dump(DumpCredFinding(
                    dump_path=dump_path,
                    dump_type="lsass",
                    username=msv.username or "",
                    domain=msv.domainname,
                    nt_hash=msv.NThash.hex() if msv.NThash else None,
                    lm_hash=msv.LMhash.hex() if msv.LMhash else None,
                    plaintext=msv.password,
                ))
                log.info("dump: lsass cred: %s\\%s", msv.domainname, msv.username)
            for wdigest in session.wdigest_creds:
                if wdigest.password:
                    result.append_dump(DumpCredFinding(
                        dump_path=dump_path,
                        dump_type="lsass",
                        username=wdigest.username or "",
                        domain=wdigest.domainname,
                        plaintext=wdigest.password,
                    ))
    except ImportError:
        log.info("dump: pypykatz not installed — LSASS minidump parsing unavailable")
        result.append_dump(DumpCredFinding(
            dump_path=dump_path,
            dump_type="lsass",
            username="<pypykatz required for extraction>",
        ))
    except Exception as exc:
        log.warning("dump: lsass parse error in %s: %s", dump_path, exc)


# ---------------------------------------------------------------------------
# SAM + SYSTEM hive
# ---------------------------------------------------------------------------

def _parse_sam(result: ScanResult, dump_path: str) -> None:
    """Parse offline SAM hive.

    Requires the companion SYSTEM hive to derive the boot key.
    We look for a SYSTEM file adjacent to the dump path.
    """
    system_path = _find_companion(dump_path, "SYSTEM")
    if not system_path:
        log.info(
            "dump: SAM hive found but no companion SYSTEM hive — "
            "place SAM and SYSTEM in the same directory"
        )
        result.append_dump(DumpCredFinding(
            dump_path=dump_path,
            dump_type="sam",
            username="<SYSTEM hive required for extraction>",
        ))
        return

    try:
        from impacket.examples.secretsdump import LocalOperations, SAMHashes  # type: ignore[import]
        local_ops = LocalOperations(system_path)
        boot_key  = local_ops.getBootKey()
        sam_hashes = SAMHashes(dump_path, boot_key, isRemote=False)
        sam_hashes.dump()
        for item in sam_hashes._SAMHashes__itemsFound:
            username  = item.get("username", "")
            nt_hash   = item.get("nthash", "")
            lm_hash   = item.get("lmhash", "")
            result.append_dump(DumpCredFinding(
                dump_path=dump_path,
                dump_type="sam",
                username=username,
                nt_hash=nt_hash or None,
                lm_hash=lm_hash or None,
            ))
            log.info("dump: SAM hash: %s NT=%s", username, nt_hash)
    except ImportError:
        log.info("dump: impacket not installed — install vaultrip[impacket] for SAM parsing")
        result.append_dump(DumpCredFinding(
            dump_path=dump_path,
            dump_type="sam",
            username="<impacket required for extraction>",
        ))
    except Exception as exc:
        log.warning("dump: SAM parse error: %s", exc)


# ---------------------------------------------------------------------------
# NTDS.dit
# ---------------------------------------------------------------------------

def _parse_ntds(result: ScanResult, dump_path: str) -> None:
    system_path = _find_companion(dump_path, "SYSTEM")
    if not system_path:
        log.info("dump: NTDS.dit found but no companion SYSTEM hive")
        result.append_dump(DumpCredFinding(
            dump_path=dump_path,
            dump_type="ntds",
            username="<SYSTEM hive required for extraction>",
        ))
        return

    try:
        from impacket.examples.secretsdump import (  # type: ignore[import]
            LocalOperations,
            NTDSHashes,
        )
        local_ops = LocalOperations(system_path)
        boot_key  = local_ops.getBootKey()
        ntds = NTDSHashes(dump_path, boot_key, isRemote=False)
        ntds.dump()
        for item in ntds._NTDSHashes__itemsFound:
            parts = item.split(":")
            if len(parts) >= 4:
                user   = parts[0]
                domain = parts[1] if len(parts) > 5 else None
                nt     = parts[3] if len(parts) > 3 else None
                lm     = parts[2] if len(parts) > 2 else None
                result.append_dump(DumpCredFinding(
                    dump_path=dump_path,
                    dump_type="ntds",
                    username=user,
                    domain=domain,
                    nt_hash=nt or None,
                    lm_hash=lm or None,
                ))
                log.info("dump: NTDS hash: %s NT=%s", user, nt)
    except ImportError:
        log.info("dump: impacket not installed — install vaultrip[impacket] for NTDS parsing")
        result.append_dump(DumpCredFinding(
            dump_path=dump_path,
            dump_type="ntds",
            username="<impacket required for extraction>",
        ))
    except Exception as exc:
        log.warning("dump: NTDS parse error: %s", exc)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _find_companion(dump_path: str, filename: str) -> str | None:
    """Look for *filename* in the same directory as *dump_path*."""
    dirpath = os.path.dirname(os.path.abspath(dump_path))
    candidate = os.path.join(dirpath, filename)
    return candidate if os.path.isfile(candidate) else None
