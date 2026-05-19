# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (c) 2026 CommonHuman-Lab
"""
VaultRip — engine/scanner.py
Top-level scan() entry point.
"""

from __future__ import annotations

import json

from ._scanner.options import ScanOptions  # noqa: F401 (re-exported)
from ._scanner.pipeline import run
from .log import ScanResultHandler, get_logger
from .reporter import ScanResult

logger = get_logger("vaultrip.scanner")


def scan(target: str = "~", options: ScanOptions | None = None) -> ScanResult:
    """Run a full VaultRip sweep against *target* and return a ScanResult.

    *target* is the directory root to sweep (defaults to current user's home).
    When ``options.remote`` is True, *target* is ignored in favour of
    ``options.ssh_host``.
    """
    if options is None:
        options = ScanOptions()

    result  = ScanResult(target=target)
    _root   = get_logger("vaultrip")
    _handler = ScanResultHandler(result)
    _handler.setFormatter(__import__("logging").Formatter("%(name)s: %(message)s"))
    _root.addHandler(_handler)

    try:
        run(options, result)
    except Exception as exc:
        result.append_error(f"Scan aborted: {exc}")
        logger.exception("VaultRip scan error")
    finally:
        _root.removeHandler(_handler)
        result.finish()

    if options.output:
        try:
            with open(options.output, "w", encoding="utf-8") as fh:
                json.dump(result.to_dict(), fh, indent=2)
        except OSError as exc:
            result.append_error(f"Failed to write output file: {exc}")

    return result
