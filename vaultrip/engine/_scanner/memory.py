# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (c) 2026 CommonHuman-Lab
"""
Process memory scanning via /proc/<pid>/mem.

Reads mapped heap/stack regions from /proc/<pid>/maps, then reads those regions
from /proc/<pid>/mem and applies credential regex patterns. Requires ptrace
permissions (same UID as target process, or root).
"""

from __future__ import annotations

import logging
import re

from commonhuman_payloads.creds.patterns import ALL_PATTERNS

from ..reporter import Confidence, MemoryCredFinding, ScanResult
from .passive import PassiveInfo

log = logging.getLogger("vaultrip.memory")

_MAX_REGION_BYTES = 4 * 1024 * 1024   # 4 MB per region cap

# Region name patterns worth scanning (heap, stack, anonymous)
_INTERESTING_REGION_RE = re.compile(r"^\[heap\]$|^\[stack\]$|^$")

# Process names that commonly hold plaintext credentials in memory
CREDENTIAL_PROCESS_NAMES = frozenset({
    "python", "python3", "ruby", "java", "node", "nginx", "apache2",
    "httpd", "postgres", "mysqld", "redis-server", "vault", "sshd",
    "ssh-agent", "gpg-agent", "gnome-keyring-daemon", "kwallet5",
    "NetworkManager", "nm-applet", "pass",
})


def run(result: ScanResult, passive: PassiveInfo, target_pid: int | None = None) -> None:
    """Scan process memory for credential patterns."""
    pids_to_scan: list[tuple[int, str]] = []

    if target_pid is not None:
        name = _pid_name(target_pid)
        pids_to_scan = [(target_pid, name)]
    else:
        for pid, name in passive.running_pids:
            if name in CREDENTIAL_PROCESS_NAMES or passive.is_root:
                pids_to_scan.append((pid, name))

    for pid, name in pids_to_scan:
        _scan_pid(result, pid, name)


def _scan_pid(result: ScanResult, pid: int, name: str) -> None:
    maps_path = f"/proc/{pid}/maps"
    mem_path  = f"/proc/{pid}/mem"

    try:
        regions = _parse_maps(maps_path)
    except OSError:
        return

    try:
        with open(mem_path, "rb") as mem_fh:
            for start, end, region_name in regions:
                size = end - start
                if size <= 0 or size > _MAX_REGION_BYTES:
                    continue
                try:
                    mem_fh.seek(start)
                    data = mem_fh.read(min(size, _MAX_REGION_BYTES))
                except OSError:
                    continue
                _scan_region(result, pid, name, data, start)
    except OSError:
        return


def _scan_region(
    result: ScanResult,
    pid: int,
    process_name: str,
    data: bytes,
    base_offset: int,
) -> None:
    try:
        text = data.decode("utf-8", errors="replace")
    except Exception:
        return

    for pattern in ALL_PATTERNS:
        for match in pattern.pattern.finditer(text):
            value = match.group(1) if match.lastindex else match.group(0)
            value = value.strip()
            if len(value) < 4:
                continue
            offset = base_offset + match.start()
            confidence = Confidence.HIGH if pattern.confidence == "high" else Confidence.MEDIUM
            result.append_memory(MemoryCredFinding(
                pid=pid,
                process_name=process_name,
                credential_type=pattern.cred_type,
                value=value[:200],
                offset=offset,
                confidence=confidence,
            ))
            log.info(
                "memory: pid=%d (%s) pattern=%s offset=0x%x",
                pid, process_name, pattern.name, offset,
            )


def _parse_maps(maps_path: str) -> list[tuple[int, int, str]]:
    """Parse /proc/<pid>/maps and return readable (start, end, name) tuples."""
    regions = []
    with open(maps_path) as fh:
        for line in fh:
            parts = line.split()
            if len(parts) < 2:
                continue
            perms = parts[1]
            if "r" not in perms:  # must be readable
                continue
            addr_range = parts[0]
            region_name = parts[5] if len(parts) > 5 else ""
            try:
                start_s, end_s = addr_range.split("-")
                start, end = int(start_s, 16), int(end_s, 16)
            except ValueError:
                continue
            # Only scan heap, stack, and anonymous (no path) regions
            if not _INTERESTING_REGION_RE.match(region_name):
                continue
            regions.append((start, end, region_name))
    return regions


def _pid_name(pid: int) -> str:
    try:
        with open(f"/proc/{pid}/comm") as fh:
            return fh.read().strip()
    except OSError:
        return "unknown"
