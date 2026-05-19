# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (c) 2026 CommonHuman-Lab
"""
Passive checks — non-invasive metadata collection before active harvesting.

Reads only: /proc/<pid>/status (no mem access), /etc/passwd, environment variables,
running user context, and basic OS info. Never reads sensitive file contents here.
"""

from __future__ import annotations

import logging
import os
import pwd
import subprocess
from dataclasses import dataclass, field

log = logging.getLogger("vaultrip.passive")


@dataclass
class PassiveInfo:
    current_user: str
    current_uid:  int
    is_root:      bool
    home_dirs:    list[str]                    = field(default_factory=list)
    running_pids: list[tuple[int, str]]        = field(default_factory=list)  # (pid, name)
    krb5ccname:   str | None                = None
    sudo_capable: bool                         = False
    active_sessions: list[str]                 = field(default_factory=list)  # "user@tty"


def collect(target_user: str | None = None) -> PassiveInfo:
    """Collect passive host metadata without accessing sensitive content."""
    uid  = os.getuid()
    info = PassiveInfo(
        current_user=_current_username(),
        current_uid=uid,
        is_root=(uid == 0),
        krb5ccname=os.environ.get("KRB5CCNAME"),
    )

    info.home_dirs = _enumerate_home_dirs(target_user, info.is_root)
    info.running_pids = _enumerate_pids()
    info.sudo_capable = _check_sudo()
    info.active_sessions = _enumerate_sessions()

    log.debug(
        "passive: user=%s uid=%d root=%s homes=%d pids=%d",
        info.current_user, info.current_uid, info.is_root,
        len(info.home_dirs), len(info.running_pids),
    )
    return info


def _current_username() -> str:
    try:
        return pwd.getpwuid(os.getuid()).pw_name
    except KeyError:
        return os.environ.get("USER", "unknown")


def _enumerate_home_dirs(target_user: str | None, is_root: bool) -> list[str]:
    dirs = []
    if target_user:
        try:
            entry = pwd.getpwnam(target_user)
            if os.path.isdir(entry.pw_dir):
                dirs.append(entry.pw_dir)
        except KeyError:
            pass
        return dirs

    if is_root:
        try:
            for entry in pwd.getpwall():
                if entry.pw_uid >= 1000 or entry.pw_name == "root":
                    if os.path.isdir(entry.pw_dir):
                        dirs.append(entry.pw_dir)
        except Exception:
            pass
    else:
        home = os.path.expanduser("~")
        if os.path.isdir(home):
            dirs.append(home)
    return list(dict.fromkeys(dirs))  # deduplicate, preserve order


def _enumerate_pids() -> list[tuple[int, str]]:
    pids = []
    try:
        for entry in os.scandir("/proc"):
            if not entry.name.isdigit():
                continue
            pid = int(entry.name)
            comm_path = f"/proc/{pid}/comm"
            try:
                with open(comm_path) as fh:
                    name = fh.read().strip()
                pids.append((pid, name))
            except OSError:
                continue
    except PermissionError:
        pass
    return pids


def _check_sudo() -> bool:
    try:
        result = subprocess.run(
            ["sudo", "-n", "true"],
            capture_output=True,
            timeout=3,
        )
        return result.returncode == 0
    except (FileNotFoundError, subprocess.TimeoutExpired):
        return False


def _enumerate_sessions() -> list[str]:
    sessions = []
    try:
        result = subprocess.run(
            ["who"], capture_output=True, text=True, timeout=5
        )
        for line in result.stdout.splitlines():
            parts = line.split()
            if len(parts) >= 2:
                sessions.append(f"{parts[0]}@{parts[1]}")
    except (FileNotFoundError, subprocess.TimeoutExpired):
        pass
    return sessions
