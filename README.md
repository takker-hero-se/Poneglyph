# Poneglyph

Active Directory NTDS.dit forensic analysis tool.

**[日本語版 README はこちら](README.ja.md)**

Poneglyph parses NTDS.dit (Active Directory database) offline and extracts users, computers, groups, trusts, password hashes, and performs forensic analysis including tombstone recovery and anomaly detection.

## Features

- **ESE Database Parsing** - Direct NTDS.dit access via libesedb (no Active Directory required)
- **Windows Server 2025 Support** - 32KB ESE page format support (patched libesedb)
- **Password Hash Extraction** - BootKey + PEK decryption pipeline for NT/LM hash recovery
- **Full Object Extraction** - Users, computers, groups, GPOs, trust relationships
- **BloodHound Integration** - BloodHound CE v5 compatible JSON output
- **Graph Visualization** - D3.js force-directed graph JSON for relationship mapping
- **Forensic Timeline** - CSV timeline of AD object changes (plaso compatible)
- **Tombstone Recovery** - Deleted object recovery from ESE tombstones
- **Anomaly Detection** - 14-rule security assessment engine with MITRE ATT&CK mapping
- **Live Collection** - Volume Shadow Copy based NTDS.dit acquisition from running DCs

## Installation

Download the latest release from the [Releases](https://github.com/takker-hero-se/Poneglyph/releases) page.

## Usage

### Full Dump (All Outputs)

```
poneglyph dump --ntds ntds.dit --system SYSTEM --all
```

Generates BloodHound JSON, graph, timeline, and hashcat output in `poneglyph-output/`.

### Hash Extraction

```
poneglyph hashes --ntds ntds.dit --system SYSTEM
```

Output format (hashcat/secretsdump compatible):
```
Administrator:500:aad3b435b51404eeaad3b435b51404ee:8846f7eaee8fb117ad06bdd830b7586c:::
```

### Forensic Analysis

```
poneglyph forensics --ntds ntds.dit --acls
```

Runs tombstone recovery and 14 anomaly detection rules. `--acls` enables DCSync ACL analysis.

### User Listing

```
poneglyph users --ntds ntds.dit --format table
```

### Database Info

```
poneglyph info --ntds ntds.dit
```

### Live Collection (on Domain Controller)

```
poneglyph collect --zip
```

Uses Volume Shadow Copy to safely acquire NTDS.dit and SYSTEM hive.

## Batch Scripts

### `run-all.bat` - Full Offline Analysis

```
run-all.bat <ntds.dit> <SYSTEM> [output_dir]
```

Runs all 9 analysis steps: info, users (table/JSON/CSV), hashes (hashcat/john/pwdump), forensics (with ACL), and full dump (BloodHound/Graph/Timeline).

### `collect.bat` - Live DC Collection

```
collect.bat [output_dir]
```

Collects NTDS.dit and SYSTEM hive from a running Domain Controller via VSS. Requires Administrator privileges. Default output directory includes domain name and hostname: `poneglyph-collect_<DOMAIN>_<HOSTNAME>`.

## CLI Reference

| Subcommand | Description | Required Flags |
|------------|-------------|----------------|
| `info` | Display database tables and record counts | `--ntds` |
| `users` | Extract user accounts | `--ntds` |
| `hashes` | Extract password hashes | `--ntds`, `--system` |
| `dump` | Full extraction with all output formats | `--ntds` |
| `forensics` | Tombstone recovery + anomaly detection | `--ntds` |
| `collect` | Acquire NTDS.dit from live DC | (none) |

### `users` Options

| Flag | Description |
|------|-------------|
| `--ntds <PATH>` | Path to NTDS.dit file |
| `-f, --format <FMT>` | Output format: `table`, `json`, `csv` (default: `table`) |
| `-o, --output <PATH>` | Output file path (stdout if omitted) |
| `--include-disabled` | Include disabled accounts |

### `hashes` Options

| Flag | Description |
|------|-------------|
| `--ntds <PATH>` | Path to NTDS.dit file |
| `-s, --system <PATH>` | Path to SYSTEM registry hive |
| `-o, --output <PATH>` | Output file path (stdout if omitted) |
| `--format <FMT>` | Output format: `hashcat`, `john`, `pwdump` (default: `hashcat`) |

### `forensics` Options

| Flag | Description |
|------|-------------|
| `--ntds <PATH>` | Path to NTDS.dit file |
| `-o, --output-dir <DIR>` | Output directory (default: `poneglyph-forensics`) |
| `--acls` | Include ACL analysis for DCSync detection (slower) |

### `dump` Options

| Flag | Description |
|------|-------------|
| `--ntds <PATH>` | Path to NTDS.dit file |
| `--system <PATH>` | Path to SYSTEM registry hive (for hash extraction) |
| `-o, --output-dir <DIR>` | Output directory (default: `poneglyph-output`) |
| `--domain <NAME>` | Domain name (auto-detected if omitted) |
| `--bloodhound` | Generate BloodHound CE JSON |
| `--hashcat` | Generate hashcat-format hashes |
| `--graph` | Generate D3.js graph JSON |
| `--timeline` | Generate forensic timeline CSV |
| `--all` | Generate all output formats |

### `collect` Options

| Flag | Description |
|------|-------------|
| `-o, --output-dir <DIR>` | Output directory (default: `poneglyph-collect`) |
| `--ntds-path <PATH>` | Custom NTDS.dit path (auto-detect if omitted) |
| `--no-cleanup` | Don't delete the shadow copy after collection |
| `--zip` | Create a zip archive of collected files |

## Output Formats

### BloodHound JSON (`bloodhound/`)

BloodHound CE v5 compatible. Generates `00-users.json`, `00-groups.json`, `00-computers.json`, `00-domains.json`.

### Graph JSON (`graph.json`)

D3.js force-directed graph with nodes (users, computers, groups, DCs) and links (MemberOf, TrustBy).

### Timeline CSV (`timeline.csv`)

Plaso-compatible CSV with columns: `datetime`, `timestamp_desc`, `source`, `message`, `extra`.
Events include account creation, modification, password changes, logon timestamps, and lockouts.

### Hashcat (`hashes.txt`)

secretsdump-compatible format: `username:RID:LM_HASH:NT_HASH:::`

### Forensics Report (`forensics-report.json`)

JSON report containing metadata, deleted objects (tombstones), anomaly findings, and severity summary.

## Anomaly Detection Rules

| ID | Rule | Severity | MITRE |
|----|------|----------|-------|
| ANOM-001 | AS-REP Roastable Accounts | High | T1558.004 |
| ANOM-002 | Password Not Required | High | T1078 |
| ANOM-003 | Non-Expiring Password on Privileged Accounts | Medium | T1078.002 |
| ANOM-004 | Stale Enabled Accounts (>90 days) | Low | T1078 |
| ANOM-005 | Never-Logged-In Enabled Accounts | Low | - |
| ANOM-006 | Unconstrained Delegation | Critical | T1550.003 |
| ANOM-007 | Constrained Delegation with Protocol Transition | High | T1550.003 |
| ANOM-008 | adminCount=1 Accounts | Info | - |
| ANOM-009 | High Bad Password Count (>=5) | Medium | T1110 |
| ANOM-010 | Recently Created Accounts (<30 days) | Info | T1136.002 |
| ANOM-011 | DCSync-Capable Non-Admin (ACL) | Critical | T1003.006 |
| ANOM-012 | SID History Present | High | T1134.005 |
| ANOM-013 | Shadow Credentials (KeyCredentialLink) | High | T1098.004 |
| ANOM-014 | Kerberoastable User Accounts (SPN) | High | T1558.003 |

## Testing

66 unit tests covering all pure functions (no database required):

```bash
cargo test
```

| Module | Tests | Coverage |
|--------|-------|----------|
| `crypto_tests` | 12 | DES key expansion, RID-to-DES, RC4 round-trip, AES-128-CBC (NIST vector), PEK/hash error paths |
| `sid_tests` | 12 | parse_sid, extract_rid, domain_sid, edge cases (empty, truncated, well-known RIDs) |
| `timestamp_tests` | 7 | FILETIME-to-string/epoch, edge cases (zero, max, negative, pre-epoch, Unix epoch) |
| `uac_tests` | 8 | UAC flag interpretation (NORMAL, DISABLED, PREAUTH, DELEGATION, etc.) |
| `group_type_tests` | 5 | Security/Distribution, Global/Universal/DomainLocal/BuiltinLocal |
| `trust_tests` | 6 | UTF-16LE decode, trust direction/type string conversion |
| `acl_tests` | 4 | Security descriptor parsing (DACL, ACE types, GenericAll) |
| `anomaly_tests` | 12 | ANOM-001~014 rules (AS-REP, PASSWD_NOTREQD, delegation, DCSync, SID history, etc.) |

## Architecture

```
src/
├── main.rs              # CLI entry point (6 subcommands)
├── lib.rs               # Library exports
├── ese.rs               # ESE database interface
├── schema.rs            # ATT code -> LDAP attribute mapping
├── bootkey.rs           # BootKey extraction from SYSTEM hive
├── crypto.rs            # PEK + hash decryption (DES/AES)
├── collect.rs           # Live DC collection (VSS)
├── links.rs             # Group membership resolution
├── acl.rs               # Security descriptor / ACE parsing
├── objects/
│   ├── mod.rs           # Core extraction, SID parsing
│   ├── user.rs          # AdUser
│   ├── computer.rs      # AdComputer
│   ├── group.rs         # AdGroup
│   ├── gpo.rs           # AdGPO
│   └── trust.rs         # AdTrust
├── output/
│   ├── bloodhound.rs    # BloodHound CE v5 JSON
│   ├── graph.rs         # D3.js graph JSON
│   ├── csv.rs           # Forensic timeline CSV
│   └── hashcat.rs       # Hashcat format
└── forensics/
    ├── mod.rs           # Report orchestration
    ├── tombstone.rs     # Deleted object recovery
    └── anomaly.rs       # 14 detection rules
```

## Building from Source

### Requirements

- Rust (`stable-x86_64-pc-windows-gnu`)
- MSYS2 with `mingw-w64-x86_64-gcc` and `mingw-w64-x86_64-binutils`

### Build

```bash
export PATH="/c/msys64/mingw64/bin:$PATH"
export CFLAGS="-DHAVE_WINDOWS_H=1 -DWIN32_LEAN_AND_MEAN=1 -Wno-error=implicit-function-declaration -Wno-error=int-conversion"

cargo build --release
```

The binary will be at `target/release/poneglyph.exe`.

### Windows Server 2025 Support

To support 32KB ESE pages used by Windows Server 2025, apply the included patches to libesedb-sys:

```bash
# 1. Clone libesedb-sys
cargo download libesedb-sys  # or clone from crates.io source
# 2. Apply patches
cd libesedb-sys
patch -p1 < /path/to/poneglyph/libesedb-patches/fix-ws2025-itag-state.patch
patch -p1 < /path/to/poneglyph/libesedb-patches/zzz-fix-ws2025-btree.patch
# 3. Uncomment [patch.crates-io] in Cargo.toml and set the path
```

Without these patches, Poneglyph supports Windows Server 2019 and earlier (8KB pages) only.

## Troubleshooting

### Japanese characters in file paths

Poneglyph uses libesedb (a C library) internally, which calls `fopen()` to open files. On Windows, `fopen()` interprets paths using the ANSI codepage (CP932/Shift-JIS for Japanese), but Rust passes paths as UTF-8. This encoding mismatch causes file open failures when the path contains non-ASCII characters such as Japanese.

**Solution: Enable Windows UTF-8 mode**

1. Open **Settings** > **Time & Language** > **Language & Region** > **Administrative language settings**
2. Click **Change system locale**
3. Check **"Beta: Use Unicode UTF-8 for worldwide language support"**
4. Restart Windows

This makes `fopen()` accept UTF-8 paths, allowing Poneglyph to open files in paths containing Japanese or other non-ASCII characters.

**Alternative workaround**: Copy the NTDS.dit and SYSTEM files to an ASCII-only path (e.g., `C:\dev\`) and run from PowerShell.

## License

This project is licensed under the [GNU Lesser General Public License v3.0 or later](COPYING.LESSER).

Poneglyph statically links [libesedb](https://github.com/libyal/libesedb) (LGPL-3.0+), so this project adopts the same license for compatibility.
