# Poneglyph

Active Directory NTDS.dit forensic analysis tool.
Active Directory の NTDS.dit フォレンジック分析ツール。

Poneglyph parses NTDS.dit (Active Directory database) offline and extracts users, computers, groups, trusts, password hashes, and performs forensic analysis including tombstone recovery and anomaly detection.

Poneglyph は NTDS.dit（Active Directory データベース）をオフラインで解析し、ユーザー・コンピューター・グループ・信頼関係・パスワードハッシュを抽出します。さらに、削除オブジェクトの復元や異常検知などのフォレンジック分析も実行できます。

## Features / 機能

- **ESE Database Parsing / ESEデータベース解析** - Direct NTDS.dit access via libesedb (no Active Directory required) / libesedb による直接アクセス（AD環境不要）
- **Password Hash Extraction / パスワードハッシュ抽出** - BootKey + PEK decryption pipeline for NT/LM hash recovery / BootKey + PEK 復号パイプラインによる NT/LM ハッシュ復元
- **Full Object Extraction / 全オブジェクト抽出** - Users, computers, groups, GPOs, trust relationships / ユーザー、コンピューター、グループ、GPO、信頼関係
- **BloodHound Integration / BloodHound連携** - BloodHound CE v5 compatible JSON output / BloodHound CE v5 互換の JSON 出力
- **Graph Visualization / グラフ可視化** - D3.js force-directed graph JSON for relationship mapping / D3.js フォースグラフ用 JSON（関係性マッピング）
- **Forensic Timeline / フォレンジックタイムライン** - CSV timeline of AD object changes (plaso compatible) / AD オブジェクト変更の CSV タイムライン（plaso 互換）
- **Tombstone Recovery / 削除オブジェクト復元** - Deleted object recovery from ESE tombstones / ESE トゥームストーンからの削除オブジェクト復元
- **Anomaly Detection / 異常検知** - 14-rule security assessment engine with MITRE ATT&CK mapping / MITRE ATT&CK マッピング付き 14 ルールのセキュリティ診断エンジン
- **Live Collection / ライブ収集** - Volume Shadow Copy based NTDS.dit acquisition from running DCs / ボリュームシャドウコピーによる稼働中 DC からの NTDS.dit 取得

## Installation / インストール

Download the latest release from the [Releases](https://github.com/takker-hero-se/Poneglyph/releases) page.

[Releases](https://github.com/takker-hero-se/Poneglyph/releases) ページから最新版をダウンロードしてください。

## Usage / 使い方

### Full Dump (All Outputs) / フルダンプ（全出力）

```
poneglyph dump --ntds ntds.dit --system SYSTEM --all
```

Generates BloodHound JSON, graph, timeline, and hashcat output in `poneglyph-output/`.

BloodHound JSON、グラフ、タイムライン、hashcat 出力を `poneglyph-output/` に生成します。

### Hash Extraction / ハッシュ抽出

```
poneglyph hashes --ntds ntds.dit --system SYSTEM
```

Output format (hashcat/secretsdump compatible) / 出力形式（hashcat/secretsdump 互換）:
```
Administrator:500:aad3b435b51404eeaad3b435b51404ee:8846f7eaee8fb117ad06bdd830b7586c:::
```

### Forensic Analysis / フォレンジック分析

```
poneglyph forensics --ntds ntds.dit --acls
```

Runs tombstone recovery and 14 anomaly detection rules. `--acls` enables DCSync ACL analysis.

削除オブジェクト復元と 14 個の異常検知ルールを実行します。`--acls` で DCSync ACL 分析を有効化します。

### User Listing / ユーザー一覧

```
poneglyph users --ntds ntds.dit --format table
```

### Database Info / データベース情報

```
poneglyph info --ntds ntds.dit
```

### Live Collection (on Domain Controller) / ライブ収集（DC 上で実行）

```
poneglyph collect --zip
```

Uses Volume Shadow Copy to safely acquire NTDS.dit and SYSTEM hive.

ボリュームシャドウコピーを使用して NTDS.dit と SYSTEM ハイブを安全に取得します。

## CLI Reference / CLI リファレンス

| Subcommand / サブコマンド | Description / 説明 | Required Flags / 必須フラグ |
|------------|-------------|----------------|
| `info` | Display database tables and record counts / DB テーブルとレコード数の表示 | `--ntds` |
| `users` | Extract user accounts / ユーザーアカウント抽出 | `--ntds` |
| `hashes` | Extract password hashes / パスワードハッシュ抽出 | `--ntds`, `--system` |
| `dump` | Full extraction with all output formats / 全形式での完全抽出 | `--ntds` |
| `forensics` | Tombstone recovery + anomaly detection / 削除復元 + 異常検知 | `--ntds` |
| `collect` | Acquire NTDS.dit from live DC / 稼働中DCからNTDS.dit取得 | (none / なし) |

### `dump` Options / `dump` オプション

| Flag / フラグ | Description / 説明 |
|------|-------------|
| `--ntds <PATH>` | Path to NTDS.dit file / NTDS.dit ファイルのパス |
| `--system <PATH>` | Path to SYSTEM registry hive (for hash extraction) / SYSTEM レジストリハイブのパス（ハッシュ抽出用） |
| `--output-dir <DIR>` | Output directory (default: `poneglyph-output`) / 出力ディレクトリ（デフォルト: `poneglyph-output`） |
| `--domain <NAME>` | Domain name (auto-detected if omitted) / ドメイン名（省略時は自動検出） |
| `--bloodhound` | Generate BloodHound CE JSON / BloodHound CE JSON を生成 |
| `--hashcat` | Generate hashcat-format hashes / hashcat 形式ハッシュを生成 |
| `--graph` | Generate D3.js graph JSON / D3.js グラフ JSON を生成 |
| `--timeline` | Generate forensic timeline CSV / フォレンジックタイムライン CSV を生成 |
| `--all` | Generate all output formats / 全出力形式を生成 |

## Output Formats / 出力形式

### BloodHound JSON (`bloodhound/`)

BloodHound CE v5 compatible. Generates `00-users.json`, `00-groups.json`, `00-computers.json`, `00-domains.json`.

BloodHound CE v5 互換。`00-users.json`、`00-groups.json`、`00-computers.json`、`00-domains.json` を生成します。

### Graph JSON (`graph.json`)

D3.js force-directed graph with nodes (users, computers, groups, DCs) and links (MemberOf, TrustBy).

D3.js フォースグラフ用 JSON。ノード（ユーザー、コンピューター、グループ、DC）とリンク（MemberOf、TrustBy）を含みます。

### Timeline CSV (`timeline.csv`)

Plaso-compatible CSV with columns: `datetime`, `timestamp_desc`, `source`, `message`, `extra`.
Events include account creation, modification, password changes, logon timestamps, and lockouts.

plaso 互換の CSV。列: `datetime`、`timestamp_desc`、`source`、`message`、`extra`。
アカウント作成・変更、パスワード変更、ログオン、ロックアウトなどのイベントを含みます。

### Hashcat (`hashes.txt`)

secretsdump-compatible format: `username:RID:LM_HASH:NT_HASH:::`

secretsdump 互換形式: `username:RID:LM_HASH:NT_HASH:::`

### Forensics Report / フォレンジックレポート (`forensics-report.json`)

JSON report containing metadata, deleted objects (tombstones), anomaly findings, and severity summary.

メタデータ、削除オブジェクト（トゥームストーン）、異常検知結果、重要度サマリーを含む JSON レポート。

## Anomaly Detection Rules / 異常検知ルール

| ID | Rule / ルール | Severity / 重要度 | MITRE |
|----|------|----------|-------|
| ANOM-001 | AS-REP Roastable Accounts / AS-REP Roast 可能なアカウント | High | T1558.004 |
| ANOM-002 | Password Not Required / パスワード不要設定 | High | T1078 |
| ANOM-003 | Non-Expiring Password on Privileged Accounts / 特権アカウントの無期限パスワード | Medium | T1078.002 |
| ANOM-004 | Stale Enabled Accounts (>90 days) / 長期未使用アカウント（90日超） | Low | T1078 |
| ANOM-005 | Never-Logged-In Enabled Accounts / 未ログインの有効アカウント | Low | - |
| ANOM-006 | Unconstrained Delegation / 制約なし委任 | Critical | T1550.003 |
| ANOM-007 | Constrained Delegation with Protocol Transition / プロトコル遷移付き制約付き委任 | High | T1550.003 |
| ANOM-008 | adminCount=1 Accounts / adminCount=1 のアカウント | Info | - |
| ANOM-009 | High Bad Password Count (>=5) / 不正パスワード試行多数（5回以上） | Medium | T1110 |
| ANOM-010 | Recently Created Accounts (<30 days) / 最近作成されたアカウント（30日以内） | Info | T1136.002 |
| ANOM-011 | DCSync-Capable Non-Admin (ACL) / 非管理者の DCSync 権限保持 | Critical | T1003.006 |
| ANOM-012 | SID History Present / SID 履歴の存在 | High | T1134.005 |
| ANOM-013 | Shadow Credentials (KeyCredentialLink) / シャドウ資格情報 | High | T1098.004 |
| ANOM-014 | Kerberoastable User Accounts (SPN) / Kerberoast 可能なユーザーアカウント | High | T1558.003 |

## Architecture / アーキテクチャ

```
src/
├── main.rs              # CLI entry point (6 subcommands) / CLIエントリポイント
├── lib.rs               # Library exports / ライブラリエクスポート
├── ese.rs               # ESE database interface / ESEデータベースインターフェース
├── schema.rs            # ATT code -> LDAP attribute mapping / ATTコード→LDAP属性マッピング
├── bootkey.rs           # BootKey extraction from SYSTEM hive / SYSTEMハイブからBootKey抽出
├── crypto.rs            # PEK + hash decryption (DES/AES) / PEK + ハッシュ復号
├── collect.rs           # Live DC collection (VSS) / 稼働中DCからの収集
├── links.rs             # Group membership resolution / グループメンバーシップ解決
├── acl.rs               # Security descriptor / ACE parsing / セキュリティ記述子/ACE解析
├── objects/
│   ├── mod.rs           # Core extraction, SID parsing / コア抽出、SID解析
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
    ├── mod.rs           # Report orchestration / レポート統合
    ├── tombstone.rs     # Deleted object recovery / 削除オブジェクト復元
    └── anomaly.rs       # 14 detection rules / 14検知ルール
```

## Building from Source / ソースからのビルド

### Requirements / 必要環境

- Rust (`stable-x86_64-pc-windows-gnu`)
- MSYS2 with `mingw-w64-x86_64-gcc` and `mingw-w64-x86_64-binutils`

### Build / ビルド

```bash
# Set environment / 環境変数の設定
export PATH="/c/msys64/mingw64/bin:$PATH"
export CFLAGS="-DHAVE_WINDOWS_H=1 -DWIN32_LEAN_AND_MEAN=1 -Wno-error=implicit-function-declaration -Wno-error=int-conversion"

cargo build --release
```

The binary will be at `target/release/poneglyph.exe`.

バイナリは `target/release/poneglyph.exe` に生成されます。

## Troubleshooting / トラブルシューティング

### Japanese characters in file paths / ファイルパスの日本語文字

Poneglyph uses libesedb (a C library) internally, which calls `fopen()` to open files. On Windows, `fopen()` interprets paths using the ANSI codepage (CP932/Shift-JIS for Japanese), but Rust passes paths as UTF-8. This encoding mismatch causes file open failures when the path contains non-ASCII characters such as Japanese.

Poneglyph は内部で libesedb（Cライブラリ）を使用しており、ファイルオープンに `fopen()` を使います。Windows の `fopen()` は ANSI コードページ（日本語環境では CP932/Shift-JIS）でパスを解釈しますが、Rust は UTF-8 でパスを渡します。このエンコーディングの不一致により、日本語などの非ASCII文字を含むパスでファイルを開けません。

**Solution / 解決策: Enable Windows UTF-8 mode / Windows UTF-8 モードの有効化**

1. Open **Settings** → **Time & Language** → **Language & Region** → **Administrative language settings**

   **設定** → **時刻と言語** → **言語と地域** → **管理用の言語の設定**

2. Click **Change system locale**

   **システム ロケールの変更** をクリック

3. Check **"Beta: Use Unicode UTF-8 for worldwide language support"**

   **「ベータ: ワールドワイド言語サポートで Unicode UTF-8 を使用」** にチェック

4. Restart Windows / Windows を再起動

This makes `fopen()` accept UTF-8 paths, allowing Poneglyph to open files in paths containing Japanese or other non-ASCII characters.

これにより `fopen()` が UTF-8 パスを受け付けるようになり、日本語などの非ASCII文字を含むパスでもファイルを開けるようになります。

**Alternative workaround / 代替手段**: Copy the NTDS.dit and SYSTEM files to an ASCII-only path (e.g., `C:\dev\`) and run from PowerShell.

NTDS.dit と SYSTEM ファイルを ASCII のみのパス（例: `C:\dev\`）にコピーし、PowerShell から実行してください。

## License / ライセンス

MIT
