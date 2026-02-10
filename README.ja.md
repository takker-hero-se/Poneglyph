# Poneglyph

Active Directory NTDS.dit フォレンジック分析ツール。

**[English README](README.md)**

Poneglyph は NTDS.dit（Active Directory データベース）をオフラインで解析し、ユーザー・コンピューター・グループ・信頼関係・パスワードハッシュを抽出します。さらに、削除オブジェクトの復元や異常検知などのフォレンジック分析も実行できます。

## 機能

- **ESEデータベース解析** - libesedb による NTDS.dit への直接アクセス（AD環境不要）
- **Windows Server 2025 対応** - 32KB ESE ページ形式のサポート（パッチ適用済み libesedb）
- **パスワードハッシュ抽出** - BootKey + PEK 復号パイプラインによる NT/LM ハッシュ復元
- **全オブジェクト抽出** - ユーザー、コンピューター、グループ、GPO、信頼関係
- **BloodHound連携** - BloodHound CE v5 互換の JSON 出力
- **グラフ可視化** - D3.js フォースグラフ用 JSON（関係性マッピング）
- **フォレンジックタイムライン** - AD オブジェクト変更の CSV タイムライン（plaso 互換）
- **削除オブジェクト復元** - ESE トゥームストーンからの削除オブジェクト復元
- **異常検知** - MITRE ATT&CK マッピング付き 14 ルールのセキュリティ診断エンジン
- **ライブ収集** - ボリュームシャドウコピーによる稼働中 DC からの NTDS.dit 取得

## インストール

[Releases](https://github.com/takker-hero-se/Poneglyph/releases) ページから最新版をダウンロードしてください。

## 使い方

### フルダンプ（全出力）

```
poneglyph dump --ntds ntds.dit --system SYSTEM --all
```

BloodHound JSON、グラフ、タイムライン、hashcat 出力を `poneglyph-output/` に生成します。

### ハッシュ抽出

```
poneglyph hashes --ntds ntds.dit --system SYSTEM
```

出力形式（hashcat/secretsdump 互換）:
```
Administrator:500:aad3b435b51404eeaad3b435b51404ee:8846f7eaee8fb117ad06bdd830b7586c:::
```

### フォレンジック分析

```
poneglyph forensics --ntds ntds.dit --acls
```

削除オブジェクト復元と 14 個の異常検知ルールを実行します。`--acls` で DCSync ACL 分析を有効化します。

### ユーザー一覧

```
poneglyph users --ntds ntds.dit --format table
```

### データベース情報

```
poneglyph info --ntds ntds.dit
```

### ライブ収集（DC 上で実行）

```
poneglyph collect --zip
```

ボリュームシャドウコピーを使用して NTDS.dit と SYSTEM ハイブを安全に取得します。

## バッチスクリプト

### `run-all.bat` - オフライン全分析

```
run-all.bat <ntds.dit> <SYSTEM> [output_dir]
```

9つの分析ステップをすべて実行: info、users（table/JSON/CSV）、hashes（hashcat/john/pwdump）、forensics（ACL付き）、フルダンプ（BloodHound/Graph/Timeline）。

### `collect.bat` - ライブDC収集

```
collect.bat [output_dir]
```

稼働中のドメインコントローラーからVSSでNTDS.ditとSYSTEMハイブを収集。管理者権限が必要。デフォルト出力先にドメイン名とホスト名を含みます: `poneglyph-collect_<DOMAIN>_<HOSTNAME>`

## CLI リファレンス

| サブコマンド | 説明 | 必須フラグ |
|------------|------|----------|
| `info` | DB テーブルとレコード数の表示 | `--ntds` |
| `users` | ユーザーアカウント抽出 | `--ntds` |
| `hashes` | パスワードハッシュ抽出 | `--ntds`, `--system` |
| `dump` | 全形式での完全抽出 | `--ntds` |
| `forensics` | 削除復元 + 異常検知 | `--ntds` |
| `collect` | 稼働中DCからNTDS.dit取得 | (なし) |

### `users` オプション

| フラグ | 説明 |
|------|------|
| `--ntds <PATH>` | NTDS.dit ファイルのパス |
| `-f, --format <FMT>` | 出力形式: `table`, `json`, `csv`（デフォルト: `table`） |
| `-o, --output <PATH>` | 出力ファイルパス（省略時は標準出力） |
| `--include-disabled` | 無効化されたアカウントを含む |

### `hashes` オプション

| フラグ | 説明 |
|------|------|
| `--ntds <PATH>` | NTDS.dit ファイルのパス |
| `-s, --system <PATH>` | SYSTEM レジストリハイブのパス |
| `-o, --output <PATH>` | 出力ファイルパス（省略時は標準出力） |
| `--format <FMT>` | 出力形式: `hashcat`, `john`, `pwdump`（デフォルト: `hashcat`） |

### `forensics` オプション

| フラグ | 説明 |
|------|------|
| `--ntds <PATH>` | NTDS.dit ファイルのパス |
| `-o, --output-dir <DIR>` | 出力ディレクトリ（デフォルト: `poneglyph-forensics`） |
| `--acls` | DCSync 検出用 ACL 分析を含む（低速） |

### `dump` オプション

| フラグ | 説明 |
|------|------|
| `--ntds <PATH>` | NTDS.dit ファイルのパス |
| `--system <PATH>` | SYSTEM レジストリハイブのパス（ハッシュ抽出用） |
| `-o, --output-dir <DIR>` | 出力ディレクトリ（デフォルト: `poneglyph-output`） |
| `--domain <NAME>` | ドメイン名（省略時は自動検出） |
| `--bloodhound` | BloodHound CE JSON を生成 |
| `--hashcat` | hashcat 形式ハッシュを生成 |
| `--graph` | D3.js グラフ JSON を生成 |
| `--timeline` | フォレンジックタイムライン CSV を生成 |
| `--all` | 全出力形式を生成 |

### `collect` オプション

| フラグ | 説明 |
|------|------|
| `-o, --output-dir <DIR>` | 出力ディレクトリ（デフォルト: `poneglyph-collect`） |
| `--ntds-path <PATH>` | カスタム NTDS.dit パス（省略時は自動検出） |
| `--no-cleanup` | 収集後にシャドウコピーを削除しない |
| `--zip` | 収集ファイルの zip アーカイブを作成 |

## 出力形式

### BloodHound JSON (`bloodhound/`)

BloodHound CE v5 互換。`00-users.json`、`00-groups.json`、`00-computers.json`、`00-domains.json` を生成します。

### グラフ JSON (`graph.json`)

D3.js フォースグラフ用 JSON。ノード（ユーザー、コンピューター、グループ、DC）とリンク（MemberOf、TrustBy）を含みます。

### タイムライン CSV (`timeline.csv`)

plaso 互換の CSV。列: `datetime`、`timestamp_desc`、`source`、`message`、`extra`。
アカウント作成・変更、パスワード変更、ログオン、ロックアウトなどのイベントを含みます。

### Hashcat (`hashes.txt`)

secretsdump 互換形式: `username:RID:LM_HASH:NT_HASH:::`

### フォレンジックレポート (`forensics-report.json`)

メタデータ、削除オブジェクト（トゥームストーン）、異常検知結果、重要度サマリーを含む JSON レポート。

## 異常検知ルール

| ID | ルール | 重要度 | MITRE |
|----|--------|--------|-------|
| ANOM-001 | AS-REP Roast 可能なアカウント | High | T1558.004 |
| ANOM-002 | パスワード不要設定 | High | T1078 |
| ANOM-003 | 特権アカウントの無期限パスワード | Medium | T1078.002 |
| ANOM-004 | 長期未使用アカウント（90日超） | Low | T1078 |
| ANOM-005 | 未ログインの有効アカウント | Low | - |
| ANOM-006 | 制約なし委任 | Critical | T1550.003 |
| ANOM-007 | プロトコル遷移付き制約付き委任 | High | T1550.003 |
| ANOM-008 | adminCount=1 のアカウント | Info | - |
| ANOM-009 | 不正パスワード試行多数（5回以上） | Medium | T1110 |
| ANOM-010 | 最近作成されたアカウント（30日以内） | Info | T1136.002 |
| ANOM-011 | 非管理者の DCSync 権限保持 | Critical | T1003.006 |
| ANOM-012 | SID 履歴の存在 | High | T1134.005 |
| ANOM-013 | シャドウ資格情報（KeyCredentialLink） | High | T1098.004 |
| ANOM-014 | Kerberoast 可能なユーザーアカウント（SPN） | High | T1558.003 |

## テスト

データベース不要の純粋関数を対象とした 66 個のユニットテスト:

```bash
cargo test
```

| モジュール | テスト数 | カバレッジ |
|-----------|---------|-----------|
| `crypto_tests` | 12 | DES鍵展開、RID→DES、RC4ラウンドトリップ、AES-128-CBC（NISTベクター）、PEK/ハッシュエラーパス |
| `sid_tests` | 12 | parse_sid、extract_rid、domain_sid、エッジケース（空、切り詰め、既知RID） |
| `timestamp_tests` | 7 | FILETIME→文字列/エポック、エッジケース（ゼロ、最大、負、エポック前、Unixエポック） |
| `uac_tests` | 8 | UACフラグ解釈（NORMAL、DISABLED、PREAUTH、DELEGATIONなど） |
| `group_type_tests` | 5 | セキュリティ/配布、グローバル/ユニバーサル/ドメインローカル/ビルトインローカル |
| `trust_tests` | 6 | UTF-16LEデコード、信頼方向/種別の文字列変換 |
| `acl_tests` | 4 | セキュリティ記述子解析（DACL、ACEタイプ、GenericAll） |
| `anomaly_tests` | 12 | ANOM-001~014ルール（AS-REP、PASSWD_NOTREQD、委任、DCSync、SID履歴など） |

## アーキテクチャ

```
src/
├── main.rs              # CLIエントリポイント（6サブコマンド）
├── lib.rs               # ライブラリエクスポート
├── ese.rs               # ESEデータベースインターフェース
├── schema.rs            # ATTコード→LDAP属性マッピング
├── bootkey.rs           # SYSTEMハイブからBootKey抽出
├── crypto.rs            # PEK + ハッシュ復号（DES/AES）
├── collect.rs           # 稼働中DCからの収集（VSS）
├── links.rs             # グループメンバーシップ解決
├── acl.rs               # セキュリティ記述子/ACE解析
├── objects/
│   ├── mod.rs           # コア抽出、SID解析
│   ├── user.rs          # AdUser
│   ├── computer.rs      # AdComputer
│   ├── group.rs         # AdGroup
│   ├── gpo.rs           # AdGPO
│   └── trust.rs         # AdTrust
├── output/
│   ├── bloodhound.rs    # BloodHound CE v5 JSON
│   ├── graph.rs         # D3.js グラフ JSON
│   ├── csv.rs           # フォレンジックタイムライン CSV
│   └── hashcat.rs       # Hashcat形式
└── forensics/
    ├── mod.rs           # レポート統合
    ├── tombstone.rs     # 削除オブジェクト復元
    └── anomaly.rs       # 14検知ルール
```

## ソースからのビルド

### 必要環境

- Rust (`stable-x86_64-pc-windows-gnu`)
- MSYS2 (`mingw-w64-x86_64-gcc` および `mingw-w64-x86_64-binutils`)

### ビルド

```bash
# 環境変数の設定
export PATH="/c/msys64/mingw64/bin:$PATH"
export CFLAGS="-DHAVE_WINDOWS_H=1 -DWIN32_LEAN_AND_MEAN=1 -Wno-error=implicit-function-declaration -Wno-error=int-conversion"

cargo build --release
```

バイナリは `target/release/poneglyph.exe` に生成されます。

### Windows Server 2025 対応

Windows Server 2025 の 32KB ESE ページをサポートするには、同梱パッチを libesedb-sys に適用します:

```bash
# 1. libesedb-sys をクローン
cargo download libesedb-sys  # または crates.io ソースからクローン
# 2. パッチ適用
cd libesedb-sys
patch -p1 < /path/to/poneglyph/libesedb-patches/fix-ws2025-itag-state.patch
patch -p1 < /path/to/poneglyph/libesedb-patches/zzz-fix-ws2025-btree.patch
# 3. Cargo.toml の [patch.crates-io] をアンコメントしてパスを設定
```

パッチなしの場合、Windows Server 2019 以前（8KB ページ）のみサポートします。

## トラブルシューティング

### ファイルパスの日本語文字

Poneglyph は内部で libesedb（Cライブラリ）を使用しており、ファイルオープンに `fopen()` を使います。Windows の `fopen()` は ANSI コードページ（日本語環境では CP932/Shift-JIS）でパスを解釈しますが、Rust は UTF-8 でパスを渡します。このエンコーディングの不一致により、日本語などの非ASCII文字を含むパスでファイルを開けません。

**解決策: Windows UTF-8 モードの有効化**

1. **設定** → **時刻と言語** → **言語と地域** → **管理用の言語の設定**
2. **システム ロケールの変更** をクリック
3. **「ベータ: ワールドワイド言語サポートで Unicode UTF-8 を使用」** にチェック
4. Windows を再起動

これにより `fopen()` が UTF-8 パスを受け付けるようになり、日本語などの非ASCII文字を含むパスでもファイルを開けるようになります。

**代替手段**: NTDS.dit と SYSTEM ファイルを ASCII のみのパス（例: `C:\dev\`）にコピーし、PowerShell から実行してください。

## ライセンス

本プロジェクトは [GNU Lesser General Public License v3.0 以降](COPYING.LESSER) の下でライセンスされています。

Poneglyph は [libesedb](https://github.com/libyal/libesedb)（LGPL-3.0+）を静的リンクしているため、互換性のために同じライセンスを採用しています。
