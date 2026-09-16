# wgft の開発の約束

This file holds the project conventions, in Japanese, for anyone changing the code, including Claude Code, which reads it automatically. The README, SECURITY.md and all tool output are in English, and issues and pull requests in English are welcome.

wgft の VPS 側はカーネルの nftables、WireGuard、conntrack を直接操作します。そのため、この操作を確かめる開発環境と、変更の進め方に関する約束があります。

## 開発用ラボの立て方

コードの編集と `go test` はホストで行います。nftables、wg0、conntrack が絡む実験と、端から端までの結合テストは、Incus の VM `wgft-lab` の中の network namespace で行います。ホストや Docker でカーネル機能を試すと、ホスト自身のカーネルバージョンや、Docker が有効にする `br_netfilter` 経由のルールと conntrack が結果に混ざるため、VM に切り分けます。

ラボの起動は `lab/lab up` の 1 コマンドで済みます。Incus が入っていて自分が `incus-admin` グループに属していれば、VM の作成、パッケージの導入、`client - vps - homerouter(NAT) - home` の 4 つの network namespace によるトポロジの構築までがこの 1 コマンドに含まれます。ビルドは `lab/lab build` がホスト上の Go コードを VM の `/usr/local/bin` にインストールし、`lab/lab exec <ns> <コマンド>` で各 namespace 内のプロセスを起動します。壊れた状態になったら `lab/lab reset` でスナップショットに戻せます。詳しい手順は [lab/README.md](lab/README.md) にあります。

## テストの分け方

`go test ./...` はホストで実行する単体テストで、ネットワーク namespace や root 権限を必要としません。`lab/` 配下の結合テストは Incus の VM を必要とするため、CI では実行されません。開発者は変更のたびにラボで結合テストを流し、CI には単体テストと後述の静的検査だけを任せます。

## 実験の置き場所

nftables や WireGuard の挙動を確かめる使い捨ての実験コードは、このリポジトリには含めていません。実験はラボで行い、結果と仕様への影響は [docs/design.md](docs/design.md) の「改訂の記録」に書きます。

## 設計文書を先に直す順序

決定事項を変えるときは、設計文書([docs/design.md](docs/design.md))を先に直してから実装します。ラボでの実験によって設計の前提が崩れた場合も、設計文書の改訂(改訂の記録への追記を含む)、実装、の順で進めます。

## コミットの粒度

設計文書の修正と実装は別々のコミットに分けます。1 つのコミットが設計の変更と実装の変更を両方含むと、後から変更の意図を追いにくくなるためです。コミットメッセージは日本語で書き、1 行目に変更の要点を書きます。

別のセッションや別の人が同時に作業していることがあります。`git status` で自分のものではない未コミットの変更を見つけたら、自分の変更と混ぜずに、触らないでおきます。

## CI が通す検査

`.github/workflows/ci.yml` は push と pull request のたびに次を検査します。`gofmt -l` によるフォーマットの確認、`go vet`、ビルドと `go test ./...`、`staticcheck` による静的解析、文字列リテラルへの日本語混入の検査([scripts/check-japanese](scripts/check-japanese/)。ツールの出力は英語だけを使う約束のためです)、公開対象ファイルの全角記号の検査([scripts/check-ascii-punct.sh](scripts/check-ascii-punct.sh))です。ラボの結合テストは Incus の VM を必要とするため、CI には含まれません。

## コードと出力の約束

- ツールの出力 (ログ、エラー、CLI のヘルプと結果) は英語だけで書きます。i18n は持ちません。Web UI だけが `internal/vpsd/admin/i18n.go` で日英を切り替えます。コードのコメントは日本語のままで構いません
- 設定は `WGFT_*` の環境変数で受け取ります。ファイルはその dotenv、フラグはその別名です。`--force`、`--purge`、`--adopt-existing`、`--yes`、`--dry-run` のような 1 回限りの操作はフラグでしか渡せません。規範は [docs/design.md](docs/design.md) の 11a 節です
- 利用者に見える呼び名とコードの識別子を対応させます。agent の `agent.json` は「認証情報 (credentials)」で、パッケージも `internal/agent/credentials` です。server の SQLite は「サーバのデータベース」(`DBPath`) です。設計文書だけは「状態ファイル」と呼びます (3 節の用語)。VPS 側のデーモンは設計文書と内部では `vpsd`、利用者に見える名前は `server` です
- 環境を見て挙動を推測しません。モードもファイアウォールも、明示された値に従うか、提示して止まります

## 文書の約束

- README は `README.md` (英語) と `README.ja.md` (日本語) の 2 本です。構成と情報量を同じにし、片方を直したらもう片方も直します。英語は英語として自然な書き方で構いません
- 日本語の文書は次の規範に従います。書く前に読み直します
  - https://raw.githubusercontent.com/megmogmog1965/claude-code-writing-style/main/plugins/writing-style/skills/style-review/references/rules.md
  - https://gist.githubusercontent.com/k16shikano/fd287c3133457c4fd8f5601d34aa817d/raw (日本語技術文書の文章規範)
  - https://gist.githubusercontent.com/k16shikano/eb2929f13ed19c97188393d297be8432/raw (「駄文の見分け方」の部分だけ使います。文書自身を語る文は削ります)
- 要点は次のとおりです。です・ます体で書きます。項目を主語にした定義文にします。体言止め、指示語 (ここ、そこ)、擬人化 (プログラムに「教える」)、翻訳調 (「前面に出して」) を使いません。くだけた語 (足す、消す、上げる) は書き言葉にします。見出しは内容を特定する名詞句にします。箇条書きのラベルは名詞句とコロンにします。未確認のことは「未確認」と書きます
- 括弧とコロンは ASCII にします。図は README なら Mermaid にします
- 試していないことを手順として書きません。ラボか実機で通したものだけを書きます

## Web UI のスクリーンショットの撮り直し方

README.md と README.ja.md が使う `docs/images/dashboard.png`(英語)と `dashboard.ja.png`(日本語)は、`scripts/screenshot-ui.sh` で撮影します。ラボの VM も実機の VPS も要りません。

このスクリプトは `tools/uidemo` をビルドして 127.0.0.1:8686 に Web UI を起動します。`tools/uidemo` は admin パッケージの公開 API(`New`、`Serve`)だけを使い、固定のサンプルデータ(エージェント 3 台、5 グループのルール、警告 1 件)を返す Backend です。サーバーが起動したら、Headless Firefox で `?lang=en` と `?lang=ja` の 2 枚を撮影し、`docs/images` へ上書きしてからサーバーを止めます。撮影には Firefox(`/usr/bin/firefox`)が要ります。

手順は `bash scripts/screenshot-ui.sh` の実行だけです。Web UI のテンプレートや文言を変えたとき、サンプルデータの形を変えたときは、このコマンドで撮り直し、`git diff --stat` で差分の大きさを確かめてからコミットします。サンプルデータの値そのものは `tools/uidemo/main.go` にあります。

## 単体テストのカバレッジが低いパッケージ

`internal/vpsd`、`internal/vpsd/wg`、`internal/agent` は、単体テストのカバレッジが意図的に低いパッケージです。これらはカーネルの nftables や WireGuard、実ネットワークとの配線を担う層であり、モックに置き換えると確かめられる範囲が狭くなります。この層は `lab/` の結合テストで、実機に近い環境での動作を確かめる方針を取っています。
