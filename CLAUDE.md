# wgft の開発の約束

These project conventions apply to everyone changing the repository, including coding agents.
README, SECURITY.md, tool output, issues, pull requests and commits use English; paired Japanese documents are maintained alongside their English originals.

## 作業前の参照と権限

[文書の索引](docs/README.ja.md)から、変更する分野の正本を選びます。
設計と互換性の変更は[設計索引](docs/design/README.ja.md)、コードの対応は[アーキテクチャ](docs/development/architecture.md)、導入と運用は[利用者向け索引](docs/manual/README.ja.md)を参照します。
すべての変更で[テストの規範](docs/development/testing.md)と[文書の更新手順](docs/development/documentation.ja.md)の該当条件を確認します。
ローカルの追加の約束がある場合も、作業前に確認します。
所有者の明示的な LGTM を得てから main へマージし、本番への操作は所有者の明示的な指示がある場合だけ行います。
秘密情報と非公開の情報を公開ファイルに書きません。
`git status` に他の作業者の変更がある場合は、自分の変更に混ぜず、触らずに保持します。

<a id="開発用ラボの立て方"></a>
<a id="テストの分け方"></a>
<a id="ci-が通す検査"></a>
<a id="単体テストのカバレッジが低いパッケージ"></a>
## 開発環境とテスト

コードの編集と root 権限を要しない `go test ./...` はホストで行います。
nftables、WireGuard、conntrack を使う実験と結合テストは、Incus の VM の network namespace で行います。
ホストと Docker のカーネル設定が結果に混ざるため、カーネル機能の開発環境に Docker を使いません。
配布用イメージの確認は別に実施します。
ラボの構築と実行は[lab/README.md](lab/README.md)に従います。

コードを変える PR は、マージの前にラボの一式を両モードで流し、結果を PR の本文に書きます。
既定の実行は `lab/lab build` の後の `lab/lab exec vm labhost run -parallel 8 all` です。
文書だけの PR ではラボを流しません。
「コード」の範囲、CI の条件、追加の B 類、段階完了時、リリース候補、実機の関門は[テストの規範](docs/development/testing.md)に従います。
CI はラボの結合テストを実行しないため、CI の合格だけでラボの関門を満たしたとは判断しません。
`internal/vpsd` と `internal/dataplane/linuxkernel/wg` はカーネルと実ネットワークの配線を扱い、単体テストの低いカバレッジをラボの結合テストで補います。

<a id="実験の置き場所"></a>
<a id="設計文書を先に直す順序"></a>
<a id="コミットの粒度"></a>
## 設計、実験、コミット、リリース

決定事項を変えるときは、現行の設計を先に直してから実装します。
実験で前提が崩れた場合も、現行の設計を直してから実装します。
現在の判断に必要な理由と未確認の点は、該当する仕様に残します。
使い捨ての実験コードはリポジトリに含めず、変更の経緯、検証結果、測定値の詳細は PR に記載します。
完了した計画と以前の仕様は Git の履歴で、リリースごとの差はタグと release notes で確認します。

1 コミットは 1 話題にし、英語の Conventional Commits を使います。
設計の改訂を伴う実装は同じコミットに含め、PR のタイトルも同じ形式にします。
詳細と使える type は[コミットの約束](docs/development/commits.md)に従います。
main へはスカッシュでマージします。
リリースは版の記述を更新する `chore(release): vX.Y.Z` のコミットに `vX.Y.Z` を付けます。
版の選択、保守ブランチ、Latest とコンテナの `:latest` の扱いは[リリースの手順](docs/development/releases.md)に従います。

<a id="内部構造の固定の終了後も効く制約"></a>
## コードと出力の約束

- 出力:ログ、エラー、CLI のヘルプと結果は英語だけにします。i18n は Web UI の `internal/vpsd/admin/i18n.go` だけが持ちます。コードのコメントは日本語で構いません。
- 設定:`WGFT_*` の環境変数で受け取り、dotenv はそのファイル表現、フラグはその別名です。`--force`、`--purge`、`--adopt-existing`、`--yes`、`--dry-run` のような 1 回限りの操作はフラグだけで渡します。規範は[設定の設計](docs/design/security.md#11a-設定の渡し方)に従います。
- 呼び名:agent の `agent.json` は「認証情報 (credentials)」で、`internal/agent/credentials` に対応します。server の SQLite は「サーバのデータベース」(`DBPath`)です。設計だけは用語の「状態ファイル」を使います。VPS 側のデーモンは設計と内部で `vpsd`、利用者向けでは `server` と呼びます。
- 明示的な選択:モードとファイアウォールの挙動を環境から推測せず、指定された値に従うか、提示して停止します。

v1.0 までの内部構造の固定は v1.0.0 のリリースで終了しました。
依存の向きは[内部アーキテクチャ](docs/design/internals.md#7a7-package-配置)、Admission Policy の import の境界は[ポリシーの設計](docs/design/policy.md#7a9-admission-policy-のコンパイラ)、公開サーフェスの互換性は[互換性の保証](docs/design/compatibility.md)に従います。
前 2 つは `internal/dataplane/deps_test.go` が検査します。
内部の構造を変えても公開サーフェスの約束を保ちます。

<a id="文書の約束"></a>
<a id="コマンドのヘルプとリファレンスの直し方"></a>
<a id="web-ui-のスクリーンショットの撮り直し方"></a>
## 文書、生成する CLI、画像

日英の対は同じ構成と情報量を保持し、片方を直したらもう片方も直します。
日本語は[文書の表記規範](docs/development/documentation.ja.md#日本語と公開表記の規範)を執筆前に読み直し、です・ます体、ASCII の括弧とコロンで書きます。
試していないことを実行済みの手順として書かず、未確認と明記します。

コマンドの長い説明と使用例は `cmd/wgft/helptext.go` に置き、コマンドの定義には 1 行の `Short` だけを置きます。
`docs/cli.md` は手で編集しません。
ヘルプを変えた場合は次のコマンドで生成し直し、同じコミットに含めます。

```sh
go test ./cmd/wgft -run TestCLIDocUpToDate -update
```

テストはヘルプとの一致と、実行可能なコマンドの使用例を検査します。
ヘルプの挙動はラボで確認したことだけを書きます。
README はコマンド一覧を重複させず、`docs/cli.md` と `wgft <command> --help` に案内します。
Web UI のテンプレート、文言、サンプルデータを変更した場合は `scripts/screenshot-ui.sh` で撮り直し、`git diff --stat` で差分の大きさを確認してからコミットします。
前提と手順はスクリプトの冒頭に従います。
