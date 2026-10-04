<!-- docs-status: historical -->

# 診断と内部構造の実装前の記述

以下は、現在は実装済みの機能について、実装前に定めた範囲と移行の順序です。
現在の診断は[診断の索引](../diagnosis/README.md)に、内部構造は[内部構造の索引](../architecture/README.md)にあります。

## architecture/model.md

6 節と 7 節が定める外部から見た挙動(送信元制限、レート制限、2 つのデータプレーン)は変えない。
対象は内部の package・型・interface・DB スキーマで、互換は求めない。
v1.0 の前に適用する再設計である。

## resource/admission.md

Phase 6 では、`internal/flowcap` を `internal/resource` に改め、Resource Guard(7a.5 節)を Admission Policy から型の上でも切り離す。
userspace のルールごとの隔離は、共有プールと隔離予約の方式に置き換える。
隔離予約は、その後にルールの登録ごとの最低分と予備の形に改めた(後述の「共有プール、最低分と予備」と移行の手順 6)。
kernel 側は conntrack の表と set の大きさを観測して提示するだけで、新しい強制は加えない。
Phase 6 は、Phase 5(7a.9 節)の移行の手順 3 で送信元ごとの同時フロー数を評価器へ移した後のコードから始める。

## diagnosis/server-observations.md

#### 両側の診断と、この版の範囲

診断は両側に置く。
server 側の `server doctor` は、server とエージェントが対応できている間、端から端までの答えを出す。
自宅側の `agent doctor` は、server と対応できない場合でも、その節点だけを手元で診断する。
`agent doctor` が server 無しで動く必要があるのは、まさに server と対応できない場合が診断を最も必要とする場面だからである。
Web UI からも同じ診断を呼び出せるようにするが、順序は `agent doctor`、Web UI、`--report`、遠隔の診断の順とする。
Web UI の診断の画面の設計は 10.2d 節にある。

この版で実装するのは `wgft server doctor [rule]` だけである。
`agent doctor`、Web UI の操作、`--report` は含めない。

`agent doctor` がまだ無いので、出力は存在しないコマンドを案内しない。
自宅側を見る必要がある所見は、今あるもの、つまりエージェントのホストでのログの読み取り (`systemctl status wgft-agent`、`journalctl -u wgft-agent`、コンテナなら `docker logs`)、名前の解決の確認、server 側の `wgft agent ls` による公開鍵の突き合わせを案内する。
`agent doctor` ができた時点で案内し直す。
実装には該当箇所に印を置いてある。

遠隔の診断は、server がエージェントに診断を要求し、その結果を併せて示す形である。
server からエージェントへの新しいメッセージが要るので `proto` と v1.0 の保証 (7a.6 節の機能の交渉) に触れる。
この版では実装しない。
遠隔の診断が加えるのは、エージェント自身の環境である。
エージェントの OS、権限、インタフェースの状態、名前解決の詳細がそれに当たる。
将来これを加えるときは、機能の交渉の上に載せ、出力の形を変えずに検査を追加する形にする。
必要かどうかの判断は `agent doctor` ができてからにする。
手元で見えるものが分かって初めて、server 側から要求すべき情報が決まるためである。

この版は、既に届いている観測だけから組み立てる。
ハートビートがエージェントのルールごとの状態と理由、トンネルの状態、最終ハンドシェイクの古さを運び、`conncheck` (10.1 節) が内側の経路を実際に試す。


## diagnosis/agent-evidence.md

この節は骨格を固定し、細部は実装のときに確定する (2026-09-23、所有者の決定)。
固定するのは、2 つのコマンドの境目、証拠の 2 つの出どころ、検査の一覧とその `id`、群の分け方、総合判定を動かす検査、終了コード 2 に倒す条件、状態の語とその意味、終了コードの意味、制御ソケットの拡張の形、そして実装が持つべき表のテストの要求である。
機械が読むサーフェスについては、`checks[]` が `id`・`status`・`reason` の 3 つのフィールドを持つことと、その値が開いた集合であることまでを固定する。
個々の理由の符号と `--json` の最上位の形は、`--json` を実装したときに確定し、後述の「機械向けの出力」の項に書いた (2026-09-23)。
境界をここに引いたのは、規則どうしの組み合わせを網羅して確かめるのが実装とそのテストの役目であり、値の一覧まで固定すると実装が現実に合わせて 1 つ直すだけで設計の変更になるためである。
v1.0 の後は機械が読むサーフェスの重みが増す (7a.11 節)。

## diagnosis/agent-evidence.md

場面ごとの結果は、この節が既に定める規則からテストが導く。
固定するのは場面を入力として持つという要求であり、結果を新しく定めることではない。
実装のときに確定したことと、そこで分かった事実は、改訂の記録に書く。
この節の骨格を変える必要が出た場合は、設計文書を先に直す順序に従う。

## diagnosis/agent-scope.md

実装のときは、`cmd/wgft/doctor.go` にある 4 か所の `TODO(agent-doctor)` の案内を `wgft agent doctor` に向け直す。
10.2a 節が「`agent doctor` ができた時点で案内し直す」と定めている箇所である。

## policy.md

Phase 5 では、`internal/policy` の IR を 2 つの対象へコンパイルする。
kernel の対象は nftables の行の列、userspace の対象は Go の評価器である。
両者が同じ判定をすることは、ホストの単体テストで動く共有 fixture で確かめる。

## policy.md

`policy.Policy` は、ルールごとの `RulePolicy`(ルール ID、プロトコル、`source_allow`、`source_deny`、3 つのレート)と、プロトコルごとの `PerSourceFlowCaps` を持つ。
この形は Phase 1 のままで、Phase 5 では次を IR に加える。

## policy.md

Phase 5 の前の userspace の実装は、次の 3 点で IR の意味と食い違っていた。
最初の 2 つは移行の手順 3、3 つ目は手順 4 で直した。

- `packet_rate` の位置:UDP の中継は、セッションの有無を見る前に、すべてのデータグラムを `packet_rate` で判定している(`relay/udp.go`)。
  deny の送信元のデータグラムも `packet` のトークンを使うため、deny の送信元からのフラッドが、正規の成立済みセッションのデータグラムを落としうる。
  nftables では deny の行が先に落とすので、この問題は起きない
- 送信元ごとの同時フロー数の上限の位置:今は `AdmitFlow` の後に `flowcap.Counter.Acquire` で判定しており、`new_flow_rate` より後になる。
  上限で拒んだフローも `new_flow_rate` のトークンを使い、drop カウンタにも数えない
- `Relay` の受け付け:userspace モードの `proxyrelay` は deny と allow だけを判定し、レートを評価していなかった。
  kernel モードも `src_flow` の行しか付けていなかったので、`Relay` のルールのレートは両モードで効いていなかった

## resource/admission.md

`flowcap.Limits` は、次の 2 つの型に分ける。

## resource/admission.md

`flowcap.Counter` は `resource.Pool` に置き換える。
Phase 5 の後の `Counter` はプロセス全体の数だけを数えており、ルールごとの数は `relay.Manager` と `proxyrelay` がそれぞれ listener の数から別に数えている。
`Pool` は両方を 1 つの排他の中で数える。
上限で拒んだことのログを間引く `flowcap.LogGate` は、宛先への dial の失敗のログにも使うので `internal/resource` には置かず、小さな package `internal/lograte` へ移す。

## web-doctor.md

Web UI の診断の画面は、`server doctor` (10.2a 節) と同じ証拠から同じ判定を組み立て、運用者がブラウザから読める形で出す。
10.2a 節が定めた順序 `agent doctor`、Web UI、`--report`、遠隔の診断のうちの 2 番目に当たる。
実装してある。
この節が定めるのは骨格であり、実装のときに確定した細部と、実装の時点で確かめた事実は、改訂の記録に分けて書く。

## web-doctor.md

この節を書く前に、使い捨ての骨組みをラボで動かして事実を取った。
以下の記述はその事実に基づく。
骨組みそのものはリポジトリに残していない。
取った事実は改訂の記録 2026-09-23 にある。

## web-doctor.md

この節は骨格を固定し、細部は実装のときに確定する (2026-09-23、所有者の決定)。
固定するのは、診断のロジックの置き場所、ラベルと群の名前の言語、そして疎通の確認を呼ぶ契機である。

## web-doctor.md

実装のときに確定するのは、画面の細かい構成、表示の文言、どの検査をどう並べるか、姉妹 package の名前、証拠の型の所有の場所、Web UI がこの画面のために持つ節点の形である。

## compatibility/surfaces.md

**リリース成果物とコンテナイメージ。**
保つものは、バイナリ名の形式 `wgft-{os}-{arch}`(Windows だけ `.exe` が付く)と、対応する `.sha256`・`.spdx.json` が付くこと、コンテナイメージ名 `ghcr.io/rahanahu/wgft-server`・`ghcr.io/rahanahu/wgft-agent` とその版タグ(`vX.Y.Z`)と、リリースのバイナリの `wgft version` の 1 行目がそのリリースのタグ(`vX.Y.Z`)そのものであることである。
docs/manual/setup.md の手順は、この行で systemd の unit のファイルをバイナリと同じタグから取得する。
保たないものは、`:latest` タグの中身(常に最新の版を指すので固定した参照ではない)と、対応する OS・アーキテクチャの組み合わせ(11a 節が明記するとおり、実機で検証できた組み合わせだけを増減する)である。
この項は配布物の名前と付随物の形の約束であり、本節冒頭の暫定の扱いはこの項に影響しない。
Windows と macOS の agent を暫定とすること自体は、現在配っているバイナリの配布を取りやめる決定ではない。
配布する成果物については、この項の名前と付随物の形式を保つ。

## resource/integration.md

agent の拒否の数は、Phase 6 では agent のログにだけ出す。
ハートビートには加えない。
ハートビートに加えるには wire protocol に加算的なフィールドと capability を加える必要があり(7a.6 節)、版と capability の規則の検証を伴う変更は Phase 6 の範囲より大きいためである。
