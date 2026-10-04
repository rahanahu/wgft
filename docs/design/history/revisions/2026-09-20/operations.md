<!-- docs-status: historical -->

# 2026-09-20: operations

- `server check` が自分の待ち受けポートも input firewall で検査する(2026-09-20):実機の Debian 13(input が `policy drop` で SSH の TCP 22 しか accept していない構成)で、`wgft server check` が「no problems」と表示しても、WireGuard の UDP 51820 と agent API の TCP 8443 が実際には host の input で塞がれ、エージェントが一度も接続できないことが分かった。
  6.1 節に、`vpsd` 自身の 2 つのポートを input の `policy drop` に対して検査し、必要な accept の行を提示することを追記した。
  ユーザー空間モードでも host の input firewall は同じ層にあるため、同じ検査を行う。
  管理用 API(既定 Unix ソケット)は外部公開を意図しないため対象から外した。
  ラボ(wgft-lab2)で、host に `iif lo accept`、established の accept、`tcp dport 22 accept` だけを持つ `input policy drop` のテーブルを足し、カーネルモードとユーザー空間モードの両方で `server check` が期待どおりの提示を出し、提示された行を足すと消えることを確認した

- WGFT_WG_ADDRESS の構文の誤りと、他の遅く解釈される設定の点検(2026-09-20):`internal/vpsd/mode.go` の `reconcileModeAndAddress` は `WGFT_WG_ADDRESS` を記録済みの値と文字列として比べるだけで、構文を検査していなかった。
  構文の誤った値は `internal/vpsd/vpsd.go` の `Run` にある `netip.ParsePrefix` まで届き、そこはただのエラー(終了コード 1)になって、再起動しても直らないのに `server.service` に 2 秒おきに再起動され続けていた。
  `WGFT_WG_PORT`・`WGFT_MTU` と同じ場所(`cmd/wgft/server.go` の `buildServerOptions`)で `netip.ParsePrefix` により検査し、`vpsd.Run` に触れる前に終了コード 3 で止めることにした(11a 節の一覧に追記)。
  同じ観点で、起動の後半で初めて解釈される他の設定項目も洗った。
  `WGFT_AGENT_API` と `WGFT_ADMIN`(`unix://` を除く)は `admin.Listen`/`agentAPI.Listen` まで構文検査をしておらず、`net.Listen` の一般的な失敗(構文の誤りも、ポートの二重使用のような環境由来の失敗も同じ形で返る)に紛れて終了コード 1 になっていたため、同じ `buildServerOptions` で構文だけを先に検査することにした。
  検査するのは `host:port` の形と、ポートが解決できることである。
  `unix://` を受け付けるのは、Unix ソケットで待ち受けられる `WGFT_ADMIN` だけで、ソケットのパスが空なら設定の誤りとする。
  エージェント用 API は TCP だけで待ち受けるので、`WGFT_AGENT_API` の `unix://` は設定の誤りとする。
  `EADDRINUSE` のような真の環境由来の失敗は、この検査を通った後の `net.Listen` にそのまま届き、終了コード 1 のままである(再起動が直しうるため)。
  検査を加えなかった項目とその理由は次のとおりである。
  `WGFT_WG_ENDPOINT` は host:port の形を検査していないが、`admin_backend.go` の `JoinString` でしか使わず、`net.SplitHostPort` の失敗はそのメソッドの戻り値のエラーとして admin API の呼び出し元に返るだけで、起動そのものは失敗しない。
  `WGFT_AGENT_API_HOST` は接続文字列にそのまま埋め込む文字列で、構文の検査を経ずに使う。
  `WGFT_ADMIN_HOST` は Host ヘッダの許可一覧に足すだけの文字列で、同様に構文の検査を経ない。
  この 3 つはいずれも「起動を止める」経路に無いため、11a 節の一覧には加えていない。
  エージェント側にも同じ種類の欠落があった。
  `internal/agent/agent.go` の `ensureRegistered` は、未登録の状態で `WGFT_JOIN` が空、`ParseJoin` が構文エラーを返す、または使用済みのトークンと一致する場合、プレーンな `error` を返しており、`cmd/wgft` 側のどこもそれを `*configError` や `*wg.StartupRefusal` に写していなかったため、終了コード 1 になり、`agent.service` に再起動され続けていた(この 3 つはどれも再試行では直らない)。
  `Register` のネットワーク到達性の失敗(VPS や経路の一時的な問題で、再起動が直しうる)とは区別する必要があるため、`internal/agent` に `*agent.ConfigRefusal`(`*wg.StartupRefusal` と同じ形の、理由だけを持つ型)を新設し、この 3 つの分岐だけをそれで返すことにした。
  `cmd/wgft/main.go` の `exitCode` に `isAgentConfigRefusal` を加え、`isStartupRefusal`・`isConfigError` と並べて終了コード 3 に写す。
  `internal/agent` は Windows・macOS のビルドにも入るクロスプラットフォームな package なので、`isStartupRefusal` と違って build tag で分ける必要が無い。
  既に登録済みのエージェントで `WGFT_JOIN` が古いまま compose に残っている場合(11a 節が意図的に許す居座り)は、`ensureRegistered` の別の分岐(`f.PermanentToken != ""`)を通り、ログを出すだけで `nil` を返すので、この変更の影響を受けない。
  ホストの単体テストで、`WGFT_WG_ADDRESS`・`WGFT_AGENT_API`・`WGFT_ADMIN` それぞれの構文の誤りが cobra 経由の `server run` で終了コード 3 になること、`WGFT_AGENT_API`/`WGFT_ADMIN` の 2 つは kernel モードで確かめると非 root の環境では `bringUpWG` の権限不足(次の改訂で加える `classifyPrivilege`)が先に終了コード 3 を返してしまい実際にはこの検査を試さないまま通ってしまうことを手を動かして確認したため、userspace モードで検査した、エージェントの `WGFT_JOIN` の 3 つの分岐が `*agent.ConfigRefusal` になり cobra 経由の `agent run` で終了コード 3 になることを確かめた。
  いずれも、検査やコードを一時的に外すと同じテストが終了コード 1 のまま失敗することを確かめてから戻した。

- カーネルモードを root でも CAP_NET_ADMIN でもない状態で起動したときの中止(2026-09-20):起動時に権限そのものを事前に確かめる処理が無く、`internal/dataplane/linuxkernel/wg.Ensure` の最初の特権付き netlink・wgctrl の書き込み(インタフェースの作成、または既存インタフェースがある場合は MTU・アドレス・鍵・ポート・ピアの差分)が `EPERM`/`EACCES` で失敗するだけだったため、ただのエラー(終了コード 1)になって `server.service` に 2 秒おきに再起動され続けていた。
  事前に `CAP_NET_ADMIN` の有無を検査する案(環境を見て推測する)は 11a 節の原則に反するため採らず、実際の書き込みが権限不足で返ってきた時点で判定する方式にした。
  `Ensure` はどの書き込みが最初に当たるかがインタフェースの有無で変わるため、各書き込みの呼び出し箇所に個別の判定を足す代わりに、既にある「作ったインタフェースを後始末する」`defer` に、`errors.Is(err, os.ErrPermission)`(`EPERM`・`EACCES` はどちらも `syscall.Errno`(`golang.org/x/sys/unix.Errno` の別名)の `Is` メソッドでこれに一致する)で判定する `classifyPrivilege` を追加し、一括して `*wg.StartupRefusal` に変えることにした。
  理由の文言には、同梱の `server.service` が使う経路(root、または `AmbientCapabilities=CAP_NET_ADMIN`)と、`WGFT_MODE=userspace`(どちらも要らない)の 2 つの逃げ道を明記する。
  ユーザー空間モードは wg のインタフェースをカーネルに作らないため、この判定に触れない。
  9 節と 11a 節の一覧に追記した。
  ホストの単体テストで、`classifyPrivilege` が `nil`・無関係なエラー・既に `*wg.StartupRefusal` のもの・`EPERM`/`EACCES` を包んだエラーのそれぞれを正しく扱うこと、`cmd/wgft` の `exitCode` がこの `*wg.StartupRefusal` を終了コード 3 に写すことを確かめた。
  判定を一時的に無効化すると同じ単体テストが `*StartupRefusal` を返さず失敗することを確かめてから戻した。
