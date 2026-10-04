<!-- docs-status: historical -->

# 2026-09-21: operations

- 起動の失敗の意味論を非対称の規則に統一する(2026-09-21、所有者の決定、11b 節を新設):終了コードの決め方を、失敗の一覧から 2 つの問い(再試行で直るか、人が手を入れなければ直らないか)による規則に改めた。
  既定は終了コード 1 とし、終了コード 3 は原因が設定された値そのものであると示せる場合か、運用者の操作なしには消えないと示せる場合だけに使う。
  示せない失敗は終了コード 1 とする。
  誤った終了コード 3 は systemd の再起動を永久に止め、原因が消えた後も転送が戻らないためである。
  この規則と 4 つの種別(`config`、`prerequisite`、`conflict`、`mode-gate`)を 11b 節に定め、9 節と 11a 節の記述をそれに合わせた。
  拒否の型は `internal/startup` の `*startup.Refusal` 1 つにまとめた。
  それまでは `internal/dataplane/linuxkernel/wg` の `StartupRefusal`、`cmd/wgft` の `configError` と `configUnreadableError`、`internal/agent` の `ConfigRefusal` の 4 つがあり、`cmd/wgft` の `exitCode` が並べて見ていたため、新しい失敗を足すときに写し忘れる余地があった。
  カーネルの WireGuard と関係の無い失敗(`WGFT_MODE` の欠落、アドレス帯の食い違い、モードの関門、conntrack の sysctl)までカーネルの package の型を通っていたことも、ユーザー空間モードでは筋が通らなかった。
  `internal/startup` はモジュールの中の何も import しない葉であり、7a.7 節の依存の向きを変えない(`internal/dataplane/deps_test.go` が検査する)。
  終了コードが v0.5.1 から変わるものは次のとおりである。
  他の所有者が持つ資源との衝突 4 つ(同名インタフェースの鍵の不一致、他の WireGuard との待ち受けポートの衝突、他のプロセスによる UDP ポートの bind、アドレス帯の重なり)と、`table inet wgft` の適用後に conntrack の sysctl が読めない場合を、終了コード 3 から 1 に変えた。
  相手が資源を手放せば次の再起動で起動できるので、再起動を止めると衝突が消えた後も転送が戻らないためである。
  逆に、次の失敗を終了コード 1 から 3 に変えた。
  `WGFT_WG_INTERFACE` がカーネルの受け付けない名前、`WGFT_MTU` が範囲外、`WGFT_WG_PORT` が 0、`WGFT_DATA_DIR` が空、`WGFT_WG_ENDPOINT` と `WGFT_AGENT_API_HOST` が `host:port` の形でない、`WGFT_ADMIN_TAILSCALE` が真偽値でない(それまでは綴りの誤りを黙って偽として扱っていた)、新しい版が書いたサーバのデータベース、登録の応答が HTTP 401・400・409 のいずれか。
  値だけから判定できる検査はすべて入口(`buildServerOptions` と新設の `buildAgentOptions`)に移し、`vpsd.Run` の中に残る `netip.ParsePrefix` は二重の守りにした。
  `WGFT_JOIN` の構文だけは入口で拒否せず警告に留める。
  登録済みのエージェントは compose に残った古い値を読まないので、拒否にすると動いていたエージェントが使われない値の誤りで止まるためである。
  ホストの単体テストで、`serverSpecs` のすべての設定項目に壊れた値を 1 つ与えると終了コード 3 で止まり、サーバのデータベースも管理用 API のソケットも作られないこと(表に無い項目を足すと落ちる形の、種類そのものを守るテスト)、資源の衝突と conntrack の読み取りの失敗が終了コード 1 になること、拒否の文言が種別と対象を出すこと、`server check` の表示が種別を添えること、登録の応答の種別分けを確かめた。
  ラボの使い捨て VM で、値の誤りが何も作らずに終了コード 3 で止まること、待ち受けポートの衝突が終了コード 1 で再試行され解消後に起動すること、非特権のカーネルモードが終了コード 3 で止まること、同梱の unit の下で終了コード 3 では `NRestarts` が増えず終了コード 1 では増えることを確かめた。
  未確認:`table inet wgft` の適用後もなお conntrack の sysctl が読めない実機の環境(前の改訂から引き続き未確認であり、この改訂で終了コード 1 に変えた判断の根拠も、その環境を見ていないことにある)、登録の応答の HTTP 409 を実機で起こした場合の文言
