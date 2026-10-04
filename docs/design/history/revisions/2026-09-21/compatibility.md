<!-- docs-status: historical -->

移動元: [docs/design/revisions.md](https://github.com/rahanahu/wgft/blob/8875f37e04e2576fed740c62e6a96a29a51e46b7/docs/design/revisions.md)。
基準コミットは `8875f37e`、元の行範囲は 116, 117, 119, 127, 131, 132, 139, 147 です。

# 2026-09-21: compatibility

- 移行の完了後の構造の点検と、v1.0 までの内部構造の固定(2026-09-21、7a.7 節):Phase 1 から 6 の移行が終わった後に、層の分け方を点検した。
  `internal/model`、`internal/policy` とその下位、`internal/planner` がモジュールの中で import するのは `proto` と互いだけで、`internal/resource` と `internal/lograte` はモジュールの中の何も import しない。
  7a.7 節が宣言する 5 つの依存の規則は `internal/dataplane/deps_test.go` がすべて検査する。
  移行のための分岐、旧い名前、暫定の fixture は、コードにもラボにも残っていない。
  PONR の順序は `reconcile.Runtime.Apply` の 1 か所に、Admission Policy の評価順は `policy.Order` の 1 か所にある。
  実装が 1 つで呼び出しが 1 か所の interface も点検したが、どれも依存の向きを保つか、管理 API への加算を型で保証する役目を持つので残した。
  点検で見つかったのは、使われない型と引数、設計文書と実装の食い違い、同じ役目の小さな仕組みの重複で、構造の変更を要するものは無かった。
  この結果を受けて、v1.0 のリリースまで package の境界、依存の向き、層の間の interface、新しい抽象の層の追加を原則として固定する。
  固定の対象、対象外、例外の条件は [CLAUDE.md](../../../../../CLAUDE.md) の「v1.0 までの内部構造の固定」に置く。
  この固定は v1.0.0 のリリースをもって終了した(下の 2026-09-23 の項)。
  未確認:点検はコードと設計文書を読んで行ったもので、実際の利用から見える構造の問題は v1.0 の後に扱う

- macOS の実機での確認と結果の反映(2026-09-21、issue #88 の D2 と E5):リリース v0.5.1 の `wgft-darwin-arm64` を Apple シリコンの Mac(macOS 27.0)で、実機の VPS(v0.5.1、カーネルモード)に対して確認した。
  `curl` で取得したファイルに隔離の属性が付かず Gatekeeper に止められないこと、ターミナルからの登録と認証情報ファイルの権限(ディレクトリ 0700、ファイル 0600)、`TUNNEL` の `ok`、LaunchDaemon からの起動と `kill -9` の後の再起動、Mac 自身と LAN の他のホストへの TCP と UDP の中継、12000 バイトのデータグラムが欠けずに届くこと、`WGFT_AGENT_ALLOW_TARGETS` の一覧の内と外の扱いと `RULES` 列に出る理由、env ファイルの権限の警告(0644 で出て 0640 で出ない)、認証情報も `WGFT_JOIN` も無いときの終了コード 3、切断したエージェントの `last:` 付きの表示、server の再起動からの復帰(約 2 秒)、Wi-Fi の切断と再接続からの復帰(次の 30 秒報告で `ok`)、蓋を閉じたスリープからの復帰(復帰の 3 秒後に再接続、プロセスは同一)、Mac の再起動(最初のログインの後にデーモンが起動し、ターミナルを触らずに中継が戻る)が通った。
  失敗した項目は無い。
  この確認を受けて 3 点を本書とセットアップガイドに直した。
  (1) 終了コード 3 で終わったときの launchd の挙動は、見込みどおり `ThrottleInterval` の間隔で再起動を繰り返すことだった(60 秒のあいだに 6 回起動し、`last exit code = 3`、`state = spawn scheduled`)。
  11a 節の未確認の一覧から外し、systemd と違って設定の誤りに気付く手段がログだけになることを書いた。
  (2) TCP の待ち受けを開いたときの `target` への試し接続(`checkTarget`)は、実装にはあったが本書に無かった。
  宛先からは中身の無い接続 1 本に見えること、宛先が未起動なら `cannot connect to target` がルールの `error` として出て次の報告で消えることを 7 節に書いた。
  ラボは宛先を先に起動するため気付かず、実機で宛先より先にルールを足して分かった。
  (3) FileVault を有効にした Mac が再起動の後に `network is unreachable` を出し続ける長さは、その Mac のネットワークが上がるまでの時間で決まる。
  2026-09-19 の確認の十数秒に対し、今回の Mac は Wi-Fi の接続もログインの後に始まるため約 60 秒だった。
  11a 節の記述をこの形に直した。
  未確認:新しいバイナリを置いた直後の 1 回目の試し接続だけが LAN の他のホストに対して `no route to host` で失敗し以後は再現しなかった理由、FileVault を無効にした Mac でログインせずに起動時から動くかどうか、ログアウトの後の動作、ブラウザで取得した隔離の属性付きのバイナリを Gatekeeper が止めること、macOS のアプリケーションファイアウォールを有効にした場合の挙動(今回の Mac では無効だった)、ターミナルからの確認の一部を Terminal.app ではなく同じ利用者の別の端末プロセスから起動したため、Terminal.app のローカルネットワークの許可を引き継ぐ経路そのものは確かめていないこと

- v1.0 の互換性の保証をサーフェスごとに明文化(2026-09-21、所有者の決定):7a.6 節は維持する外部仕様の一覧を持つが、「すべてを凍結する」のか「約束する範囲だけを凍結する」のかを名指ししていなかった。
  所有者の方針(すべてを凍結するのが目的ではない)に沿って、7a.11 節を追加し、管理用 API・Web UI・CLI・設定・ログ出力・wire protocol・サーバの DB とエージェントの認証情報ファイル・ファイルの権限・`deploy/` の同梱物・リリース成果物とコンテナイメージ・Go モジュールのそれぞれについて、保つもの・保たないもの・機械可読な保証・自由に変えてよい人間向けの表示を分けて書いた。
  コードを読んで確かめたことは次のとおりである。
  管理用 API(`internal/vpsd/admin`)には独自の認証が無く 401 を使わない(403 は Host/Origin の検査による拒否)。
  `GET /api/v1/rules` のバックエンド失敗を 500 にした v0.5.1 の修正は管理用 API 自身の話で、401 を 500 に変えた修正はエージェント用 API の stream 認証(`internal/vpsd/stream/hub.go`)の話であり、この 2 つを混同していた最初の前提を訂正した。
  `rule ls --json`(`cmd/wgft/rule.go`)と `agent ls --json`(`cmd/wgft/agent.go`)は CLI 独自の型を持たず、管理用 API のレスポンス型(`admin.BatchResponse`、`[]admin.AgentInfo`)をそのまま出力するため、CLI の `--json` の保証は管理用 API v1 の保証と同一であると明記した。
  `proto.SupportedProtocol` が今も `{Min:1, Max:1}` で、`capabilities` の語彙(`proto.SupportedCapabilities`)が空であることを確認し、「現在の版と直前の版の wire protocol を必ず支える」という 7a.6 節の約束は、番号の付いた版が v1 しか無いため実地では未検証であると明記した。
  `GET /api/v1/nft` だけが `text/plain` を返し他の `/api/v1/*` と揃っていないことも、保証として追認する前に判断が要る点として残した。
  `proto/` は `internal/` の外にあり Go として import できるが、README(英日とも)がライブラリとしての利用を謳っていないため、Go の API としては約束しないことにした(判断)。
  `rule ls` の REFUSED 列(Resource Guard のフロー予算の拒否だけを数える)と、`WGFT_AGENT_ALLOW_TARGETS` によるエージェント側の拒否理由(`agent ls` の RULES 列と Web UI にだけ現れる、v0.5.0/v0.5.1 の既知の問題)が今も別々であることを明記し、一本化は今後の判断として約束の対象外にした。
  終了コードの意味の仕様は、別の作業が 9 節・11a 節で並行して定めているため、この節では値を決めず参照だけにした。
  サーバの DB とエージェントの認証情報ファイル、ファイルの権限、`deploy/` の同梱物、リリース成果物とコンテナイメージ、README の記述は、コードとリリースワークフロー(`.goreleaser.yaml`、`.github/workflows/release.yml`)を読んで確かめた。
  README.md・README.ja.md と `cmd/wgft/helptext.go` は変更していない。
  CLAUDE.md の約束どおり CLI のヘルプは `docs/cli.md` の生成元であり `cmd/wgft` は他の作業が並行して触れているため、「`--json` は自動化向け、表は人間向け」という一文をヘルプに足すかどうかは今回は判断を保留し、要否と要る場合の生成・ラボの要否を所有者に委ねる。
  未確認:番号の付いた版が 2 つ以上になったときに、実際に rolling upgrade が成り立つこと

- Windows でエージェントのトンネル受信が永久に止まる不具合を修正(2026-09-21、実験による確認):`golang.zx2c4.com/wireguard` の `conn.NewDefaultBind()` は、Windows では Registered I/O を使う `WinRingBind` を返し、`SIO_UDP_CONNRESET` を無効にしないことを確認した。
  到達できない宛先へ UDP を送った後の受信が Windows 特有の WSAECONNRESET(`net.Error` の `Temporary()` が false)になり、`device.RoutineReceiveIncoming` がこれを回復不能な誤りとして受信ループを止め、そのトンネルの受信が以後戻らないことを、スタンドアロンの再現コードと `device.LogLevelVerbose` のログで確認した。
  同じ Windows のソケットを Go の `net` パッケージ経由(`conn.NewStdNetBind()`)で開くと、同じ操作でも受信が止まらないことも確認した。
  修正は、Windows でだけ `conn.NewStdNetBind()` を明示して使う形にし、エージェントのトンネル(`internal/dataplane/userspace/tunnel`)と、CI の `windows-test` がビルドと単体テストの対象にしている server 側のユーザー空間トンネル(`internal/dataplane/userspace/utun`)の両方に適用した。
  この選択は Windows でのバッチサイズを変えない。
  依存する `golang.zx2c4.com/wireguard` のこの版では、`WinRingBind.BatchSize()` も `StdNetBind.BatchSize()` も Windows で 1 を返し、差が無いためである。
  残る差は、自前のリングバッファと Go の netpoller 経由の UDP ソケットとの間の、パケットごとの syscall や I/O 完了通知のオーバーヘッドであり、その大きさは未測定である。
  7・6.3 節を追随。
  実サーバーに対する実運用での挙動のうち、経路上を伝わる ICMP がこのソケットに WSAECONNRESET として現れるかどうかは、後日インターネット越しの計測で確かめた(改訂の記録 2026-09-21 の別項)。
  10054 は Windows 自身のスタックが答える ICMP(TTL 128)でのみ再現し、経路上を伝わる ICMP(WSL2 ゲストの Linux カーネル発、LAN 上の別ホスト発)は一度も現れなかった。
  WSL2 のミラーモードはポートで振り分けるため、待ち受けの無いポートへの送信はゲストに届かずホスト自身が答える、代替ではない実際の経路である。
  この機構は観測した恒久的な失敗の説明として十分だが、公開済みのエージェントでの実際の原因かどうかは、計装していないため確かめていない。
  実サーバーの到達不能な UDP ポートへインターネット越しに送る計測でも、WinRingBind のソケットに WSAECONNRESET は現れず、この引き金はこの計測環境では実際には引かなかった。
  ICMP がその経路のどこで失われているか(VPS が拒否ではなく破棄している、経路上の何かが落としている、Windows がこのソケットに反映しない、のいずれか)と、他の経路でこの引き金が引きうるかどうかは、なお未確認である。
  また、この修正を実サーバーに対して実機で通しで確かめてはいない。

- Windows の CI で in-process のテストのエージェント側が受信を止める(2026-09-21、docs/development/testing.md「実機の確認を小さな回帰テストに置き換えた範囲」の追加に伴う CI での確認):エージェント側のトンネルと中継、VPS 側のユーザー空間モードが使う部品を 1 プロセスの中で繋いで転送を確かめる新しいテスト(`internal/dataplane/userspace/utun` の `TestAgentServerInProcessForwarding`)を Windows の CI runner(`windows-test`)で流したところ、握手の後、server 側はエージェントの endpoint を学習して送信を続ける(`tx` が伸び続ける)のに対し、エージェント側は受信が最初から最後まで 0 のままだった。
  握手を待つ上限を 15 秒から 40 秒に広げても変わらず、待つ時間の不足では説明できない、送信だけが働き受信だけが止まる片方向だけの停止である。
  原因として最も有力なのは、wireguard-go の `conn.NewDefaultBind()` が Windows で返す `WinRingBind`(`conn/bind_windows.go`)が Go の `net` パッケージを経由せず Winsock の関数を直接呼ぶため、`net` パッケージが自分の作る UDP ソケットに自動で行う `SIO_UDP_CONNRESET`/`SIO_UDP_NETRESET` の無効化(2026-09-19 の「Windows の UDP 中継をバッファなしで待つ形に修正」の項、`go.dev/issue/5834`)を受けないことである。
  無効化が無いと、ICMP の port unreachable が届いた UDP ソケットは後続の受信を `WSAECONNRESET` で失敗させる、Windows の UDP の既知の挙動が起こり得る。
  `afWinRingBind.Receive`(`conn/bind_windows.go`)はこの状態を裸の `windows.Errno`(`syscall.Errno` の別名)として返し、Windows の `syscall.Errno.Temporary()`(`src/syscall/syscall_windows.go`)は `EINTR`・`EMFILE`・`Timeout()`(`EAGAIN`/`EWOULDBLOCK`/`ETIMEDOUT`)のときだけ真を返すため `WSAECONNRESET` では偽になり、`Errno` は構造的に `net.Error` を満たす。
  `device.RoutineReceiveIncoming`(`device/receive.go`)の `err.(net.Error)` が `ok` かつ `!Temporary()` という判定にこれが掛かり、受信の goroutine をその場で永久に終える。
  この経路は未確認である。
  決定的な確認には wireguard-go 自身の verbose なログ(`Routine: receive incoming ... - stopped` などの行)が要るが、これは `device.NewLogger` の `LogLevelVerbose` でだけ出て、`utun.New`/`tunnel.New` はどちらも `LogLevelError` を固定で渡しており、外から水準を選ぶ経路が無い。
  これを設けるには `utun.Config`/`tunnel.Config` に項目を足す production の変更が要るため、テストだけを直す作業の範囲を超えるとして見送り、この未確認の読みのまま記録する。
  もしこの読みが正しければ、ループバックだけの興味本位の話ではなく実機にも及ぶ懸念になる。
  `internal/agent` の `apply`(`agent.go` の `runtime.apply`)は wg 設定(`st.WG`)自体が変わらない限りトンネルを作り直さないため、Windows のエージェントが一度でも同種の `WSAECONNRESET` を受けると、プロセスを再起動するまで受信が戻らない可能性がある。
  D1 の「再接続:server の再起動と、エージェントの再起動の後に転送が戻るかを確かめます」がまさにこれを実機で確かめる項目であり、この確認の重みが増した。
  `TestAgentServerInProcessForwarding` は Windows ではこの理由により結果を判定せず SKIP する。
  未確認:上記の機構そのもの(verbose なログでの確認は production の変更を要するため行っていない)、この状態が実機の Windows のエージェントで実際に起こるかどうか(D1・E4 で確かめる)

- SKIP を外し、wg の listen port の選び方を直す(2026-09-21、Pull Request #107 の反映と、Windows の実機での再確認):直前の改訂の記録が未確認としていた原因の機構は、main に取り込み済みの Pull Request #107 が別に確かめて直している。
  `internal/dataplane/userspace/tunnel` と `internal/dataplane/userspace/utun` の `newBind()` は、Windows でだけ `conn.NewStdNetBind()` を明示して使う。
  `TestAgentServerInProcessForwarding` の `runtime.GOOS == "windows"` の SKIP と `windowsSkipReason` は、この前提が崩れたため外した。
  SKIP を外した状態を Windows の実機で繰り返し実行すると、一部の実行が失敗した。
  失敗はトンネル側の不具合ではなく、テストが wg の `listen_port` を連続する 50 個のポートの走査で選んでいたことによる「空きポートが見つからない」失敗だった。
  連続するポートがまとめて使えなかった理由は未確認である。
  走査は `ListenPort` に 0 を渡して OS に選ばせ、実際に割り当てられたポートを `IpcGet` で読み返す形に変えた(`device.BindUpdate` が `net.ListenUDP` と同じ規則で port 0 を実際の空きポートに解決し、`IpcGet` が解決後の値を返すことを、依存する `golang.zx2c4.com/wireguard` のこの版で確認している)。
  `Tunnel` に読み返しの手段が無いため、テストファイルが package utun の内側から非公開の `dev` フィールドへ直接アクセスする形にし、production 側の interface は変えていない。
  この形にした後、CI の `windows-test` でこのテストが繰り返し通ることを確かめた。
  未確認:Windows の実機での再実行、連続するポートがまとめて使えなかった理由

- macOS の実機でのスリープと Wi-Fi の確認(2026-09-21、issue #124 の E5):main の ebee6fb から作ったエージェントを Apple シリコンの Mac(macOS 27.0)で、実機の VPS(v0.6.0、カーネルモード)に対して確認した。
  短いスリープ、300 秒を超えるスリープ、短い Wi-Fi の切断、長い Wi-Fi の切断、経路の切り替え、通信を流し続ける対照の 6 つである。
  どの場合も転送は自力で戻り、エージェントを手で再起動する必要は無かった。
  長い Wi-Fi の切断では 7 節の作り直しとバックオフが実機でも働いた。
  ここで確かめたのは、受信の goroutine が死んだ場合の再現ではなく、ハンドシェイクが長時間新しくならない場合の watchdog の動作である。
  スリープからの復帰では作り直しは起きなかった。
  これとは別に、`time.Now` の単調な読みがサスペンドの時間を含まないことを実機で直接測って確かめた。
  345 秒のスリープを挟んで壁時計が 344 秒進む間に、単調な読みは 1 秒しか進まなかった。
  E5 の結果だけでは、復帰の直後に新しいハンドシェイクを観測して判定の起点が更新される場合と区別できないので、時計そのものを測った。
  これを受けて 7 節の未確認を macOS について解消した。
  測定値は issue #124 にある。
  確認の中で見つかった別件は 2 つに分けた。
  復旧した後もサーバがエージェントを切断と表示し続ける件が #135、経路の往復で `ip-flapping` が立つ件が #136 である。
  未確認:Linux と Windows の実機でのサスペンド中の時計の進み方

- 復帰したエージェントを server が数分にわたって未接続と表示する(2026-09-21、GitHub issue #135、実機の macOS とラボでの実測):`wgft agent ls` と Web UI が、TCP も UDP も転送しており WireGuard のハンドシェイクも数秒前のエージェントを、`STREAM` が空、ハートビートが古い、`TUNNEL last:ok` の形で未接続として示す状態が、実機の macOS で 3 分 43 秒と 1 分 31 秒続いた。
  原因は 2 つある。
  1 つ目は、stream の再接続のバックオフが上限の 5 分に達すると、接続が 1 分以上続くか再登録するまで初期値に戻らず、トンネルの回復が待ちを打ち切る根拠にならなかったことである。
  2 つ目は、エージェントが読みの期限も ping も持たず、半開きの TCP を、30 秒ごとのハートビートの書き込みが失敗するまで、つまり OS が再送を諦めるまで検出できなかったことである。
  5.2 節に「接続の生死の判定」を追加した。
  stream が生きているとは TCP が `ESTABLISHED` であることではなく、相手の応答が限られた時間の内に届くことだと定め、状態の報告を担うハートビートと、経路が双方向に通ることを測る ping の役割を分けた。
  エージェントは 30 秒ごとに WebSocket の ping を送り、20 秒以内に pong が返らなければ接続を閉じて繋ぎ直す。
  判定に要する時間の上限は 50 秒で、`vpsd` が何も届かない stream を閉じる 90 秒に対して 40 秒の余裕がある。
  期限を間隔の 2 / 3 としたのは、Python の `websockets`、MQTT、SSH、NATS が採る 1.0 倍から 3 倍の範囲の内側に収めるためである。
  同じ節の再接続の間隔には、WireGuard の新しいハンドシェイクを観測したら残りの待ちを打ち切り、バックオフを初期値に戻すことを加えた。
  観測には、トンネルの点検(7 節)が 30 秒ごとに読む最終ハンドシェイクの値をそのまま使い、別の監視を持たない。
  打ち切りによる再接続の試みは 2 分に 1 回を超えない。
  ラボで確かめたことは次のとおりである。
  homerouter で stream の 5-tuple だけを落として半開きの stream を作ると、Linux の既定の設定では、エージェントが気付くまでに修正の前は 15 分 53 秒かかり、その間 server は動いているエージェントを 14 分 48 秒にわたって未接続として示した。
  修正の後は 34 秒で気付いて繋ぎ直し、server の側は置き換えとして処理したので未接続の区間は現れなかった。
  経路を断ってバックオフを上限に届かせ、戻した後に `vpsd` が接続を認めるまでの時間は、修正の前が 301 秒、修正の後が 14 秒である。
  どちらの回でも転送は経路を戻してから 10 秒以内に回復しており、stream の遅れは転送の回復とは無関係である。
  Go の既定の 15 秒の TCP keepalive は、この 15 分 53 秒を縮めなかった。
  Linux では網の口を落としてもアドレスが残るため、既存の stream は誤りを返さずに半開きになることも分かった。
  エージェントの ping が `vpsd` 側の 90 秒の期限を延ばさないことは、`internal/vpsd/stream` の単体テストで固定した。
  `lab/version-skew.sh` の 4 つの組み合わせ(legacy v0 の v0.3.0 の agent、v0.6.0 の agent、v0.6.0 の server、現在の版どうし)がすべて通り、ping を送るようになった agent が旧い版の server とも通じることを確かめた。
  一式(`labhost run -parallel 8 all`)の判定も変わらない。
  未確認:Windows と macOS の実機での判定、`vpsd` 以外の WebSocket の実装が相手になる場合の pong の応答、pong の期限を 20 秒とした判断が細い回線や混んだ回線で十分かどうか。
