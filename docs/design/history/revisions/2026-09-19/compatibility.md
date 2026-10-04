<!-- docs-status: historical -->

# 2026-09-19: compatibility

- Windows の認証情報ファイルの ACL を保護(2026-09-19、Windows 11 の実機での確認を受けて):実機で非管理者のまま Windows agent を実サーバに対して確認したところ、登録・トンネル・中継・双方の再起動からの復帰・二重起動の拒否・認証情報ファイルの書き換え・稼働中の `rotate-key` は通ったが、`icacls` により `agent.json` が `%ProgramData%` から継承した `BUILTIN\Users:(RX)` を持ち、PC の他の利用者が wg 秘密鍵と恒久トークンを読める状態にあることが分かった(`.lock`・`.sock` は秘密を持たない)。
  9・11a 節に、`agent.json` は `Save` が一時ファイルへ SYSTEM・`BUILTIN\Administrators`・実行中の利用者だけのフルアクセスに絞った保護 DACL を付けてから書き rename する形、既存の緩い `agent.json`・`.lock`・`.sock` は Windows に限り起動時に個別に締め直す形、データディレクトリは agent が新規に作った場合だけ同じ DACL を付ける形(既存のディレクトリは Unix の `MkdirAll` と同様に変えない)を追記した。
  Unix の chmod はこの修正より前から機能しており、締め直すと管理者が絞った権限を緩めたり、ファイルを所有しない非特権の構成(`deploy/agent.compose.yaml` など)を壊したりするため、Unix の挙動はこの修正の前後で変えていない。
  SYSTEM でのサービス実行は常に読み書きできるが、非昇格の対話利用者は `BUILTIN\Administrators` が UAC で拒否専用になるため直前に書き込んだ本人でなければ読めないことも書いた。
  Windows 11 の実機で、既に緩かった `agent.json` が起動のたびに締まり直し、3 ファイルから `BUILTIN\Users` が消え、実サーバとの再接続が保たれることを確認した。
  この修正は既に流出した恒久トークンと wg 鍵までは無効にしない。
  wg 鍵は `agent rotate-key` で作り直せるが、恒久トークンを作り直す操作は無く、VPS 側で `agent revoke` の後に新しい接続文字列で登録し直す必要がある。
  未確認:Windows サービスとしての SYSTEM 実行

- Windows の一時ファイルの DACL を作成の瞬間に付けるよう修正(2026-09-19、レビュー指摘):前項の実装は `Save` が `agent.json` の一時ファイルを `os.CreateTemp` で作ってから保護 DACL を付け直しており、作成直後から付け直すまでの間、親ディレクトリから継承した緩い ACL のままの期間にハンドルを開かれ得ること、Windows はハンドルを開く瞬間にしかアクセス可否を見ないため後から DACL を締めてもその間に開かれたハンドルは取り消せないことが指摘された。
  9・11a 節を、Windows では一時ファイルの作成に使う `CreateFile` に保護 DACL を最初から渡す形に改めた(Unix は `os.CreateTemp` が作成の瞬間から 0600 なので変更なし)。
  制御ソケットにも `Listen` から `SecureSocket` までの間に同様の(より短い)緩い ACL のままの期間が残ることを 11a 節に明記したが、制御ソケットが受け付けるのは `rotate-key` の 1 コマンドだけで秘密をやり取りしないため、専用ディレクトリを都度作って先に締めるところまではせず、既知の制約として残す判断をした。
  Windows 11 の実機で、`createSecureTemp` が返す一時ファイルが作成の直後(他の呼び出しを挟む前)から保護 DACL になっていることを確認した。

- Windows のエージェントと CLI を公開(2026-09-19、Windows 11 の実機での確認を受けて):非管理者権限の Windows 11 から実機の VPS に対して、登録から中継、復帰、二重起動の拒否、rotate-key までを確認した。
  これを受けて Windows 版のエージェントと CLI を GoReleaser の build と README に加えることを決めた。
  常駐は、`agent run` をそのときの利用者の権限で起動するところまでを提供し、サービスや常駐の仕組みは持たない方針とし、Windows のゲームサーバの多くがユーザー権限で動くこと、サービス化が Program Files への配置や SYSTEM と対話利用者の ACL の取り合いを新たに要することを理由に決めた。
  Windows Defender Firewall の受信許可ダイアログは、許可してもキャンセルしても中継が鍵の再交換をまたいで動作し続けることを確認した。
  macOS は実機での確認がまだ済んでいないため、引き続き Releases に含めず、README にも対応とは書かない。
  未確認:Windows サービスまたは SYSTEM としての実行、Windows での UDP 中継のメモリ使用量

- macOS のエージェントの UDP の送信バッファを拡大(2026-09-19、macOS の実機での確認を受けて):macOS 27(arm64)のエージェントを実機の Linux の VPS(v0.3.0、カーネルモード)に対して確かめたところ、8000 バイトの UDP は通ったが、12000 バイトの UDP は VPS とトンネルを通ってエージェントまで届き、エージェントから宛先への書き込みで落ちた。
  原因は、macOS の UDP の送信バッファの既定が `net.inet.udp.maxdgram` の 9216 バイトで、これを超える書き込みが `EMSGSIZE` で即座に失敗することである。
  この失敗はログを出さずに、その送信元のセッションを閉じていた。
  `SetWriteBuffer` で送信バッファを上げると制限が外れることを確かめた。
  7 節に、macOS に限り宛先へのカーネルのソケットの送信バッファを 65535 バイトに上げること、宛先への書き込みの失敗をリスナーごとに 1 分に 1 回までログに出すことを追記した。
  セッションごとの Go のバッファは増やさない(2026-09-18 の項目の方針のまま)。
  修正後のエージェントで、12000 バイトと 30000 バイトの UDP が実機の VPS を通って中継され、同じ送信元ポートのままセッションが閉じられないことを確認した。
  未確認:同時フロー数の上限までセッションを張ったときの macOS のエージェントのメモリ使用量

- macOS のエージェントと CLI を公開(2026-09-19、macOS の実機での確認を受けて):macOS 27(Apple シリコン)のエージェントを、ホームルータの NAT の内側から実機の VPS(v0.3.0、カーネルモード)に対して確認した。
  登録、トンネル、Mac 自身と LAN の他のホストへの UDP と TCP の中継、Mac と server の再起動からの復帰、強制終了後の launchd による再起動、二重起動の拒否、稼働中の `rotate-key`、データディレクトリと認証情報ファイルの権限が通った。
  これを受けて darwin/arm64 を GoReleaser の build、release の証明と SBOM、README に加えることを決めた。
  darwin/amd64 は Intel Mac を対象にしないため公開しない。
  常駐には `UserName` 付きの LaunchDaemon を推奨し、`deploy/io.github.rahanahu.wgft.agent.plist` を加えた。
  LaunchAgent として起動した agent は LAN の他のホストに接続できず、ターミナルからの起動と LaunchDaemon では接続できたためである。
  原因をローカルネットワークのプライバシー保護とするのは症状からの推測である。
  FileVault を有効にした Mac では再起動後に最初のログインまで LaunchDaemon が起動しないが、想定する利用者はその Mac のセッションでゲームサーバも動かすため、対処せず文書に書く判断をした。
  初回登録はターミナルから行い、全員が読める plist には join string を書かない。
  11a 節を改訂した。
  未確認:同時フロー数の上限でのメモリ使用量、FileVault を無効にした Mac でのログイン前の起動、ログアウト後の動作、終了コード 3 での launchd の挙動、darwin/amd64、Homebrew

- macOS で保持していた TCP の接続が閉じられた原因の追試(2026-09-19、前項の未確認の点の確認):前項と同じ Mac のコンテナの環境で追試した。
  TCP の接続だけを上限まで張った場合は 1 本も閉じられず、閉鎖は TCP の接続のフラッドとは関係がなかった。
  閉鎖は、トンネルを通る UDP のセッションを上限まで張るのと同時に TCP の接続を張っている間だけ起き、張り終えた後には起きなかった。
  閉鎖の一部は、エージェントのログの `connect: connection reset by peer` と 1 対 1 で対応した。
  これは Mac 上の試験の宛先への同時の接続が listen キュー(macOS の `kern.ipc.somaxconn` の既定は 128)を溢れさせたもので、試験の構成によるものである。
  残りの閉鎖は server とエージェントのどちらにもログを残さず、宛先にも届いていなかった。
  トンネルが colima の UDP のポート転送を通るのは Mac のエージェントだけで、転送を通らないコンテナ内の Linux のエージェントでは起きなかったため、トンネルが混んでいる間にこの転送でパケットが落ちたものと推測している。
  実機の VPS と実ネットワークではこの閉鎖を見ていないが、同じ負荷での試験はしていない。
  設計は変えず、11a 節の未確認の点の説明を改めた。
  未確認:残りの閉鎖の原因(パケットキャプチャで確かめていない)、実ネットワークで同じ負荷を掛けたときの挙動

- 内部アーキテクチャの再設計を追加(2026-09-19、v1.0 の前に再設計するという決定を受けて):7a 節を新設した。
  Rule から Forwarding(Transparent/Relay)、SourceMetadata(None/ProxyV2)、DataplaneMode(Kernel/Userspace)を分け、「kernel」という語をルール単位の選択と server・agent 全体の選択の両方に使わないようにした。
  転送の意味(vps_mode)と送信元の情報(proxy_protocol)は今の外部仕様でも別の軸(vps_mode=proxy かつ proxy_protocol=false/true はどちらも有効)なので、内部モデルも 2 つの型に分け、外部表現をロスなく写せるようにした。
  送信元制限とレートをまとめた Admission Policy という中間表現を導入し、今は `internal/vpsd/nft`、`internal/vpsd/srcpolicy`、`internal/vpsd/conntrack` の `allowed`、`internal/vpsd/proxyrelay` の `sourceAllowed` の 4 か所に分かれている許可拒否の判定を、1 つの IR から 2 つのコンパイラ(nftables、Go)を作る形に集約する計画にした。
  送信元 IP ごとの同時フロー数の上限(`WGFT_MAX_*_FLOWS_PER_SOURCE`)は Admission Policy に一本化し(kernel は `ct count`、userspace は Go のカウンタで同じ方針を実装する)、Resource Guard はプロセス全体の予算・メモリ・ルールごとの隔離・kernel の conntrack とシステムの予算に絞った。
  今の `flowcap.Limits` はこの 2 つを混ぜているため、Phase 6 で `AdmissionLimits` と `ResourceLimits` に分けることにし、それまで `internal/flowcap` の名前は変えない。
  Resource Guard に kernel/userspace 共通の Go interface は持たせない。
  Desired・Validated・Prepared・Active・Retiring の状態遷移を定め、Prepare は元に戻せる資源の確保、Commit は nftables の 1 トランザクションと Active 世代の更新に限り、汎用の 2 相コミットは持たないことにした。
  この区別は、プロキシの listener 管理が新しい待ち受けを先に開き差し替えの成否で開閉を分ける今の実装(6.1 節)を一般化したものである。
  失敗の粒度は失敗の範囲で決めることに確定した。
  1 つの listener の bind や 1 つの target の名前解決のようなルールに閉じた失敗は、そのルールだけを fail-closed(他のルールの commit 後に新規フローを拒む。
  既存のフローは安全なら Retiring として残す)にして他のルールの Active 化と世代の前進を妨げず、共有資源や backend 全体に及ぶ失敗(共有 set が作れない、WireGuard の設定誤り、nftables のトランザクション誤り)は世代全体を commit しないことにした。
  fail-closed は、nftables が全体を毎回組み立てて差し替える性質(6.1 節)を使い、次の全体差し替えにそのルールの新しい dispatch を含めないだけで実現でき、部分的な nft の書き換えは要らない。
  admin API v1 にはルールごとの `apply_state`・`reason`・`desired_generation`・`active_generation` と、`Desired` に無いのに残っている資源(`active_only`/`retiring`)を観測する経路を加算的に追加することにした。
  外部仕様(CLI、`WGFT_*`、rule import/export、admin API v1、agent/server の通信、既存データの置き場からの更新)は維持し、agent と server が別々に更新される前提で、agent の `pubkey` メッセージへの `protocol_version`/`capabilities`、server の `state` メッセージへの `server_protocol_version`/`server_capabilities` という対称な追加による版と機能の交渉を設けることにした。
  フィールドの不在は版 0、空の配列は「版はあるが追加機能は無い」を表し、両者を混同しない。
  旧い agent のサポートは製品の版ではなく `protocol_version` で決め、server は現在と直前の 2 つの版を必ず支え、`protocol_version` の無い(0 の)agent は v1.0.x の間は必ず支えて v1.1 以降で落としてよく、capability の追加だけでは版を上げず、旧い agent が新機能を表せない場合は黙って downgrade せずそのルールを理由付きの not active にすることにした。
  Reconciler は共有 package `internal/reconcile` に置き、Observe → diff → Prepare → Commit の骨格を server と agent で共有することにした。
  package 配置は `internal/model`、`internal/policy`、`internal/planner`、`internal/resource`、`internal/reconcile`、`internal/dataplane/{userspace,linuxkernel}`、`internal/frontend`、`internal/platform/{linux,windows,darwin}` を目標とし、`internal/dataplane/linuxkernel` が `internal/vpsd` に依存しない一方向の依存規則を定め、agent の kernel dataplane(v1.1 以降)が同じ実装を再利用できるようにした。
  移行は model/policy/plan、wire protocol の版交渉、userspace backend 化、VPS kernel backend 化、トランザクショナルな収束、共通の Admission Policy、Resource Guard の再設計の順に進め、各段階で既存のラボの結合テストと策定中の lifecycle テストを通す。
  未決:`capabilities`/`server_capabilities` の語彙(機能を追加する時点で個別に定める)、ルールごとの隔離を共有プールと隔離予約へ置き換える具体式(Phase 6、隔離予約は admission 時の予約であり既存フローを追い出す保証にはしない)、`frontend` の package の分け方(Phase 5 で実装しながら決める)
