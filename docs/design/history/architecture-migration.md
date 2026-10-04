<!-- docs-status: historical -->

### 7a.8 移行の段取り

各段階は、今のラボの結合テスト(`lab/e2e.sh`、rate、connlimit、split-merge、import-export)と、策定中の lifecycle テスト(再起動中の転送継続、無関係なフローを切らないこと、proxy の bind 失敗が nftables に漏れないこと、teardown が wgft の物だけを消すこと、上限到達時の RSS がソフト上限と余裕の和の内側にあること)を、その段階の終わりに通すことを共通の完了条件とする。
どのテストをどの変更と時点で流すか(コードを変える PR ではマージの前にラボの一式を流すことを含む)は [docs/development/testing.md](../../development/testing.md) に定める。
以下は各段階に固有の完了条件だけを示す。

- **Phase 1(model/policy/plan)**:既存の Rule と State を内部モデルへ normalize し(外部形式からのアダプタを含む)、`AdmissionPolicy` の IR、`Plan`、`Planner` を作る。
  dataplane の挙動は変えない。
  完了条件:純粋な単体テストが model/policy/planner を対象とし、生成される nftables の内容と userspace の転送挙動が変更前と一致する
- **wire protocol の版と機能の交渉**:全体状態の形を変える前に入れる。
  完了条件:旧 agent と新 server、新 agent と旧 server の組み合わせで、通常の rolling upgrade がラボで通る
- **Phase 2(userspace backend 化)**:userspace の中継と proxy を `Backend` の後ろへ移す。
  完了条件:挙動を変えず、基準のテストを通す
- **Phase 3(VPS kernel backend 化)**:WireGuard、nftables、conntrack、sysctl、所有判定を `internal/vpsd` から `internal/dataplane/linuxkernel` へ切り離す。
  完了条件:`internal/dataplane/linuxkernel` から `internal/vpsd` への import が無いことをビルドで確かめられ、停止時に残し起動時に収束する今の挙動を保つ
- **Phase 4(トランザクショナルな収束)**:`Desired`/`Prepared`/`Active`/`Retiring`、`Prepare`/`Commit`/`Rollback`(7a.3 節の範囲)、世代、失敗からの回復、再起動時の収束を導入する。
  ルール単位の fail-closed は、nftables の全体差し替え(6.1 節)にそのルールの新しい dispatch を含めないことで実現し、差し替え中のルールだけを部分的に書き換える仕組みは作らない。
  完了条件:backend 全体に及ぶ失敗が `Active` 世代を進めないこと、ルール単位の prepare 失敗はそのルールだけを理由付きの `not_active` のまま見えるようにし、他のルールの `Active` 化と世代の前進を妨げないこと、置き換えに失敗したルールが他のルールの commit 後に新規フローを拒むこと(fail-closed)、`Desired` に無いのに残っている資源が `active_only`/`retiring` として見えること、`Relay` のルールを fail-closed にしても安全な成立済みの TCP 接続が残ることを、新設の lifecycle テストで確かめる
- **Phase 5(共通の Admission Policy)**:nftables コンパイラと Go の評価器を 1 つの IR から作る形に統合し、4 か所に分かれていた許可拒否の判定(`internal/dataplane/linuxkernel/nft`、`internal/dataplane/userspace/srcpolicy`、`internal/dataplane/linuxkernel/conntrack` の `sourceAllowed`、`internal/vpsd/proxyrelay` の `sourceAllowed`)を IR と 2 つのコンパイラへ集約する。
  kernel dataplane では `Transparent` と `Relay` の分岐より前に共通の ingress 層を置く。
  IR の形、各コンパイラの約束、許容差、fixture、移行の手順は 7a.9 節に定める。
  完了条件:同じ入力に対して両コンパイラが 7a.4 節と 7a.9 節の許容差の範囲内で一致することを共有 fixture で確かめ、既存の connlimit などのラボテストを保つ
- **Phase 6(Resource Guard の再設計)**:`flowcap.Limits` が混ぜている送信元ごとの上限(Admission Policy)とプロセス全体の予算(Resource Guard)を `AdmissionLimits` と `ResourceLimits` に分ける。
  ルールごとの隔離を、共有プールと隔離予約の方式に置き換える。
  隔離予約は admission 時の予約であり、既存のフローを追い出す保証ではない。
  kernel 側の保護(conntrack の表、set の大きさ)は、userspace の計算式を再利用しない形のまま整理する。
  型、式、拒否の報告、移行の手順は 7a.10 節に定める。
  完了条件:1 本のルールなら空いている予算をほぼ使い切れ、複数のルールが競合するときだけ他ルールの最低限を守り、既存のフローを公平化のために切らないことを、ラボで確かめる
- **Phase 7(agent の kernel dataplane、v1.2)**:Linux のエージェントのカーネルモード(7b 節)を、`internal/dataplane/linuxkernel` の共通の部品を再利用し、agent に固有の nftables と conntrack の経路を同じ package に足す形で追加する。
  agent は `Runtime` へ移さず、`internal/agent` の中に切った dataplane の境目の後ろに置く(7a.7 節)。
  ラボで手作業で組んだ検証(2026-09-19)から、範囲のルールは無名 map の DNAT で表すこと、`DynamicUser` と `CAP_NET_ADMIN` のサンドボックスで足りること(`ProtectKernelTunables` は `ip_forward` の書き込みを妨げるため付けないこと)、実物の Docker の `DOCKER-USER` への追加行が Docker の再起動をまたいで残ること、複数 LAN セグメントを持つ自宅では `rp_filter` の strict が転送を壊しうること(`conf.all` と個別インタフェースの値は、より厳しい方が勝つ)が分かっている。
  agent の kernel dataplane をラボで試作した結果(2026-09-19)からは、agent の停止中も既存と新規のフローが続くこと、変更の無い再起動で conntrack が保たれること、マシンの再起動の後に保存した状態から stream に接続する前に組み直せること、LAN の target に設定変更が要らず MASQUERADE が要ることが分かっている。
  同じ試作で、自宅側に conntrack の収束が要ること(7a.3 節)、agent は `ip_forward` を明示して設定する必要があること、userspace と kernel の切り替えには約 1 から 2 秒の断があることも分かった。
  v1.2 の設計の前のラボ(2026-09-23)では、範囲のずらしを表す無名の連結 map の DNAT を google/nftables で組めること、非 root で `CAP_NET_ADMIN` だけを持つプロセスが WireGuard、nftables、conntrack、`ip_forward` のすべてを操作できること、非特権の LXC の中でも同じ操作ができることを確かめた(改訂の記録 2026-09-24)。
  決定と外部から見える面は 7b 節に定め、完了条件の細部は各段の実装がその節に書く
