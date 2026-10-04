<!-- docs-status: historical -->

移動元: [docs/design/revisions.md](https://github.com/rahanahu/wgft/blob/8875f37e04e2576fed740c62e6a96a29a51e46b7/docs/design/revisions.md)。
基準コミットは `8875f37e`、元の行範囲は 80, 83, 84, 88, 91, 93 です。

# 2026-09-20: admission-policy

- Admission Policy のコンパイラを定める(2026-09-20、7a.8 節の Phase 5):7a.9 節を新設した。
  IR には評価の定数(burst、送信元ごとの表の期限と大きさ、set の大きさ)、段と drop の種類の対応、CIDR の正規化を加えた。
  評価順は IR の `Order` だけが持ち、ある段が拒んだときは後の段の状態を消費せず、IR に無いルール ID は拒むことを約束にした。
  `Forwarding` は届け方、Admission Policy は入口の規則であり、両者を混ぜない。
  nftables のコンパイラは google/nftables に依存しない行の列を返し、`internal/dataplane/linuxkernel/nft` がそれを式へ写す形にした。
  行の列をホストで実行できる解釈器に流し、共有 fixture で Go の評価器との一致を root なしの単体テストで確かめるためである。
  Go の評価器は拒んだ段を示す `Decision` を返し、drop も自分で数える。
  状態を持つ段は、`DataplaneMode` で決まる 1 か所だけで評価する。
  コードを読んで、今の実装が IR の意味と食い違う点を見つけた。
  userspace の UDP の中継は deny より前に `packet_rate` を判定する。
  userspace の送信元ごとの同時フロー数の上限は `new_flow_rate` の後に判定され、drop に数えられない。
  `Relay` のルールのレートは両モードで効いていない。
  TCP のルールの `packet_rate` は kernel だけで効く。
  userspace と `Relay` の listener は IPv6 でも待ち受ける。
  後の 3 つについて、所有者の決定は次のとおりである。
  `Relay` のルールには Admission Policy のすべての段を適用する。
  `packet_rate` は UDP のデータグラムだけに効かせ、TCP のルールの値は受け付けて保存したまま、効かないことを CLI と Web UI で示す(TCP のパケット数は ACK と再送を含み、落としても再送を招くだけのため)。
  v1 は IPv4 だけを扱い、listener を IPv4 だけで開き、評価器自身も IPv4 でない送信元を拒む。
  IPv6 の送信元への対応は 13 節に加えた。
  避けられない差(拒否のネットワーク上の見え方、応答前の UDP パケットと SYN の再送の数え方、drop カウンタの単位、送信元ごとの表の期限と溢れ、補充の境界)は名前付きの許容差とし、等価性は判定、drop の種類、drop カウンタ、レートと同時フロー数の状態を対象とし、見え方は対象としないことにした。
  Resource Guard の判定は Admission Policy がフローを通した後に置き、その拒否は fixture に含めない。
  未決:`frontend` の package の分け方(Phase 7 の前に決める)。
  未確認:kernel の meter の要素の期限が `add` で延びないこと、トークンがちょうど補充される時刻での kernel の判定、解釈器の模型と kernel の一致(ラボで確かめる)

- Admission Policy の nftables コンパイラを置く(2026-09-20、7a.9 節の移行の手順 2):`internal/policy/nftables` が IR と判定を付けるポートの列から行の列を作り、`internal/dataplane/linuxkernel/nft` の `emit` はその行の列を式へ写す形にした。
  行の列は、set の宣言と、一致条件、文、コメントを持つ行からなる素の Go のデータである。
  段の順序は `policy.Order` を回して決まり、コンパイラは順序を持たない。
  生成した netlink のメッセージのバイト列が置き換えの前後で一致することを、`basic.json` を含む 7 つの設定で確かめた。
  行の列を実行する解釈器と、`internal/policy/testdata/admission` の fixture 16 本を加えた。
  fixture の形式に、場面の説明 `comment`、暫定の fixture の印 `interim_until_step`、数えない拒否を表す `want` の値 `drop`、許容差の識別子を加えた。
  `Relay` のポートの行と TCP の `packet` の行は今の kernel の挙動のまま残し、その fixture に手順 4 と 5 の印を付けた。
  許容差を挙げた fixture で実装ごとの結果の違いをどう書くかは決めておらず、7a.9 節の未決事項に加えた。
  解釈器の模型とカーネルの一致はホストでは確かめられず、7a.9 節のとおりラボで確かめる

- kernel の Admission Policy の行を IPv4 に限る(2026-09-20、7a.9 節、レビュー反映):7a.9 節は「kernel の行は IPv4 の送信元だけに一致する」としていたが、今の nftables の行で IPv4 に限っているのは送信元を読む行だけで、集約の `new_flow_rate` と `packet_rate` の行は IPv6 のパケットにも一致し、IPv6 のフラッドで IPv4 の通信のトークンを使い切れることが分かった。
  移行の手順 3 で、すべての行に `meta nfproto ipv4` を付けることにした。
  未確認:ラボでの IPv6 の経路での再現

- Admission Policy の Go の評価器を置く(2026-09-20、7a.9 節の移行の手順 3):`internal/policy/goengine` を加え、共有 fixture を解釈器と同じ手順で流すようにした。
  評価器は `policy.Order` を回し、拒んだ段より後の状態を消費しない。
  送信元ごとの同時フロー数の枠は手形として返し、後の段が拒んだときはその場で返す。
  IR に無いルール ID と、IPv4 射影を戻した後に IPv4 でない送信元は、drop に数えずに拒む。
  7a.9 節の未決事項だった許容差の及ぶ出来事の書き方は、fixture に書かないことに決めた。
  実装ごとの `want` を加えると、どちらの実装が正しいかを fixture が決めなくなるためである。
  `tolerances` は避けた許容差を示すだけになり、実装どうしの照合を省かない。
  移行の途中で kernel と userspace の挙動が意図して異なる場面(TCP のルールの `packet_rate`)は、暫定の fixture に照らす評価器を `engines` で限り、userspace の挙動を書いた暫定の fixture を 1 本加えた。
  `Relay` のルールの暫定の fixture は、userspace モードでも同じ挙動になるので、両方の評価器に照らす。
  userspace モードの `Relay` の中継のために、送信元ごとの同時フロー数の段だけを判定する `AdmitSourceFlow` を手順 4 までの入口として加えた

- kernel の Admission Policy の行をすべて IPv4 に限る(2026-09-20、7a.9 節の移行の手順 3、所有者の設計レビューを受けて):kernel モードの `table inet wgft` では、送信元を読む行(deny、allow、per_source、src_flow)だけが `ip saddr` の前の `meta nfproto ipv4` で IPv4 に限られ、集約のレートの行(new_flow、packet)は IPv6 のパケットにも一致していた。
  このため、判定を付けるポートへの IPv6 のフラッドが、IPv4 の通信の `new_flow_rate` と `packet_rate` のトークンを使い切れた。
  手順 2 はこの挙動をそのまま引き継いでいた。
  行の列の一致条件に IPv4 の印を加え、コンパイラがすべての行に付け、`internal/dataplane/linuxkernel/nft` が `meta nfproto ipv4` に写すようにした。
  `new_flow_rate` か `packet_rate` を持つルールでは生成するテーブルが変わり、`testdata/basic.nft` もこの行を含む形に改めた。
  解釈器は IPv4 の印を持つ行を IPv6 のパケットに一致させない。
  IPv6 の送信元の出来事は、kernel では行に一致せず DNAT もされず、Go の評価器では拒まれるので、両方の評価器で `drop` になる。
  この一致を使い、IPv6 のフローがトークンを使わず、後の IPv4 の通信が各レートの burst を使い切れることを確かめる fixture を加えた。
  許容差は要らない

- `Relay` のルールに Admission Policy のすべての段を適用する(2026-09-20、7a.9 節の移行の手順 4):`Relay` のルールは、それまで kernel モードで送信元ごとの同時フロー数の行だけを持ち、userspace モードでは deny と allow だけを中継が判定してレートを評価していなかった。
  7a.9 節の「`Forwarding` の値によって Admission Policy の意味は変わらない」に合わせ、両モードで全段を適用した。
  kernel モードでは、待ち受けを開けている `Relay` のポートに `Transparent` と同じ段の行を付け、set の連番も `Relay` のポートで進めるようにした。
  `Relay` のルールを含む設定では `wgft server nft` が示す set の番号が変わり、レートと送信元ごとの同時フロー数で拒む接続は accept の後に閉じられる代わりに nftables で捨てられる。
  クライアントには RST ではなく時間切れとして見えるので、この差を許容差 `rejection_visibility` として扱う。
  userspace モードでは、`proxyrelay` の受け付けが評価器の `AdmitFlow` を呼び、拒んだ段の drop を数え、接続の終わりに送信元ごとの枠を返すようにした。
  手順 3 で置いた入口 `AdmitSourceFlow` は取り除いた。
  kernel モードの `proxyrelay` に残るのは deny と allow の状態を持たない確認だけで、その拒否は drop に数えない。
  暫定の fixture(`relay_src_flow_only_until_step4`)を最終の挙動に書き直して `relay_shared_per_source_cap` に改め、`Relay` のルールの 2 つのレートを確かめる fixture を加えた。
  `Transparent` だけの設定の生成は変わらず、ゴールデンの `testdata/basic.nft` は `Relay` のルール(`r_proxy`)の deny の行と、それに伴う set の連番だけが変わった。
  TCP のルールの `packet` の行は手順 5 に残る
