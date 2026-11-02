# v2: Rust への移行

v2 は、agent と server の両方を Rust で書き直し、製品から Go を取り除く版です。
この文書は移行の決定事項を定めます。
Rust のコードは `crates/` 以下にあり、ビルドと検査は[テストの規範](../../development/testing.md)の B13 から B15 に従います。
実装済みのものは agent のユーザー空間モードとその周りのコマンドで、wire の版 1 の型、WireGuard の device の層、wgstack の Rust 版、データプレーン、トンネルの送受信のバッチ、中継、制御プレーンを含みます。
server と agent のカーネルモードは未実装です。

## 動機

ガベージコレクションを持つ実行環境では、保持するメモリの上界を導き、小さなホストで保ち続けることが難しくなります。
wgft は agent と server の資源を有限に保つことを設計の中心に置くため、実行環境が上界の導出を妨げない言語へ移します。
Go 製の v1 系は、この移行の間も動作を変えません。

## 移行の順序

1. agent のユーザー空間モードを Rust にします。相手は変更しない v1 の server です。
2. server を Rust にします。kernel モード、ユーザー空間モードの順です。
3. agent の kernel モードを最後に Rust にします。

1 つのバイナリの中で Go と Rust を結合する段階 (C ABI による結合) は作りません。
各段階は v1 の server と agent に対して相互運用を確かめてから進めます。

## 変えないもの

移行の間、wire の版は 1 のまま、`agent.json` と server のデータベースの形式も変えません。
Rust の agent は、v1 の `agent.json` をそのまま読み、wire の版 1 を話します。
形式は言語に依らない仕様として定めます。
仕様は[境目の仕様 (wire の版 1)](../spec/README.md)にあります。
server と話す制御の部分の設計は [Rust の agent の制御プレーン](agent-control.md) にあります。
WireGuard の通信を暗号化する層の設計は [agent の WireGuard の device の層](wireguard-device.md) にあります。

## 配布

v2.0.0 まで、Rust の成果物は配布しません。
Rust のビルドは CI と開発者のホストにだけ存在し、リリースのワークフローは変えません。
v1.x は Go のまま保守だけを続けます。
コード署名は行いません。

## agent の置き換え

Rust の agent が Go の v1 の agent のユーザー空間モードを置き換えるための設計は、[Rust の agent が Go の agent を置き換えるための設計](agent-parity.md)にあります。
速さを制限しない経路の基準の値と、トンネルの送受信をまとめる設計 (バッチ) の目標と規則は、[速さを制限しない経路の agent の性能](agent-throughput.md)にあります。
WireGuard の暗号を別のスレッドでも行う設計 (評価中) は、[データプレーンの暗号の作業者](agent-crypto-workers.md)にあります。

## 文書の一覧

この節の文書は、必要な分野だけを読みます。

| 文書 | 定めるもの | 読まなくてよい場合 |
|---|---|---|
| [agent の置き換え](agent-parity.md) | Go の agent の置き換えの完成の条件、UDP の中継、データプレーンの送る経路、メモリの上界の行、CLI と設定、ラボの切り替え | WireGuard の層か核だけを変える場合は、該当の節だけで足ります |
| [Rust の agent の制御プレーン](agent-control.md) | server と話す制御の部分 | データプレーンだけを変える場合 |
| [agent の WireGuard の device の層](wireguard-device.md) | sanstun の上の sans-IO の device、キュー、ハンドシェイクの規則 | 核と中継だけを変える場合 |
| [wgstack の Rust 版](wgstack-rs.md) | 核の API、データプレーンの駆動、メモリ、SYN cookie、検証、qbench | device の層と制御プレーンだけを変える場合 |
| [速さを制限しない経路の agent の性能](agent-throughput.md) | 速さと byte あたりの CPU の基準の値、バッチの目標と規則と作り、判定の手順 | 性能に関わらない変更では不要です |
| [データプレーンの暗号の作業者](agent-crypto-workers.md) | 暗号を別のスレッドでも行う設計 (評価中)、device の層の段に分けた口、判定 | 暗号の作業者に関わらない変更では不要です |
| [v2 の試験の道具](test-tooling.md) | 台本、runner、DUT の口、Go の wgstack の記録、qbench、fuzz、関門 | 製品のコードだけを変える場合は、関門の節だけで足ります |
| [メモリの上界の表 (agent)](agent-bound.md) と [同 (wgstack)](wgstack-bound.md) | 試験が生成する表で、手で読む必要はありません | 上界の式を変えない場合は不要です |

## 設計の制約

- WireGuard は crates.io の `sanstun` を使います。使う範囲を 1 つのモジュールに閉じ込め、wgft 自身の型でその外と話します。差し替えのための抽象と、2 つ目の実装は作りません。
- 依存は寛容なライセンスだけにします。MPL-2.0 と、GPL 系と LGPL は許可しません。許可の一覧は `deny.toml` が持ち、B15 が検査します。
- データプレーンの核は sans-IO にします。入力は時刻、パケット、操作で、出力はパケット、次に起きる時刻、イベントです。核の中にスレッド、実時間のタイマー、ソケットを置きません。
- 制御プレーン (HTTP、WebSocket、SQLite、CLI) は通常の非同期の実行環境 (tokio) で書きます。

## テスト

実ネットワークのインタフェースを通して製品を外から確かめるテストは、Go のまま残して構いません。
内部に触れる必要のあるテストは Rust に移します。
試験の道具 (データにした台本、2 つの runner、Rust の DUT を叩く標準入出力の口、凍結した Go の wgstack の記録との照合、qbench、fuzz、関門) の設計は[v2 の試験の道具](test-tooling.md)にあります。

## Go の wgstack

Go の wgstack は参照実装として凍結し、移行の間に機能を足さず、Rust の実装が追いついた後に消します。
v2 の Rust の agent は `WGFT_AGENT_NETSTACK=gvisor` を受け付け、wgstack の Rust 版を動かして 1 行の通知を出します。
Rust 版の構造、API、メモリ、検証は [wgstack の Rust 版](wgstack-rs.md) にあります。

[日本語の設計の索引](../README.ja.md)
