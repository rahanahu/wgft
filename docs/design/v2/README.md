# v2: Rust への移行

v2 は、agent と server の両方を Rust で書き直し、製品から Go を取り除く版です。
この文書は移行の決定事項を定めます。
Rust のコードは `crates/` 以下にあり、ビルドと検査は[テストの規範](../../development/testing.md)の B13 から B15 に従います。
実装済みのものはワークスペース、CI、wire の版 1 の型 (`crates/wgft-proto`)、WireGuard の device の層です。
設計の制約のうち、WireGuard の隔離と sans-IO の核は device の層で実装しました。
ほかの決定は未実装です。

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
server と話す制御の部分の試作の設計は [Rust の agent の制御プレーン](agent-control.md) にあります。
WireGuard の通信を暗号化する層の設計は [agent の WireGuard の device の層](wireguard-device.md) にあります。

## 配布

v2.0.0 まで、Rust の成果物は配布しません。
Rust のビルドは CI と開発者のホストにだけ存在し、リリースのワークフローは変えません。
v1.x は Go のまま保守だけを続けます。
コード署名は行いません。

## agent の置き換え

Rust の agent が Go の v1 の agent のユーザー空間モードを置き換えるまでに要るものと段の計画は、[Rust の agent が Go の agent を置き換えるための設計](agent-parity.md)にあります。

## 設計の制約

- WireGuard は crates.io の `sanstun` を使います。使う範囲を 1 つのモジュールに閉じ込め、wgft 自身の型でその外と話します。差し替えのための抽象と、2 つ目の実装は作りません。
- 依存は寛容なライセンスだけにします。MPL-2.0 と、GPL 系と LGPL は許可しません。許可の一覧は `deny.toml` が持ち、B15 が検査します。
- データプレーンの核は sans-IO にします。入力は時刻、パケット、操作で、出力はパケット、次に起きる時刻、イベントです。核の中にスレッド、実時間のタイマー、ソケットを置きません。
- 制御プレーン (HTTP、WebSocket、SQLite、CLI) は通常の非同期の実行環境 (tokio) で書きます。

## テスト

実ネットワークのインタフェースを通して製品を外から確かめるテストは、Go のまま残して構いません。
内部に触れる必要のあるテストは Rust に移します。

## Go の wgstack

Go の wgstack は参照実装として凍結し、移行の間に機能を足さず、Rust の実装が追いついた後に消します。
v2 では `WGFT_AGENT_NETSTACK=gvisor` を受け付け、wgstack の Rust 版を動かして 1 行の通知を出します。
この挙動は未実装です。

[日本語の設計の索引](../README.ja.md)
