# 文書の索引

導入手順は[セットアップガイド](setup.ja.md)を参照してください。[設計文書の索引](design.md)には、従来の節番号と参照先を残しています。

## 利用者向けの手順

| 話題 | 文書 |
| --- | --- |
| 導入 | [Linux のセットアップ](setup.ja.md)、[環境別の導入](setup-alternatives.ja.md)、[Docker](setup-docker.ja.md)、[デスクトップのエージェント](setup-desktop.ja.md)、[VPS のユーザー空間モード](setup-server-userspace.ja.md) |
| 運用 | [運用ガイド](operations.ja.md)、[CLI リファレンス](cli.md)、[ソケットバッファ](socket-buffers.ja.md) |
| 開発 | [アーキテクチャ](architecture.md)、[テスト](testing.md)、[Linux エージェントのカーネルモード](agent-kernel.ja.md) |

英語の利用者向け文書は[英語の索引](README.md)から参照できます。

## 設計仕様

| 節 | 文書 |
| --- | --- |
| 背景と 1-5 節: 範囲、構成、用語、ネットワーク、制御プレーン | [全体像と制御プレーン](design-overview.md) |
| 6 節: VPS 側のデータプレーン | [VPS 側のデータプレーン](design-vps-dataplane.md) |
| 7 節: 自宅側のデータプレーンとメモリの上界 | [エージェントのデータプレーン](design-agent-dataplane.md) |
| 7a.1-7a.8 節: 層、失敗の意味論、移行 | [内部アーキテクチャ](design-internals.md) |
| 7a.9 節: Admission Policy のコンパイラ | [ポリシーのコンパイル](design-policy.md) |
| 7a.10 節: Resource Guard | [Resource Guard](design-resource-guard.md) |
| 7a.11 節: 互換性の保証 | [互換性](design-compatibility.md) |
| 7b 節: Linux エージェントのカーネルモード | [エージェントのカーネルデータプレーン](design-agent-kernel.md) |
| 8-9 節: 接続元 IP と状態の保存 | [アドレスと状態](design-state.md) |
| 10.1-10.2、10.3-10.5 節: 操作インタフェース | [操作インタフェース](design-interface.md) |
| 10.2a 節: server doctor | [サーバの診断](design-server-doctor.md) |
| 10.2b 節: status | [状態の要約](design-status.md) |
| 10.2c 節: agent doctor | [設計文書の索引](design.md#102c-エージェント側の診断-wgft-agent-doctor) |
| 10.2d 節: Web UI の診断 | [Web UI の診断](design-web-doctor.md) |
| 11-11b 節: セキュリティ、設定、起動時の失敗 | [セキュリティと設定](design-security.md) |
| 12-13 節: マイルストーンと未決事項 | [マイルストーンと未決事項](design-roadmap.md) |
| 改訂の記録 | [改訂の記録](design-revisions.md) |
