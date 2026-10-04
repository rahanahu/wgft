# 利用者向けの手順

[English](README.md) | 日本語

Linux VPS に root 権限がある場合は、[Linux のセットアップ](setup.ja.md)で server と agent を常駐させ、最初のルールを追加します。
Windows、macOS、Docker、root 権限のない VPS では、[環境別の導入](setup-alternatives.ja.md)から手順を選びます。

| 目的 | 手順と確認できる内容 |
| --- | --- |
| Linux で最初の転送を作る | [Linux のセットアップ](setup.ja.md): バイナリ、systemd、登録、転送ルール、firewall を設定します。 |
| 別の環境に導入する | [環境別の導入](setup-alternatives.ja.md): [Windows と macOS の agent](setup-desktop.ja.md)、[Docker](setup-docker.ja.md)、[VPS のユーザー空間モード](setup-server-userspace.ja.md)を選びます。 |
| 管理画面を開き、TCP や HTTPS を転送する | [転送と運用](operations.ja.md): 管理 API への接続、PROXY protocol、転送先の制限を設定します。 |
| 通信が止まった箇所を調べる | [診断手順](troubleshooting.ja.md): VPS と agent の診断、結果の意味、未検査の通信、ログを確認します。 |
| 既存の登録を保って更新する | [更新手順](upgrade.ja.md): 保持するデータ、Linux のバイナリ交換、旧版へ戻す制限を確認します。 |
| Linux agent をカーネルモードにする | [カーネルモードのエージェント](agent-kernel.ja.md): 権限、LAN の転送先、設定、モードを戻す手順を確認します。 |
| Linux のバッファの警告を解消する | [ソケットバッファ](socket-buffers.ja.md): ホスト側の設定と再起動を確認します。 |
| wgft を削除する | [削除](operations.ja.md#削除): 転送状態の削除とデータの保持を選びます。 |
| コマンドの全オプションを確認する | [CLI リファレンス](../cli.md): ヘルプから生成した使用例と設定を確認します。 |

[文書の索引](../README.ja.md)
