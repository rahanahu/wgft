# 設計仕様

wgft は、VPS の公開ポートから WireGuard 経由で自宅へ TCP と UDP を転送します。
現行 main の仕様には、最新のリリース v1.4.1 の後の変更も含みます。
特定のリリースの動作を確認するときは、そのタグの文書を参照してください。
互換性の保証は Linux の server と agent、Windows 11 の実機で確認した範囲の Windows agent を対象とし、macOS agent は対象外です。

| 知りたいこと | 仕様と要点 |
| --- | --- |
| 何を公開できるか | [全体像](overview.md)と[ネットワーク](network.md): IPv4 の L4 転送を扱い、TLS 終端は自宅側で行います |
| 登録と設定の変更はどう届くか | [制御プレーン](control/README.md): 登録、stream、全体状態、ルールのバッチを分けます |
| VPS はどのように転送するか | [VPS の転送方式](vps/README.md): kernel の DNAT、TCP の proxy、userspace の中継を定めます |
| 自宅側の既定モードはどう動くか | [ユーザー空間の転送と資源](userspace/README.md): socket の条件、UDP/TCP の中継、予算、保持の限界を定めます |
| 停止中も転送できるか | [kernel エージェント](kernel-agent/README.md): Linux の転送面、収束、停止、未確認の配置を定めます |
| 宣言と実際の転送面をどう揃えるか | [内部構造](architecture/README.md): 状態遷移、失敗、wire と package の境界を定めます |
| 通信と資源の拒否はどう違うか | [Admission Policy](policy.md)と[Resource Guard](resource/README.md): 通信方針と backend の予算を分けます |
| 接続元と再起動時の状態はどう扱うか | [接続元 IP と状態](state.md): 送信元の見え方、状態の保存、所有の判定を定めます |
| 故障と運用の劣化をどう判断するか | [診断](diagnosis/README.md): server doctor、agent doctor、status と Web UI の責務を分けます |
| 管理の経路と起動をどう守るか | [接続の守り、設定、起動](security/README.md): 信頼の境界、優先順位、起動の拒否と再試行を定めます |
| 停止と撤去、ログはどう動くか | [操作インタフェース](interface.md)と[操作の設計](operations/README.md): CLI/Web UI と所有する資源の撤去を定めます |
| 更新後も何が維持されるか | [互換性](compatibility.md): 公開サーフェスごとの名前と意味を保証します |
| 未対応と未確認の範囲は何か | [制限と未実装の提案](roadmap.md): 実装予定の版を確約せず、現在の制限と提案を分けます |

## 設計の履歴

[過去の計画と改訂記録](history/README.md)には、移行の手順と当時のレビューを残しています。 <!-- docs-history -->
旧節番号のリンクは、[旧見出しの参照先](../design.md)から対応する仕様へ進めます。

[English index](README.md) · [文書の索引](../README.ja.md)
