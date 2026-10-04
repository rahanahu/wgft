<a id="7b-データプレーン自宅側カーネルモード"></a>
## データプレーン(自宅側、カーネルモード)

エージェントのカーネルモードは、Linux のエージェントが、カーネルの WireGuard インタフェースと nftables の DNAT で LAN の宛先へ転送するモードである(2026-09-24、所有者の決定)。
エージェントのプロセスは制御プレーンとカーネルの設定の収束を担い、パケットを中継しません。
このため、エージェントの停止中や更新の間も、カーネルに残した設定で転送が続く。
この節は決定と外部から見える面を骨格として定め、内部の作りは各段の実装がこの節に書き加えます。

カーネルモードは、ユーザー空間モード([7 節](agent-dataplane.md#7-データプレーン自宅側))と同じ「転送できる」「転送できない」の意味を保つ。
ルールの `ok` と `error`([5.2 節](control/connection.md#52-全体状態の配信とハートビート))、宛先の変更と削除で成立済みのフローが切れるかどうか([7 節](agent-dataplane.md#7-データプレーン自宅側)の収束の表)、宛先の許可一覧が守る範囲は、モードで変わりません。
backend 全体の失敗とルール単位の失敗は [7a.3 節](architecture/lifecycle.md#7a3-状態遷移と失敗の意味論)のとおり分けて扱い、混ぜない。

## 関連する仕様

- [kernel エージェント](kernel-agent/README.md)

<details>
<summary>旧見出しの参照先</summary>

- <a id="7b1-カーネルに置くもの"></a> [7b1-カーネルに置くもの](kernel-agent/installation.md#7b1-カーネルに置くもの)
- <a id="7b2-宛先の扱い"></a> [7b2-宛先の扱い](kernel-agent/targets.md#7b2-宛先の扱い)
- <a id="7b3-ルールの状態と失敗の種類"></a> [7b3-ルールの状態と失敗の種類](kernel-agent/targets.md#7b3-ルールの状態と失敗の種類)
- <a id="7b4-収束と停止"></a> [7b4-収束と停止](kernel-agent/lifecycle.md#7b4-収束と停止)
- <a id="7b5-権限と配置"></a> [7b5-権限と配置](kernel-agent/operations.md#7b5-権限と配置)
- <a id="7b6-server-との関係"></a> [7b6-server-との関係](kernel-agent/operations.md#7b6-server-との関係)
- <a id="7b7-未確認の点"></a> [7b7-未確認の点](kernel-agent/limits.md#7b7-未確認の点)

</details>
