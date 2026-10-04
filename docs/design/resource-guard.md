<!-- docs-status: deprecated -->

# Resource Guard

新規フローは、Admission Policy に通った後に、共有予算、ルールの上限、登録の最低分と予備で判定します。

現行の各仕様は[Resource Guardの索引](resource/README.md)から参照できます。

<details>
<summary>旧見出しの参照先</summary>

- <a id="7a10-resource-guard-の再設計"></a> [7a10-resource-guard-の再設計](resource/admission.md#7a10-resource-guard-の再設計)
- <a id="判定の位置と範囲"></a> [判定の位置と範囲](resource/admission.md#判定の位置と範囲)
- <a id="型の分割"></a> [型の分割](resource/admission.md#型の分割)
- <a id="共有プール最低分と予備"></a> [共有プール最低分と予備](resource/admission.md#共有プール最低分と予備)
- <a id="退役した登録のフローの帰属"></a> [退役した登録のフローの帰属](resource/admission.md#退役した登録のフローの帰属)
- <a id="最低分と予備の性質"></a> [最低分と予備の性質](resource/admission.md#最低分と予備の性質)
- <a id="既定値と今の挙動との対応"></a> [既定値と今の挙動との対応](resource/reporting.md#既定値と今の挙動との対応)
- <a id="拒否の報告"></a> [拒否の報告](resource/reporting.md#拒否の報告)
- <a id="メモリのソフト上限との関係"></a> [メモリのソフト上限との関係](resource/integration.md#メモリのソフト上限との関係)
- <a id="kernel-側の保護"></a> [kernel-側の保護](resource/integration.md#kernel-側の保護)
- <a id="agent-への適用"></a> [agent-への適用](resource/integration.md#agent-への適用)
- <a id="phase-6-の移行の手順"></a> [phase-6-の移行の手順](https://github.com/rahanahu/wgft/blob/c5a6dc454468733e9ff4b2a4eb2b5a17ed4bdf4e/docs/design.md#phase-6-の移行の手順) <!-- docs-history -->
- <a id="利用者から見て変わらないものと変わるもの"></a> [利用者から見て変わらないものと変わるもの](https://github.com/rahanahu/wgft/blob/c5a6dc454468733e9ff4b2a4eb2b5a17ed4bdf4e/docs/design.md#利用者から見て変わらないものと変わるもの-1) <!-- docs-history -->
- <a id="ホストで確かめることとラボで確かめること"></a> [ホストで確かめることとラボで確かめること](resource/validation.md#ホストで確かめることとラボで確かめること)

</details>
