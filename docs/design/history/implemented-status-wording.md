<!-- docs-status: historical -->

# 導入時の状態が残っていた仕様の記述

移動元: [docs/design/architecture/lifecycle.md](https://github.com/rahanahu/wgft/blob/a8260eb8812e4c7eafd2a662d7dfa1236a514d54/docs/design/architecture/lifecycle.md)。
基準コミットは `a8260eb8`、元の行範囲は 33, 35, 38 です。
移動元: [docs/design/architecture/model.md](https://github.com/rahanahu/wgft/blob/a8260eb8812e4c7eafd2a662d7dfa1236a514d54/docs/design/architecture/model.md)。
基準コミットは `a8260eb8`、元の行範囲は 114, 124, 126, 142 です。
移動元: [docs/design/architecture/packages.md](https://github.com/rahanahu/wgft/blob/a8260eb8812e4c7eafd2a662d7dfa1236a514d54/docs/design/architecture/packages.md)。
基準コミットは `a8260eb8`、元の行範囲は 73, 77 です。
移動元: [docs/design/architecture/wire-compatibility.md](https://github.com/rahanahu/wgft/blob/a8260eb8812e4c7eafd2a662d7dfa1236a514d54/docs/design/architecture/wire-compatibility.md)。
基準コミットは `a8260eb8`、元の行範囲は 21, 23, 26, 37, 38, 39, 44 です。
移動元: [docs/design/compatibility/surfaces.md](https://github.com/rahanahu/wgft/blob/a8260eb8812e4c7eafd2a662d7dfa1236a514d54/docs/design/compatibility/surfaces.md)。
基準コミットは `a8260eb8`、元の行範囲は 18 です。
移動元: [docs/design/diagnosis/agent-output.md](https://github.com/rahanahu/wgft/blob/a8260eb8812e4c7eafd2a662d7dfa1236a514d54/docs/design/diagnosis/agent-output.md)。
基準コミットは `a8260eb8`、元の行範囲は 28 です。
移動元: [docs/design/kernel-agent/operations.md](https://github.com/rahanahu/wgft/blob/a8260eb8812e4c7eafd2a662d7dfa1236a514d54/docs/design/kernel-agent/operations.md)。
基準コミットは `a8260eb8`、元の行範囲は 24 です。
移動元: [docs/design/kernel-agent/targets.md](https://github.com/rahanahu/wgft/blob/a8260eb8812e4c7eafd2a662d7dfa1236a514d54/docs/design/kernel-agent/targets.md)。
基準コミットは `a8260eb8`、元の行範囲は 49 です。
移動元: [docs/design/resource/integration.md](https://github.com/rahanahu/wgft/blob/a8260eb8812e4c7eafd2a662d7dfa1236a514d54/docs/design/resource/integration.md)。
基準コミットは `a8260eb8`、元の行範囲は 20, 24, 43, 45, 56, 86 です。
移動元: [docs/design/resource/reporting.md](https://github.com/rahanahu/wgft/blob/a8260eb8812e4c7eafd2a662d7dfa1236a514d54/docs/design/resource/reporting.md)。
基準コミットは `a8260eb8`、元の行範囲は 16, 94, 96 です。
移動元: [docs/design/resource/validation.md](https://github.com/rahanahu/wgft/blob/a8260eb8812e4c7eafd2a662d7dfa1236a514d54/docs/design/resource/validation.md)。
基準コミットは `a8260eb8`、元の行範囲は 34, 49, 50, 53, 57 です。
移動元: [docs/design/roadmap.md](https://github.com/rahanahu/wgft/blob/a8260eb8812e4c7eafd2a662d7dfa1236a514d54/docs/design/roadmap.md)。
基準コミットは `a8260eb8`、元の行範囲は 14 です。
移動元: [docs/design/state.md](https://github.com/rahanahu/wgft/blob/a8260eb8812e4c7eafd2a662d7dfa1236a514d54/docs/design/state.md)。
基準コミットは `a8260eb8`、元の行範囲は 53-54 です。
移動元: [docs/design/userspace/tcp-host-sockets.md](https://github.com/rahanahu/wgft/blob/a8260eb8812e4c7eafd2a662d7dfa1236a514d54/docs/design/userspace/tcp-host-sockets.md)。
基準コミットは `a8260eb8`、元の行範囲は 132, 136 です。

以下は、現在の実装との照合で導入時の状態が残っていた記述です。
現在の仕様は[設計仕様の索引](../README.ja.md)から参照できます。

## 1. architecture/wire-compatibility.md

wire protocol の版と機能の交渉は、既存のメッセージへ次のフィールドを追加するだけで足りる。

## 2. architecture/wire-compatibility.md

を追加します

## 3. architecture/wire-compatibility.md

を追加します

## 4. architecture/wire-compatibility.md

版のフィールドを持たない実装(今の実装)は、legacy v0 として別に扱う。

## 5. architecture/wire-compatibility.md

server は今の形の全体状態を送る。

## 6. architecture/wire-compatibility.md

今の機能だけを使います。

## 7. architecture/wire-compatibility.md

版の番号は 1 から始める。

## 8. architecture/wire-compatibility.md

これにより、通常の rolling upgrade(server と agent のどちらを先に上げても)が通る。

## 9. diagnosis/agent-output.md

項目の一覧は、実装のときに定める

## 10. compatibility/surfaces.md

診断の報告の型は、[10.2d 節](../web-doctor.md#102d-web-ui-の診断の画面)のとおり Web UI と共有する姉妹 package へ移るので、CLI 専用ではありません。

## 11. roadmap.md

| 管理 UI の public 待ち受け | 公開の管理経路を提供しません | 必要になった場合の条件はセキュリティ仕様に定めます |

## 12. architecture/model.md

現在の実装から新しい層への対応は次のとおりです。

## 13. architecture/model.md

| 現在の実装 | 新しい層 | 備考 |

## 14. architecture/model.md

今この骨格を使うのは server であり、agent は `Runtime` へ移った後に同じ骨格を使う([7a.7 節](../architecture/packages.md#7a7-package-配置))。

## 15. architecture/model.md

| `internal/dataplane/userspace/relay`(Phase 2 で `internal/agent/relay` から移した)の `plan`/`Action` | `internal/reconcile` の骨格のひな型 | この型を `internal/reconcile` に一般化する。agent が `Runtime` へ移った後は、server と agent で共有する |

## 16. resource/validation.md

- 手順 2 で、今の実装と通す・拒むが一致すること、手順 3 で `proxyrelay` の拒否が RST になること(ループバックのソケットで確かめられる)

## 17. resource/validation.md

  agent のルールごとの上限を「`WGFT_MAX_TCP_FLOWS` の半分」と書いた説明を改める

## 18. resource/validation.md

- 手順 6 の隔離:check 5c から 5e の期待値を改める。

## 19. resource/validation.md

- 手順 6 の拒否の理由:

## 20. resource/validation.md

- 手順 6 の帰属の規則:

## 21. resource/integration.md

Phase 6 はこの役割を変えません。

## 22. resource/integration.md

Phase 6 はこれらに新しい上限を加えない。

## 23. resource/integration.md

Phase 6 のこの段で、同じ判定を `ip_forward` と同じ起動時のログにも出すようにした。

## 24. resource/integration.md

Phase 6 は変えません。

## 25. resource/integration.md

agent の kernel dataplane(Phase 7)では、

## 26. resource/reporting.md

Phase 6 の式には使いません。

## 27. resource/reporting.md

Web UI の表示は Phase 6 では変えません。

## 28. architecture/lifecycle.md

[6.1 節](../vps/kernel.md#61-カーネルモード)が述べるとおり、この手順でも SQLite には新しい宣言(`Desired`)が既に保存されているのに、nftables への適用(`Commit`)だけが失敗する瞬間が生じる。今の実装は、この失敗を `log.Printf` で記録し、その場の管理用 API 呼び出しへのエラー応答として返すだけである(`internal/vpsd/apply.go` の `applyNFT`、`admin_backend.go` の `Batch`)。呼び出し元がその応答を見送れば、SQLite に保存された宣言と実際に転送しているルールとの食い違いは、どこにも残らない。これが埋めるべき隙間である。

## 29. architecture/lifecycle.md

新しいアーキテクチャでは、制御プレーンが `Desired` と `Active` の両方を持ちます。

## 30. architecture/lifecycle.md

今はこの理由がログにしか残りません。

## 31. architecture/packages.md

v1.2 はこの形を保ったまま、`internal/agent` の中に狭い dataplane の境目を切り、その後ろにユーザー空間モードとカーネルモードの 2 つの実装を置く(2026-09-24、所有者の決定)。

## 32. architecture/packages.md

agent を `Runtime` へ移すのは後の段階とします。

## 33. userspace/tcp-host-sockets.md

送り残しと同じく、v1.3.0 の後の設計に含めます

## 34. userspace/tcp-host-sockets.md

v1.3.0 の後に送信の側と閉じた後のソケットの扱いを設計し直す

## 35. kernel-agent/operations.md

Docker:v1.2 ではカーネルモードの手順を書かない

## 36. kernel-agent/targets.md

切り替えと振り分けはカーネルの DNAT に新しい機能を足すことになるので、v1.2 では扱わない

## 37. state.md

対象は動作モード(`kernel`。
  `userspace` は [13 節](../roadmap.md#制限と未実装の提案))と wg のアドレス帯。

## 38. resource/reporting.md

admin API には、既存のフィールドを変えずに次の 2 つを加えます。

## 39. resource/integration.md

  管理用 API と Web UI への表示は、他の nftables の Finding(`ip_forward` を含む)と同じくこの段の対象外であり、今もログだけです
