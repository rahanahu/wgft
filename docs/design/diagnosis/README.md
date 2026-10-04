# 診断

server doctor は server から見た転送を、agent doctor は手元のホストの状態を診断します。
status は配置全体に運用者の対応が要るかを答えます。

- [制御ソケットの拡張](agent-control.md)
- [エージェント側の診断](agent-evidence.md)
- [総合判定を動かす検査](agent-judgment.md)
- [`host.forwarding` の判定](agent-kernel-host.md)
- [`dataplane.table` の判定](agent-kernel-table.md)
- [カーネルモードのエージェント](agent-kernel.md)
- [出力の形](agent-output.md)
- [範囲外](agent-scope.md)
- [検査の一覧と証拠の出どころ](server-evidence.md)
- [`agent.connection` が測るもの](server-failures.md)
- [転送の診断 (`server doctor`)](server-observations.md)
- [履歴](server-output.md)

[状態の要約](../status.md)と[Web UI の診断](../web-doctor.md)も参照できます。
