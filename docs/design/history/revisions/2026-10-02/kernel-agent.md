<!-- docs-status: historical -->

移動元: [docs/design/revisions.md](https://github.com/rahanahu/wgft/blob/8875f37e04e2576fed740c62e6a96a29a51e46b7/docs/design/revisions.md)。
基準コミットは `8875f37e`、元の行範囲は 378-379, 382-383 です。

# 2026-10-02: kernel-agent

- エージェントのカーネルモードの dataplane を `internal/agent` の外へ移す準備をした(2026-10-02、7a.7 節。
  挙動は変えていない):カーネルモードの実装のファイルのうち、`internal/agent` の残りの部分の非公開の名前を使うのは、`agent doctor` の応答の文字列を切る関数だけだった。
  応答に載せる 1 つの文字列の長さの上限(512 バイト)を `internal/agent/controlapi` の定数にし、実行時の状態の側とカーネルの読み取りの側が、それぞれ同じ値で切る同じ 1 行の関数を持つようにした。
  カーネルモードの dataplane を組む関数を、カーネルと名前解決への操作を受け取る関数と、それに本番の操作を渡す関数に分けた。
  試験は偽のカーネルの操作を前者に渡して dataplane を組み、非公開のフィールドを並べて構造体を直接組まない。
  組んだ値は前と同じである。
  hub の切り詰めの長さと応答の上限が等しいことを確かめる試験は、新しい定数と比べる。
  宣言の本文は、これらの箇所を除いて変えていない。


- エージェントのカーネルモードの dataplane を `internal/agent/kernelmode` へ移した(2026-10-02、7a.7 節。
  挙動は変えていない):カーネルモードの実装と、停止中の `agent doctor` が使うカーネルの読み取りのファイルを、新しい package へそのまま移した。
  名前を変えたのは、`internal/agent` の本番のコード、`cmd/wgft`、`internal/agent` のテストが使う名前だけで、どれも公開の名前にした。
  実行時の状態とカーネルモードを組み合わせるテストは、実行時の状態の型が非公開なので `internal/agent` に残る。
  カーネルの偽物と補助は、`internal/agent` と `kernelmode` に同じものを 1 つずつ置いた。
  `kernelmode` のテストは `internal/agent` を import できず、`internal/agent` のテストは `kernelmode` のテストのファイルに届かないためである。
  2 つは修飾子と package と import の行だけが違う。
  理由の文言を server doctor に読ませるテストも `kernelmode` へ移し、それが使う `internal/agent` のテストの補助を写した。
  テストのためだけの口を `internal/dataplane/deps_test.go` の `modeTestSeams` に列挙し、モードの package が公開する名前をどちらかの一覧に必ず載せるよう、`TestAgentModeTestSeamsStayInTests` を広げた。
  `TestAgentModesStayApart` は、カーネルモードの import の範囲と、`internal/agent` 自身がカーネルの層を直接 import しないことも検査する。
  この 2 つの検査が本番のファイルだけを読み、直接の import の規則は推移的な依存を見ないことを 7a.7 節に書いた。
  移した宣言は、移す前と比べて、名前の変更と修飾子と注釈を除いて同じだった。
  違いは、変えた名前を含む試験の失敗の文言だけだった。
  比べたのは Linux、Windows、macOS のビルドである。
  テストの名前の集合は移す前と同じだった。
  テストのための口を本番のコードが使うと `TestAgentModeTestSeamsStayInTests` が落ち、許していない import を加えると `TestAgentModesStayApart` が落ちた。
  ラボでは、カーネルモードのエージェントの確認と `agent doctor` の確認が通った。
  口の検査の外にあることは次のとおりである。
  本番のコードが使ってよい変数 `Prerequisites` に `kernelmode` の外の本番のコードが代入しても、口の検査は落ちない。
  `lab` の build tag を持つ本番のファイルは口の検査の型検査に入らない。
  今は該当するファイルが無い。
  呼び出し側が定める interface への型アサーションや reflection による使用も検査の外である。
  未確認:`ReadKernel` が受け取るインタフェースの名前と `ProcessNetAdmin` の結果は、移す前から単体テストが固定していない。
  ラボの `agent doctor` の確認がこの 2 つの誤りを捉えるかどうかは確かめていない。
