<!-- docs-status: historical -->

# 2026-10-02: server-doctor

- ルールの理由の文言のうち、理由を書く側と `server doctor` が共有する断片を `internal/reasontext` に置いた(2026-10-02、7a.7 節。
  挙動は変えていない):`server doctor` は、エージェントと server が書くルールの理由を部分一致で分類する(10.2a 節)。
  分類に使う断片は、書く側と読む側に別々の文字列として書かれていた。
  名前の解決の失敗、直前の解決の結果で転送を続けている目印、許可一覧の拒否と設定の名前、宛先への試し接続が期限までに応えなかったこと、bind の失敗、ループバックの宛先、`ip_forward`、server が公開しなかったルールの理由である。
  片側だけで言い回しを変えると、分類が黙って変わる形だった。
  断片を葉の package `internal/reasontext` に置き、両側がそれを使うようにした。
  値は変えていないので、稼働中の別の版のエージェントの理由も今までどおり分類する。
  許可一覧の設定の名前もこの package に置いたので、`internal/vpsd/doctor` は `internal/agent/allowtargets` を import しなくなった。
  2 つの制御プレーンが互いを import しないことを、`TestControlPlanesDoNotImportEachOther` が検査する。
  書く側が実際に組み立てる理由を `server doctor` に読ませる単体試験を、エージェントと server の両方に置いた。
  エージェントの理由は、hub が保存する形(`stream.HeartbeatReason` の切り詰め)に通してから読ませる。
  この試験で、この変更より前からある問題を確かめた。
  名前の解決に失敗して直前の解決の結果で転送を続けているルールの理由は、ホスト名を 2 回含む。
  ホスト名が長いと、hub の 512 バイトの切り詰めが目印を落とし、`server doctor` は転送を続けているルールを `target resolve` で止まったと判定する。
  253 バイトのホスト名で確かめた。
  この変更では直していない。
  試験は今の挙動を固定し、既知の問題として印を付けた。
