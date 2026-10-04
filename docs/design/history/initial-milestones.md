<!-- docs-status: historical -->

# 当初のマイルストーン

移動元: [docs/design/roadmap.md](https://github.com/rahanahu/wgft/blob/8875f37e04e2576fed740c62e6a96a29a51e46b7/docs/design/roadmap.md)。
基準コミットは `8875f37e`、元の行範囲は 1-11 です。

## 12. マイルストーン

1. `proto` のスキーマ(全体状態とルール)と `vpsd` の nftables 適用。
   ルールは JSON ファイルから読み、API なし
2. 登録 API、stream での公開鍵の宣言と全体状態の配信、エージェント。
   実際のゲームサーバで UDP と TCP が通ることを確認する。
   トークンの扱い(5.1 節)、サーバ秘密鍵の永続化、公開鍵の検証、stream の 1 本化とバックオフ、削除後の復帰経路、バッチ操作、状態ファイルの原子的な書き込みと flock、input チェーン、ハーフクローズ、エンドポイントの再解決、bind 中ポートの衝突検査はここで入れる
3. 接続元制限とレート制限。
   conntrack の収束手順、プロキシモードの中継を閉じる部品、カウンタの累積、`error` の再試行、wg0 属性の突き合わせ、IP の食い違いによる窃取の警告もここで入れる
4. Web UI
5. `vps_mode = proxy` と PROXY protocol
6. 既存のリバースプロキシから 443 を移し、そちらを停止する

2 が終われば当初の問題は解決しているので、3 以降は使いながら進める。
