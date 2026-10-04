<a id="5-制御プレーン"></a>
## 制御プレーン

制御の接続はエージェントから server への外向き HTTPS です。
登録、stream、ルールの管理は別の責務として扱います。


制御プレーンは常にエージェントから `vpsd` への外向き HTTPS で行います。
`vpsd` からエージェントへ接続を張ることはありません。

`vpsd` は 2 つのリスナーを持ちます。

- **エージェント用 API**:公開。
  `/api/v1/agents/register` と `/api/v1/agents/stream` だけを露出します。
  TLS 証明書は `vpsd` が初回起動時に生成する有効期限 10 年の自己署名証明書で、秘密鍵ごと SQLite に保存します
- **管理用 API**:既定は Unix ソケット。
  Web UI と CLI が使います。
  独自の認証は持たず、接続経路(ソケットのパーミッション、SSH、Tailscale)に任せる([11 節](../security/admin-transport.md#11-セキュリティ))

エージェント用 API を wg 経由に切り替えない理由は、wg が落ちたときに制御まで落ちると復旧の手がかりが減るからです。

## 制御の責務

- [ルールのバッチ操作](batches.md)
- [全体状態の配信とハートビート](connection.md)
- [ハートビートと到達性](heartbeat.md)
- [stream の生死と再接続](liveness.md)
- [全体状態の配信](publication.md)
- [登録](registration.md)
- [ルールのスキーマ](rules.md)
- [全体状態の wire 形式](state-wire.md)
- [複数サービスへの配り方](targets.md)
- [接続元 IP の食い違いと往復](warnings.md)

[制御プレーン](README.md)
