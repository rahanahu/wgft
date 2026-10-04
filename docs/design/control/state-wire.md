# 全体状態の wire 形式

全体状態には、そのエージェントの wg 設定とルールを載せます。
版の交渉が無い旧エージェントには、交渉に使う加算フィールドを載せません。


全体状態の形:

```json
{
  "generation": 42,
  "wg": {
    "server_pubkey": "...",
    "endpoint": "vps.example.com:51820",
    "address": "10.200.0.2/24",
    "mtu": 1420,
    "keepalive": 25,
    "udp_timeout": 30,
    "udp_timeout_stream": 120
  },
  "rules": [ ... ],
  "server_protocol_version": 1,
  "server_capabilities": []
}
```

`server_protocol_version`/`server_capabilities` は、agent が legacy v0 なら載らない(上記)。
`pubkey` メッセージの側も同じ形で `protocol_min`/`protocol_max`/`capabilities` を持つ([7a.6 節](../architecture/wire-compatibility.md#7a6-維持する外部仕様と互換性))。

[制御プレーン](README.md)
