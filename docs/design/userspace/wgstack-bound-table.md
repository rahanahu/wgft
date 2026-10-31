# wgstack の上界の表

この文書は `internal/wgstack` の `TestBoundDocUpToDate` が `Device.Bound` と構造の大きさから生成します。
手で直しません。
上界の式の項、構造の大きさ、表の大きさを変えたら次のコマンドで生成し直し、同じコミットに含めます。

```sh
go test ./internal/wgstack -run TestBoundDocUpToDate -update
```

式と項の意味は[上界の式](wgstack.md#上界の式)にあります。
値は 64 bit の Linux の build で求めます。
公開する target のどれでも構造の大きさが同じことは、[上界の式](wgstack.md#上界の式)の節にあります。
MiB は 1,048,576 byte です。

## 構造の大きさ

| 記号 | 意味 | byte |
|---|---|---|
| <a id="size-conn"></a>c_conn | 接続の枠 1 つの構造 | 5,440 |
| <a id="size-record"></a> | 送信の記録 1 件 | 32 |
| <a id="size-interval"></a> | 順序外の区間 1 つ | 16 |
| <a id="size-syn"></a>c_syn | 握手の途中の表の 1 行 | 80 |
| <a id="size-tw"></a>c_tw | TIME_WAIT の表の 1 行 | 64 |
| <a id="size-index"></a> | 握手の途中と TIME_WAIT の hash の表の 1 項目 | 20 |
| <a id="size-conn-index"></a> | 接続の hash の表の 1 項目(世代を含みます) | 28 |
| <a id="size-slot-runtime"></a> | 接続の枠 1 つが表の外に持つ構造として数える量 | 1,024 |

## 枠 1 つの項

値は確保の丸めを含めた byte の数です。

| 項 | 意味 | byte |
|---|---|---|
| <a id="slot-fs"></a>f_s | 送信の floor | 262,144 |
| <a id="slot-fr"></a>f_r | 受信の floor | 262,144 |
| <a id="slot-rf"></a>r_f | floor の送信の記録の輪 | 18,432 |
| <a id="slot-hf"></a>h_f | floor の順序外の区間の表 | 4,096 |
| <a id="slot-floor"></a>f_s + f_r + r_f + h_f | 接続の枠 1 つの floor の和 | 546,816 |
| <a id="slot-ds"></a>d_s | boost が送信の floor に加える分 | 3,932,160 |
| <a id="slot-dr"></a>d_r | boost が受信の floor に加える分 | 3,932,160 |
| <a id="slot-drec"></a>d_rec | boost の送信の記録の輪の全体 | 286,720 |
| <a id="slot-dh"></a>d_h | boost の順序外の区間の表の全体 | 65,536 |
| <a id="slot-boost"></a>d_s + d_r + d_rec + d_h | boost の枠 1 つの和 | 8,216,576 |

## 構成

| 構成 | 説明 |
|---|---|
| <a id="config-agent-k2048"></a>`agent-k2048` | エージェントの既定。K は 2048、U は 8192 で、P_max は 518 です |
| <a id="config-agent-k1024"></a>`agent-k1024` | エージェントで K を 1024 にした構成。U は 8192 で、P_max は 412 です |
| <a id="config-agent-k512"></a>`agent-k512` | エージェントで K を 512 にした構成。U は 8192 で、P_max は 360 です |
| <a id="config-agent-k256"></a>`agent-k256` | エージェントで K を 256 にした構成。U は 8192 で、P_max は 333 です |

## 構成ごとの上界

値は `Device.Bound` の欄で、単位は MiB です。
M_fix は、式の N_c × c_conn、N_syn × c_syn、M × c_tw、Q_ctl × s_ctl を含みます。
boost の項は、プロセスの boost の枠のすべてを 1 つの Device が持つとして数えます。

| 項 | 欄 | `agent-k2048` | `agent-k1024` | `agent-k512` | `agent-k256` |
|---|---|---|---|---|---|
| <a id="bound-k"></a>K |  | 2,048 | 1,024 | 512 | 256 |
| <a id="bound-nc"></a>N_c |  | 2,560 | 1,536 | 1,024 | 768 |
| <a id="bound-fix"></a>M_fix | `Fix` | 25.2 | 18.6 | 15.4 | 13.7 |
| <a id="bound-floor"></a>N_c × (f_s + f_r + r_f + h_f) | `FloorConn` | 1,335.0 | 801.0 | 534.0 | 400.5 |
| <a id="bound-boost"></a>B × (d_s + d_r + d_rec + d_h) | `Boost` | 125.4 | 125.4 | 125.4 | 125.4 |
| <a id="bound-udp-rx"></a>M_udp_rx | `UDPRx` | 4.4 | 4.4 | 4.4 | 4.4 |
| <a id="bound-udp-tx"></a>M_udp_tx | `UDPTx` | 4.1 | 4.1 | 4.1 | 4.1 |
| <a id="bound-frag"></a>M_frag | `Frag` | 4.0 | 4.0 | 4.0 | 4.0 |
| <a id="bound-ping"></a>N_ping × c_ping | `Ping` | 0.025 | 0.025 | 0.025 | 0.025 |
| <a id="bound-total"></a>和 | `Total` | 1,498.1 | 957.6 | 687.3 | 552.2 |
| <a id="bound-transient"></a>式の外の一時の保持 B × (f_s + f_r) | `Transient` | 8.0 | 8.0 | 8.0 | 8.0 |
