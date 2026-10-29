package wgstack

import "os"

// streamSeedsFull は、乱数の stream の試験を段階の関門の回数(受信 2000、送信 600)で流すかを返す。既定は
// 受信 100、送信 80 で、WGFT_WGSTACK_STREAM_SEEDS=full のときだけ全部を流す。送信の既定は、レビューで
// 中身を壊す変異が落ちた種(37、43、49)より余裕を持たせる。
func streamSeedsFull() bool { return os.Getenv("WGFT_WGSTACK_STREAM_SEEDS") == "full" }
