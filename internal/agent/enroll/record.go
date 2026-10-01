package enroll

import (
	"encoding/hex"

	"github.com/rahanahu/wgft/internal/agent/credentials"
)

// Record は登録の結果を認証情報に写す。初回の登録(internal/agent の ensureRegistered)と登録のし直し
// (recover)が共有する。排他は取らない。recover は rt.mu を持ったまま呼び、保存も呼び出し側が行う。
func Record(f *credentials.Credentials, j *Join, tok, addr, name string) {
	f.Name, f.Endpoint, f.PermanentToken = name, j.Endpoint, tok
	f.CertSHA256 = hex.EncodeToString(j.Pin[:])
	f.UsedJoinTokenSHA256 = j.TokenHash()
	f.TunnelAddress = credentials.RegisteredTunnelAddress(addr)
}
