package agent

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"reflect"
	"testing"

	"github.com/rahanahu/wgft/internal/agent/credentials"
)

// recordRegistration は、初回の登録と登録のし直しが認証情報に書く項目をすべて書き、それ以外の
// 項目には触れない。どちらの経路の試験も見ていない項目(Endpoint など)も、ここで 1 つずつ確かめる。
func TestRecordRegistrationWritesEveryField(t *testing.T) {
	pin := sha256.Sum256([]byte("server certificate"))
	j, err := ParseJoin(fmt.Sprintf("wgft://vps.example:7443/tok#sha256:%x", pin))
	if err != nil {
		t.Fatal(err)
	}
	f := &credentials.Credentials{
		Name: "old", Endpoint: "old.example:1", PermanentToken: "OLD", CertSHA256: "old-pin",
		UsedJoinTokenSHA256: "old-hash", TunnelAddress: "10.99.0.7/16", WGPrivateKey: "keep",
	}
	recordRegistration(f, j, "PERM", "10.200.0.2", "home")
	want := credentials.Credentials{
		Name: "home", Endpoint: "vps.example:7443", PermanentToken: "PERM", CertSHA256: hex.EncodeToString(pin[:]),
		UsedJoinTokenSHA256: j.TokenHash(), TunnelAddress: "10.200.0.2", WGPrivateKey: "keep",
	}
	if !reflect.DeepEqual(*f, want) {
		t.Errorf("credentials after recordRegistration:\n got %+v\nwant %+v", *f, want)
	}
}
