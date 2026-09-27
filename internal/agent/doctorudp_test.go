package agent

import (
	"encoding/json"
	"errors"
	"strings"
	"testing"
)

// doctor の応答は、netstack の UDP の受信の会計の状態を、トンネルの項目に加算のフィールドとして
// 載せる(設計文書 10.2c 節の制御ソケットの拡張)。トンネルが無い応答とカーネルモードの応答には
// 載らない。
func TestDoctorCarriesTheUDPAccounting(t *testing.T) {
	dp := &fakeDataplane{up: true, reading: dataplaneReading{tunnel: tunnelReading{present: true, udpAccounting: &udpAccountingReading{}}}}
	rt := newFakeDataplaneRuntime(t, dp)
	got := rt.collectDoctor().RuntimeState.Tunnel.UDPAccounting
	if got == nil || *got != (DoctorUDPAccounting{}) {
		t.Fatalf("udp_accounting of a healthy ledger = %+v", got)
	}
	b, err := json.Marshal(got)
	if err != nil {
		t.Fatal(err)
	}
	if string(b) != `{"stopped":false}` {
		t.Errorf("JSON = %s", b)
	}

	dp.reading.tunnel.udpAccounting = &udpAccountingReading{fault: errors.New("unreserved UDP dequeue")}
	got = rt.collectDoctor().RuntimeState.Tunnel.UDPAccounting
	if got == nil || !got.Stopped || got.Error != "unreserved UDP dequeue" {
		t.Fatalf("udp_accounting of a stopped ledger = %+v", got)
	}
	b, _ = json.Marshal(got)
	if !strings.Contains(string(b), `"stopped":true`) || !strings.Contains(string(b), `"error":"unreserved UDP dequeue"`) {
		t.Errorf("JSON = %s", b)
	}

	dp.reading = dataplaneReading{tunnel: tunnelReading{present: false, udpAccounting: &udpAccountingReading{}}}
	if u := rt.collectDoctor().RuntimeState.Tunnel.UDPAccounting; u != nil {
		t.Errorf("a missing tunnel reports udp_accounting %+v", u)
	}
	dp.reading = dataplaneReading{tunnel: tunnelReading{present: true}}
	if u := rt.collectDoctor().RuntimeState.Tunnel.UDPAccounting; u != nil {
		t.Errorf("a tunnel without a netstack, as in kernel mode, reports %+v", u)
	}
}
