package agent

import (
	"encoding/json"
	"errors"
	"strings"
	"testing"

	"github.com/rahanahu/wgft/internal/dataplane/userspace/sockbuf"
)

// doctor の応答は、トンネルを立てた直後に測った WireGuard の UDP ソケットのバッファを、トンネルの
// 項目に加算のフィールドとして載せる(設計文書 10.2c 節の制御ソケットの拡張)。トンネルが無い応答と
// カーネルモードの応答には載らない。
func TestDoctorCarriesTheSocketBuffers(t *testing.T) {
	short := sockbuf.Reading{Supported: true, Port: 35454, Sockets: 2, Recv: 425984, Send: 425984}
	dp := &fakeDataplane{up: true, reading: dataplaneReading{tunnel: tunnelReading{present: true, socketBuffers: &short}}}
	rt := newFakeDataplaneRuntime(t, dp)
	got := rt.collectDoctor().RuntimeState.Tunnel.SocketBuffers
	want := DoctorSocketBuffers{Supported: true, Port: 35454, Sockets: 2, Recv: 425984, Send: 425984, Required: sockbuf.Required}
	if got == nil || *got != want {
		t.Fatalf("socket_buffers = %+v, want %+v", got, want)
	}
	b, err := json.Marshal(got)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(b), `"recv":425984`) || !strings.Contains(string(b), `"required":14680064`) {
		t.Errorf("JSON = %s", b)
	}

	dp.reading = dataplaneReading{tunnel: tunnelReading{present: false, socketBuffers: &short}}
	if sb := rt.collectDoctor().RuntimeState.Tunnel.SocketBuffers; sb != nil {
		t.Errorf("a missing tunnel reports socket buffers %+v", sb)
	}
	dp.reading = dataplaneReading{tunnel: tunnelReading{present: true}}
	if sb := rt.collectDoctor().RuntimeState.Tunnel.SocketBuffers; sb != nil {
		t.Errorf("a tunnel without a measurement, as in kernel mode, reports %+v", sb)
	}
}

func TestDoctorSocketBuffersMapping(t *testing.T) {
	if got := doctorSocketBuffers(sockbuf.Reading{Port: 1}); *got != (DoctorSocketBuffers{}) {
		t.Errorf("an OS without a measurement maps to %+v, want only supported=false", got)
	}
	got := doctorSocketBuffers(sockbuf.Reading{Supported: true, Port: 35454, Err: errors.New("no UDP socket bound to port 35454 was found in this process")})
	if got.Error == "" || got.Sockets != 0 || !got.Supported {
		t.Errorf("a failed measurement maps to %+v", got)
	}
}
