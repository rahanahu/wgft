package controlapi

import (
	"encoding/json"
	"fmt"
	"reflect"
	"testing"
	"time"
)

// fill sets every exported field reachable from v to a value that is not the zero value: two
// elements per slice, a time that is not the zero time, and strings and numbers derived from the
// depth, so a field that moves to another struct changes the encoding too.
func fill(v reflect.Value, depth int) {
	switch v.Kind() {
	case reflect.Pointer:
		v.Set(reflect.New(v.Type().Elem()))
		fill(v.Elem(), depth)
	case reflect.Struct:
		if v.Type() == reflect.TypeOf(time.Time{}) {
			v.Set(reflect.ValueOf(time.Date(2026, 10, 1, 12, 34, 56, 789, time.UTC)))
			return
		}
		for i := 0; i < v.NumField(); i++ {
			if v.Type().Field(i).IsExported() {
				fill(v.Field(i), depth+1)
			}
		}
	case reflect.Slice:
		s := reflect.MakeSlice(v.Type(), 2, 2)
		for i := 0; i < 2; i++ {
			fill(s.Index(i), depth+1)
		}
		v.Set(s)
	case reflect.String:
		v.SetString(fmt.Sprintf("s%d", depth))
	case reflect.Bool:
		v.SetBool(true)
	case reflect.Int, reflect.Int64, reflect.Int32:
		v.SetInt(int64(7 + depth))
	case reflect.Uint64, reflect.Uint16, reflect.Uint32, reflect.Uint:
		v.SetUint(uint64(9 + depth))
	}
}

// wantDoctorJSON は、すべての項目を埋めた応答を encoding/json で書いた 1 行である。稼働中の
// エージェントと CLI は別の版でありうるので(新しい実行ファイルを置いてから常駐プロセスを再起動する
// までの間。設計文書 10.2c 節)、項目の名前、順序、入れ子、omitempty の有無は制御ソケットの形
// そのものである。項目を足すときはこの値も直す。既存の項目の値が変わるなら、
// それは形を変える改訂である。
const wantDoctorJSON = `{"error":"s1","allow_targets":{"set":true,"list":"s2","env":"s2"},"stream":{"connected":true,"disconnected_at":"2026-10-01T12:34:56.000000789Z","disconnect_reason":"s2","pin_mismatch":true,"key_change_limited":true,"backoff":9,"retry_at":"2026-10-01T12:34:56.000000789Z","last_ping_at":"2026-10-01T12:34:56.000000789Z","last_pong_at":"2026-10-01T12:34:56.000000789Z","awaiting_pong":true},"process":{"uid":9,"user":"s2","cap_net_admin":true},"runtime_state":{"mode":"s2","generation":11,"tunnel":{"present":true,"state":"s3","reason":"s3","endpoint":"s3","last_handshake":"2026-10-01T12:34:56.000000789Z","rx_bytes":10,"tx_bytes":10,"started_at":"2026-10-01T12:34:56.000000789Z","watchdog":{"rebuild_interval":11,"retry_at":"2026-10-01T12:34:56.000000789Z"},"socket_buffers":{"supported":true,"port":13,"sockets":11,"recv":11,"send":11,"required":11,"error":"s4"},"udp_accounting":{"stopped":true,"error":"s4"}},"rules":[{"id":"s4","state":"s4","reason":"s4","proto":"s4","listeners":11,"listening":11,"bind_errors":11,"bind_error":"s4","target_errors":11,"target_error":"s4","sessions":11,"flows":11,"ports":11,"dnat_ports":11},{"id":"s4","state":"s4","reason":"s4","proto":"s4","listeners":11,"listening":11,"bind_errors":11,"bind_error":"s4","target_errors":11,"target_error":"s4","sessions":11,"flows":11,"ports":11,"dnat_ports":11}],"budgets":[{"proto":"s4","total":11,"in_use":11,"rule_cap":11,"reserve":11,"rules":11,"refusals":[{"rule_id":"s6","reason":"s6","count":15},{"rule_id":"s6","reason":"s6","count":15}]},{"proto":"s4","total":11,"in_use":11,"rule_cap":11,"reserve":11,"rules":11,"refusals":[{"rule_id":"s6","reason":"s6","count":15},{"rule_id":"s6","reason":"s6","count":15}]}],"refusals_since":"2026-10-01T12:34:56.000000789Z","agent_disabled":true,"kernel":{"interface":{"name":"s4","read_error":"s4","exists":true,"kind":"s4","up":true,"needs_net_admin":true,"device_error":"s4","ownership":"s4","mtu":11,"addresses":["s5","s5"],"peers":[{"public_key":"s6","allowed_ips":["s7","s7"],"endpoint":"s6","keepalive":13,"last_handshake":"2026-10-01T12:34:56.000000789Z","rx_bytes":13,"tx_bytes":13},{"public_key":"s6","allowed_ips":["s7","s7"],"endpoint":"s6","keepalive":13,"last_handshake":"2026-10-01T12:34:56.000000789Z","rx_bytes":13,"tx_bytes":13}],"declared":true,"server_address":"s4","peer_ok":true,"differs":["s5","s5"],"route_interface":"s4","route_error":"s4"},"table":{"read_error":"s4","needs_net_admin":true,"present":true,"source":"s4","generation":13,"missing":["s5","s5"],"missing_count":11,"guard_missing":["s5","s5"],"guard_missing_count":11,"guard_effects":["s5","s5"],"guard_closed":["s5","s5"],"moved":["s5","s5"],"moved_count":11,"unexpected":["s5","s5"],"unexpected_count":11,"rules":[{"id":"s6","state":"s6","reason":"s6","proto":"s6","listeners":13,"listening":13,"bind_errors":13,"bind_error":"s6","target_errors":13,"target_error":"s6","sessions":13,"flows":13,"ports":13,"dnat_ports":13},{"id":"s6","state":"s6","reason":"s6","proto":"s6","listeners":13,"listening":13,"bind_errors":13,"bind_error":"s6","target_errors":13,"target_error":"s6","sessions":13,"flows":13,"ports":13,"dnat_ports":13}]},"forwarding":{"ip_forward":"s4","ip_forward_error":"s4","rp_filter_strict":["s5","s5"],"policy_drops":["s5","s5"],"policy_error":"s4","policy_needs_net_admin":true}},"publish_error":"s2","check_error":"s2"},"runtime_state_timeout":8}`

func TestDoctorResponseWireShape(t *testing.T) {
	var r DoctorResponse
	fill(reflect.ValueOf(&r).Elem(), 0)
	b, err := json.Marshal(r)
	if err != nil {
		t.Fatal(err)
	}
	if string(b) != wantDoctorJSON {
		t.Errorf("DoctorResponse encodes as\n%s\nwant\n%s", b, wantDoctorJSON)
	}
	if b, _ := json.Marshal(DoctorResponse{}); string(b) != "{}" {
		t.Errorf("the empty DoctorResponse encodes as %s, want {}", b)
	}
}

// TestWireConstants は、読み手と書き手が別の版でありうる値を固定する。
func TestWireConstants(t *testing.T) {
	for _, c := range []struct {
		name      string
		got, want any
	}{
		{"DoctorCommand", DoctorCommand, "doctor"},
		{"DoctorReplyMaxBytes", DoctorReplyMaxBytes, 4 << 20},
		{"ControlPathLimit", ControlPathLimit, 103},
		{"ControlPath", ControlPath("/var/lib/wgft/agent.json"), "/var/lib/wgft/agent.json.sock"},
		{"ReasonHandshakePending", ReasonHandshakePending, "handshake not established"},
		{"ReasonWGRefused", ReasonWGRefused, "refused the wg configuration"},
		{"ReasonNoTunnel", ReasonNoTunnel, "no tunnel"},
		{"ReasonNoTunnelBuildFailed", ReasonNoTunnelBuildFailed, "no tunnel; building it failed"},
		{"ReasonNoTunnelBuildRetrying", ReasonNoTunnelBuildRetrying, "no tunnel; building it failed and will be retried"},
		{"ReasonFullStateNotReceived", ReasonFullStateNotReceived, "full state not received"},
		{"ReasonNoTunnelFullStatePending", ReasonNoTunnelFullStatePending, "no tunnel; full state not received"},
		{"KernelOwnershipAbsent", KernelOwnershipAbsent, "absent"},
		{"KernelOwnershipCurrent", KernelOwnershipCurrent, "current"},
		{"KernelOwnershipPrevious", KernelOwnershipPrevious, "previous"},
		{"KernelOwnershipForeign", KernelOwnershipForeign, "foreign"},
		{"KernelOwnershipKeyless", KernelOwnershipKeyless, "keyless"},
		{"KernelOwnershipNotWireGuard", KernelOwnershipNotWireGuard, "not_wireguard"},
		{"KernelEffectHost", KernelEffectHost, "host"},
		{"KernelEffectOtherDNAT", KernelEffectOtherDNAT, "other_dnat"},
		{"KernelEffectLAN", KernelEffectLAN, "lan"},
		{"KernelEffectHairpin", KernelEffectHairpin, "hairpin"},
		{"KernelEffectToTunnel", KernelEffectToTunnel, "to_tunnel"},
		{"KernelEffectMSS", KernelEffectMSS, "mss"},
		{"KernelClosedHostByFilterPre", KernelClosedHostByFilterPre, "host_by_filter_pre"},
		{"KernelClosedHostByInput", KernelClosedHostByInput, "host_by_input"},
		{"KernelClosedLANByFilterPre", KernelClosedLANByFilterPre, "lan_by_filter_pre"},
		{"KernelClosedLANByForward", KernelClosedLANByForward, "lan_by_forward"},
		{"KernelTableFromRecord", KernelTableFromRecord, "record"},
		{"KernelTableFromDeclaration", KernelTableFromDeclaration, "declaration"},
	} {
		if c.got != c.want {
			t.Errorf("%s = %v, want %v", c.name, c.got, c.want)
		}
	}
}
