package main

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

// このファイルは、言語に依らない仕様(docs/design/spec/control-socket.md)の fixture と、
// `wgft agent doctor --json` の出力の形を照らす。fixture はラボの agent に対して実行した出力である。

// TestSpecAgentDoctorJSONRoundTrip は、fixture を agentDoctorJSON が知らないキー無しで読み、
// writeAgentDoctorJSON と同じ符号化で同じ byte 列に戻ることを確かめる。
func TestSpecAgentDoctorJSONRoundTrip(t *testing.T) {
	for _, name := range []string{"agent-doctor.json", "agent-doctor-stopped.json"} {
		want, err := os.ReadFile(filepath.Join("..", "..", "testdata", "spec", "control", name))
		if err != nil {
			t.Fatal(err)
		}
		dec := json.NewDecoder(bytes.NewReader(want))
		dec.DisallowUnknownFields()
		var r agentDoctorJSON
		if err := dec.Decode(&r); err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		var got bytes.Buffer
		enc := json.NewEncoder(&got)
		enc.SetIndent("", "  ")
		if err := enc.Encode(r); err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(got.Bytes(), want) {
			t.Errorf("%s:\n got %s\nwant %s", name, got.Bytes(), want)
		}
		if r.Status != "failed" || len(r.Checks) == 0 {
			t.Errorf("%s: status %q, %d checks", name, r.Status, len(r.Checks))
		}
	}
}
