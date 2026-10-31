package controlapi

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

// このファイルは、言語に依らない仕様(docs/design/spec/control-socket.md)の fixture と、制御ソケットの
// doctor の応答の形を照らす。fixture はラボで稼働中の agent の制御ソケットから読んだ 1 行で、
// 秘密に当たる値は無い。

var specDir = filepath.Join("..", "..", "..", "testdata", "spec")

// TestSpecDoctorReplyRoundTrip は、fixture の応答を DoctorResponse が知らないキー無しで読み、
// json.Marshal と改行で同じ 1 行に戻ることを確かめる。
func TestSpecDoctorReplyRoundTrip(t *testing.T) {
	for _, name := range []string{"doctor-reply.json", "doctor-reply-kernel.json"} {
		want, err := os.ReadFile(filepath.Join(specDir, "control", name))
		if err != nil {
			t.Fatal(err)
		}
		dec := json.NewDecoder(bytes.NewReader(want))
		dec.DisallowUnknownFields()
		var r DoctorResponse
		if err := dec.Decode(&r); err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		got, err := json.Marshal(r)
		if err != nil {
			t.Fatal(err)
		}
		if got = append(got, '\n'); !bytes.Equal(got, want) {
			t.Errorf("%s:\n got %s\nwant %s", name, got, want)
		}
	}
}

// TestSpecControlConstants は、control-socket.md の要求と上限を固定する。
func TestSpecControlConstants(t *testing.T) {
	if DoctorCommand != "doctor" || ControlPath("/d/agent.json") != "/d/agent.json.sock" || ControlPathLimit != 103 ||
		DoctorReplyMaxBytes != 4<<20 || DoctorTextMaxBytes != 512 {
		t.Errorf("constants changed")
	}
}
