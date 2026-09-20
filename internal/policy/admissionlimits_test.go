package policy

import "testing"

// 接続元ごとの上限は、ゼロ値なら既定値、PerSourceOff なら上限なし(実効値 0)になる。
// ゼロ値の AdmissionLimits で守りが外れないことを確かめる。
func TestPerSourceCap(t *testing.T) {
	var zero AdmissionLimits
	if zero.UDPPerSourceCap() != UDPPerSource || zero.TCPPerSourceCap() != TCPPerSource {
		t.Errorf("zero AdmissionLimits: got %d/%d, want the defaults %d/%d",
			zero.UDPPerSourceCap(), zero.TCPPerSourceCap(), UDPPerSource, TCPPerSource)
	}
	off := AdmissionLimits{UDPPerSource: PerSourceOff, TCPPerSource: PerSourceOff}
	if off.UDPPerSourceCap() != 0 || off.TCPPerSourceCap() != 0 {
		t.Errorf("PerSourceOff: got %d/%d, want 0/0", off.UDPPerSourceCap(), off.TCPPerSourceCap())
	}
	set := AdmissionLimits{UDPPerSource: 999, TCPPerSource: 111}
	if set.UDPPerSourceCap() != 999 || set.TCPPerSourceCap() != 111 {
		t.Errorf("explicit values: got %d/%d, want 999/111", set.UDPPerSourceCap(), set.TCPPerSourceCap())
	}
}
