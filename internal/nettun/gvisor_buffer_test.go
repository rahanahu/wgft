package nettun

import (
	"bytes"
	"testing"

	"gvisor.dev/gvisor/pkg/buffer"
)

// netstack と channel は backing を共有した buffer の clone を使う。
// 片方を短くして再び広げるときに、元の内容まで 0 にしない版を固定する。
func TestGVisorClonedBufferGrowPreservesOriginal(t *testing.T) {
	for _, tc := range []struct {
		name string
		keep int
		grow int
	}{
		{name: "within_original", keep: 7, grow: 96},
		{name: "past_original", keep: 31, grow: 320},
	} {
		t.Run(tc.name, func(t *testing.T) {
			originalBytes := make([]byte, 96)
			for i := range originalBytes {
				originalBytes[i] = byte(i + 1)
			}
			original := buffer.MakeWithData(originalBytes)
			defer original.Release()
			clone := original.Clone()
			defer clone.Release()

			clone.Truncate(int64(tc.keep))
			clone.GrowTo(int64(tc.grow), true)
			want := make([]byte, tc.grow)
			copy(want, originalBytes[:tc.keep])
			if got := clone.Flatten(); !bytes.Equal(got, want) {
				t.Fatalf("expanded clone = %x, want preserved prefix and zero extension %x", got, want)
			}
			if got := original.Flatten(); !bytes.Equal(got, originalBytes) {
				t.Fatalf("growing clone changed original bytes: got %x, want %x", got, originalBytes)
			}
		})
	}
}
