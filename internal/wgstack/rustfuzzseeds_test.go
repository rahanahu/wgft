package wgstack

import (
	"encoding/binary"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

// TestRustFuzzSeeds は、FuzzCore と FuzzAdversarialSender の種を、Rust の wgstack の fuzz の target の corpus
// (crates/wgft-wgstack/fuzz/corpus/core と adversarial_sender) と照らす (docs/design/v2/test-tooling.md の
// 6 節)。core の種は FuzzCore の記録の元と同じ列 (fuzzCorePrograms) で、f.Add の値、repo の corpus
// (`go test fuzz v1` の形式) から取り出した []byte の値、種から作った長い列である。Rust の core の target は
// 同じ byte を同じ op に読む。adversarial_sender の種は FuzzAdversarialSender
// の f.Add の uint64 を 8 byte の little endian にしたもの。corpus の go- で始まるファイルは、この試験が書く
// ものだけにする。作り直すときは TestRustGolden と同じ -update-rust-golden を付ける。
func TestRustFuzzSeeds(t *testing.T) {
	// FuzzCore の記録と同じ列:f.Add の値、repo の corpus、種から作った列 (gen-N は 200 から 600 byte で、
	// 500 段まで進む長い種になる)
	core := map[string][]byte{}
	for name, p := range fuzzCorePrograms(t, 8) {
		core["go-"+name] = p
	}
	adv := map[string][]byte{}
	// FuzzAdversarialSender の f.Add と同じ種
	for seed := uint64(1); seed <= 8; seed++ {
		adv[fmt.Sprintf("go-seed-%d", seed)] = binary.LittleEndian.AppendUint64(nil, seed)
	}
	for target, seeds := range map[string]map[string][]byte{"core": core, "adversarial_sender": adv} {
		out := filepath.Join(rustCrate, "fuzz", "corpus", target)
		for name, b := range seeds {
			compareOrUpdate(t, filepath.Join(out, name), b, false)
		}
		// 消えた種の残りのファイルを断る
		have, err := os.ReadDir(out)
		if err != nil {
			t.Fatal(err)
		}
		for _, e := range have {
			if _, ok := seeds[e.Name()]; ok || !strings.HasPrefix(e.Name(), "go-") {
				continue
			}
			if *updateRustGolden {
				if err := os.Remove(filepath.Join(out, e.Name())); err != nil {
					t.Fatal(err)
				}
				continue
			}
			names := slices.Sorted(func(yield func(string) bool) {
				for k := range seeds {
					if !yield(k) {
						return
					}
				}
			})
			t.Fatalf("%s/%s is not a Go seed (want %v); run go test ./internal/wgstack -run TestRustFuzzSeeds -update-rust-golden", out, e.Name(), names)
		}
	}
}
