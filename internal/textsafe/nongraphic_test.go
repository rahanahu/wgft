package textsafe

import (
	"bytes"
	"encoding/json"
	"flag"
	"os"
	"path/filepath"
	"testing"
	"unicode"
)

// このファイルは、Go の unicode.IsGraphic が表示できないとする文字の範囲の一覧
// testdata/spec/text/non-graphic.json を作り、一覧が今の Go から離れていないことを確かめる。Rust の実装
// (crates/wgft-proto の textsafe) は同じ一覧と自分の判定を比べる。Go の版を上げて unicode.Version が
// 変わったときは、次で作り直す。
//
//	go test ./internal/textsafe -run TestNonGraphicRanges -update

var updateNonGraphic = flag.Bool("update", false, "rewrite testdata/spec/text/non-graphic.json")

const nonGraphicPath = "../../testdata/spec/text/non-graphic.json"

type nonGraphicList struct {
	// UnicodeVersion は一覧を作った Go の unicode.Version である
	UnicodeVersion string `json:"unicode_version"`
	// Ranges は unicode.IsGraphic が偽の code point の範囲で、両端を含む。surrogate も含む
	Ranges [][2]rune `json:"ranges"`
}

func buildNonGraphic() nonGraphicList {
	l := nonGraphicList{UnicodeVersion: unicode.Version}
	start := rune(-1)
	for r := rune(0); r <= unicode.MaxRune+1; r++ {
		non := r <= unicode.MaxRune && !unicode.IsGraphic(r)
		switch {
		case non && start < 0:
			start = r
		case !non && start >= 0:
			l.Ranges = append(l.Ranges, [2]rune{start, r - 1})
			start = -1
		}
	}
	return l
}

func TestNonGraphicRanges(t *testing.T) {
	got, err := json.Marshal(buildNonGraphic())
	if err != nil {
		t.Fatal(err)
	}
	got = append(got, '\n')
	if *updateNonGraphic {
		if err := os.WriteFile(filepath.FromSlash(nonGraphicPath), got, 0o644); err != nil {
			t.Fatal(err)
		}
		return
	}
	want, err := os.ReadFile(filepath.FromSlash(nonGraphicPath))
	if err != nil {
		t.Fatal(err)
	}
	// Windows の checkout は改行を CRLF にすることがある
	want = bytes.ReplaceAll(want, []byte("\r\n"), []byte("\n"))
	if !bytes.Equal(got, want) {
		t.Fatalf("%s differs from unicode.IsGraphic; after a Go upgrade, run go test ./internal/textsafe -run TestNonGraphicRanges -update", nonGraphicPath)
	}
}
