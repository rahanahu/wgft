// wgstack-reccmp compares two directories of the Go wgstack's recordings and prints their sizes,
// or installs a new set over the recordings in git (docs/design/v2/test-tooling.md section 4).
//
//	go run ./scripts/wgstack-reccmp [-budget BYTES] NEW OLD
//	go run ./scripts/wgstack-reccmp -install NEW DEST
//
// Two recordings are the same when their frames are the same and their metas are the same apart
// from go_version, so a new Go toolchain alone changes nothing. A scenario that reads or writes
// from a goroutine of its own (meta "concurrent") may order its frames differently each time it
// is made; for it only the metas, apart from go_version, are compared.
//
// Compare mode requires every recording in both directories to be the same; with -budget, NEW's
// recordings must not take more than BYTES. Install mode copies NEW into DEST, keeps a DEST file
// that is the same as NEW's (so a concurrent recording stays as it is until its meta, such as
// go_commit, changes), and removes DEST's recordings that NEW does not have. The exit status is 1
// when a check fails.
package main

import (
	"bytes"
	"flag"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"strings"

	"github.com/rahanahu/wgft/internal/dutproto"
)

func main() {
	budget := flag.Int64("budget", 0, "the most bytes NEW's recordings may take; 0 for no limit")
	install := flag.Bool("install", false, "install NEW over DEST instead of comparing")
	flag.Parse()
	if flag.NArg() != 2 {
		fmt.Fprintln(os.Stderr, "usage: wgstack-reccmp [-budget BYTES] NEW OLD | wgstack-reccmp -install NEW DEST")
		os.Exit(2)
	}
	a, b := flag.Arg(0), flag.Arg(1)
	filesA, err := list(a)
	if err != nil {
		fail(err)
	}
	filesB, err := list(b)
	if err != nil {
		fail(err)
	}
	if *install {
		installSet(a, b, filesA, filesB)
		return
	}
	bad := 0
	sizes := map[string]int64{}
	var total int64
	for _, rel := range sortedKeys(filesA) {
		da := filesA[rel]
		total += int64(len(da))
		sizes[strings.Split(rel, string(filepath.Separator))[0]] += int64(len(da))
		db, ok := filesB[rel]
		if !ok {
			fmt.Printf("only in %s: %s\n", a, rel)
			bad++
			continue
		}
		if same, why := sameRecording(da, db); !same {
			fmt.Printf("%s: %s\n", rel, why)
			bad++
		}
	}
	for rel := range filesB {
		if _, ok := filesA[rel]; !ok {
			fmt.Printf("only in %s: %s\n", b, rel)
			bad++
		}
	}
	for _, src := range sortedKeys(sizes) {
		fmt.Printf("size %-12s %9d bytes\n", src, sizes[src])
	}
	fmt.Printf("size %-12s %9d bytes in %d recordings\n", "total", total, len(filesA))
	if *budget > 0 && total > *budget {
		fmt.Printf("the recordings take %d bytes, over the budget of %d\n", total, *budget)
		bad++
	}
	if bad > 0 {
		os.Exit(1)
	}
}

// sameRecording applies the rule of the package comment and says why two recordings differ.
func sameRecording(da, db []byte) (bool, string) {
	if bytes.Equal(da, db) {
		return true, ""
	}
	ma, fa, errA := dutproto.ReadRecord(bytes.NewReader(da))
	mb, fb, errB := dutproto.ReadRecord(bytes.NewReader(db))
	if errA != nil || errB != nil {
		return false, fmt.Sprintf("unreadable: %v %v", errA, errB)
	}
	ma.GoVersion, mb.GoVersion = "", ""
	if !reflect.DeepEqual(ma, mb) {
		return false, "the metas differ"
	}
	if !ma.Concurrent && !bytes.Equal(fa, fb) {
		return false, "the frames differ"
	}
	return true, ""
}

// installSet copies the new set over DEST, keeping DEST's files that are the same.
func installSet(src, dest string, news, olds map[string][]byte) {
	kept, written, removed := 0, 0, 0
	for _, rel := range sortedKeys(news) {
		if old, ok := olds[rel]; ok {
			if same, _ := sameRecording(news[rel], old); same {
				kept++
				continue
			}
		}
		p := filepath.Join(dest, rel)
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			fail(err)
		}
		if err := os.WriteFile(p, news[rel], 0o644); err != nil {
			fail(err)
		}
		written++
	}
	for rel := range olds {
		if _, ok := news[rel]; !ok {
			if err := os.Remove(filepath.Join(dest, rel)); err != nil {
				fail(err)
			}
			removed++
		}
	}
	fmt.Printf("installed %s into %s: %d kept, %d written, %d removed\n", src, dest, kept, written, removed)
}

// list reads every recording under dir, by its path relative to dir.
func list(dir string) (map[string][]byte, error) {
	out := map[string][]byte{}
	err := filepath.WalkDir(dir, func(p string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() || !strings.HasSuffix(p, ".rec.gz") {
			return err
		}
		rel, err := filepath.Rel(dir, p)
		if err != nil {
			return err
		}
		out[rel], err = os.ReadFile(p)
		return err
	})
	return out, err
}

func sortedKeys[V any](m map[string]V) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}

func fail(err error) {
	fmt.Fprintln(os.Stderr, "wgstack-reccmp:", err)
	os.Exit(1)
}
