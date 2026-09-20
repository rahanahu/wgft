package store

import (
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

// TestSQLiteFileURIHandlesSpecialPaths is the regression test for a bug found in review: building
// the "file:" URI as url.URL{Scheme: "file", Path: path} without first making path absolute breaks
// every relative path. net/url's URL.String always emits "file://" (two slashes) when Host is
// empty, even if Path does not start with "/"; SQLite's own URI grammar (sqlite.org/uri.html)
// treats those two slashes as introducing an authority (host) component, so a relative path such
// as "rel.db" serialises to "file://rel.db?..." and SQLite rejects it with "invalid uri authority:
// rel.db?...". This matters in practice: WGFT_DATA_DIR can be relative (for example "./data"), and
// so can a path handed to the CLI from a checkout.
//
// It fails without sqliteFileURI's filepath.Abs call: verified by hand while writing this test, by
// changing sqliteFileURI to build the URI directly from the unmodified path (the code exactly as
// it shipped before this fix), which made the "relative path" and "relative path, nested dir"
// cases below fail Open with "invalid uri authority"; restored afterwards.
//
// Each case also opens the store, writes a row, closes it, and lists the directory to confirm the
// file that actually landed on disk has the exact name given (Open returning nil is not enough: a
// URI-escaping bug could still land the wrong file, notably a literal "%41" decoding to "A"). This
// runs for real on Windows too (windows-test CI), which is what caught the drive-letter-path bug
// TestWindowsPathToURIPath and TestFileURIFromAbsPath cover directly.
func TestSQLiteFileURIHandlesSpecialPaths(t *testing.T) {
	cases := []struct {
		name             string
		fileName         string
		nested           bool // put the db under a subdirectory, then chdir there and pass a relative path
		windowsForbidden bool // the character is not valid in a Windows file name at all
	}{
		{name: "plain absolute path", fileName: "wgft.sqlite"},
		{name: "path with a space", fileName: "wg ft.sqlite"},
		{name: "path with a question mark", fileName: "wg?ft.sqlite", windowsForbidden: true},
		{name: "path with a percent-encoded-looking sequence", fileName: "wg%41ft.sqlite"},
		{name: "path with a hash", fileName: "wg#ft.sqlite"},
		{name: "relative path", fileName: "wgft.sqlite", nested: true},
		{name: "relative path with a space", fileName: "wg ft.sqlite", nested: true},
	}

	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			// '?' (also '<', '>', ':', '"', '/', '\', '|', '*') cannot appear in a Windows file name
			// at all (rejected by the filesystem itself, nothing to do with the URI conversion this
			// file tests); ' ', '#' and '%' are all valid Windows file name characters and must keep
			// running there, since they are exactly the characters windowsPathToURIPath's caller
			// (url.URL's percent-encoding) has to get right.
			if tc.windowsForbidden && runtime.GOOS == "windows" {
				t.Skipf("%q is not a valid Windows file name character", tc.fileName)
			}
			dir := t.TempDir()
			pathArg := filepath.Join(dir, tc.fileName)
			if tc.nested {
				// Open() and its callers (cmd/wgft) do not chdir on our behalf; this reproduces a
				// process invoked with a relative WGFT_DATA_DIR from whatever directory it started in.
				cwd, err := os.Getwd()
				if err != nil {
					t.Fatal(err)
				}
				t.Cleanup(func() { _ = os.Chdir(cwd) })
				if err := os.Chdir(dir); err != nil {
					t.Fatal(err)
				}
				pathArg = tc.fileName
			}

			s, err := Open(pathArg)
			if err != nil {
				t.Fatalf("Open(%q): %v", pathArg, err)
			}
			if err := s.SetMeta("k", []byte("v")); err != nil {
				s.Close()
				t.Fatalf("SetMeta: %v", err)
			}
			s.Close()

			if _, err := os.Stat(filepath.Join(dir, tc.fileName)); err != nil {
				t.Errorf("want %s on disk after Open(%q): %v", tc.fileName, pathArg, err)
			}

			// OpenReadOnly must read the same file back (server check's path).
			roArg := pathArg
			ro, err := OpenReadOnly(roArg)
			if err != nil {
				t.Fatalf("OpenReadOnly(%q): %v", roArg, err)
			}
			defer ro.Close()
			v, err := ro.GetMeta("k")
			if err != nil || string(v) != "v" {
				t.Errorf("OpenReadOnly(%q).GetMeta(k) = %q, %v, want \"v\", nil", roArg, v, err)
			}
		})
	}
}
