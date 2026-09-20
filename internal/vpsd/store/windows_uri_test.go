package store

import "testing"

// TestWindowsPathToURIPath is the regression test for a bug found in CI: filepath.Abs on Windows
// returns a backslash-separated, drive-letter path (e.g. `C:\Users\a\s.sqlite`), and the old
// sqliteFileURI passed that straight to url.URL{Path: ...} unmodified. Since it does not start with
// "/", url.URL.String() still emits the "file://" authority prefix, and since backslash is not a
// URI path separator, it just gets percent-encoded, producing "file://C:%5CUsers%5Ca%5Cs.sqlite?..."
// -- exactly the shape SQLite rejects as "invalid uri authority", the Windows counterpart of the
// relative-path bug TestSQLiteFileURIHandlesSpecialPaths covers for Unix. This runs on every OS,
// not just under GOOS=windows: it feeds windows-flavoured strings directly to the pure conversion
// function, which does not itself consult runtime.GOOS (see its doc comment and sqliteFileURI's).
func TestWindowsPathToURIPath(t *testing.T) {
	cases := []struct {
		name    string
		abs     string
		want    string // path component only, before url.URL does its own percent-encoding
		wantErr bool
	}{
		{name: "plain drive path", abs: `C:\foo\bar.db`, want: "/C:/foo/bar.db"},
		{name: "lowercase drive letter", abs: `c:\x\q.db`, want: "/c:/x/q.db"},
		{name: "nested directories", abs: `C:\Users\a b\s.sqlite`, want: "/C:/Users/a b/s.sqlite"},
		{name: "UNC path rejected", abs: `\\server\share\x.db`, wantErr: true},
		{name: "UNC path rejected, forward slashes already", abs: `//server/share/x.db`, wantErr: true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := windowsPathToURIPath(tc.abs)
			if tc.wantErr {
				if err == nil {
					t.Fatalf("windowsPathToURIPath(%q) = %q, nil; want an error", tc.abs, got)
				}
				return
			}
			if err != nil {
				t.Fatalf("windowsPathToURIPath(%q): %v", tc.abs, err)
			}
			if got != tc.want {
				t.Errorf("windowsPathToURIPath(%q) = %q, want %q", tc.abs, got, tc.want)
			}
		})
	}
}

// TestFileURIFromAbsPath asserts the exact "file:" URI string fileURIFromAbsPath produces, for both
// path flavours, on whatever OS this test happens to run on: the windows argument is explicit, not
// read from runtime.GOOS, so the Windows cases below are exercised on Linux and macOS runners too,
// not only in the windows-test CI job. Teeth: reverting windowsPathToURIPath to pass abs straight
// through unconverted (the code as it shipped when this bug was found in CI, equivalent to the
// pre-fix sqliteFileURI applied to a Windows-shaped path) was confirmed by hand to make the "plain
// drive path", "space in directory name" and "drive letter colon stays literal" cases below fail
// with the reported shape ("file://C:%5C..." instead of "file:///C:/..."); restored afterwards.
func TestFileURIFromAbsPath(t *testing.T) {
	const query = "_busy_timeout=5000&_journal_mode=WAL&_foreign_keys=on"
	cases := []struct {
		name    string
		abs     string
		windows bool
		want    string
		wantErr bool
	}{
		{
			name: "unix absolute path",
			abs:  "/var/lib/wgft/wgft.sqlite", windows: false,
			want: "file:///var/lib/wgft/wgft.sqlite?" + query,
		},
		{
			name: "unix path with special characters",
			abs:  "/tmp/wg ft?#%41.sqlite", windows: false,
			want: "file:///tmp/wg%20ft%3F%23%2541.sqlite?" + query,
		},
		{
			name: "windows drive letter path",
			abs:  `C:\Users\a\s.sqlite`, windows: true,
			want: "file:///C:/Users/a/s.sqlite?" + query,
		},
		{
			name: "windows path with a space in a directory name",
			abs:  `C:\Users\a b\s.sqlite`, windows: true,
			want: "file:///C:/Users/a%20b/s.sqlite?" + query,
		},
		{
			// The exact scenario the reviewer asked to be verified rather than assumed: the drive
			// letter's ':' must stay a literal ':' in the output, not become a %3A that SQLite's URI
			// decoder would have to undo. It survives because it is not the first path segment once
			// the URI already has an authority ("file://" + empty host), so net/url's escaper does
			// not treat it as a scheme-like separator that needs escaping.
			name: "drive letter colon stays literal",
			abs:  `c:\x\q?x%41#.db`, windows: true,
			want: "file:///c:/x/q%3Fx%2541%23.db?" + query,
		},
		{
			name: "UNC path is rejected, not guessed at",
			abs:  `\\server\share\x.db`, windows: true,
			wantErr: true,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := fileURIFromAbsPath(tc.abs, query, tc.windows)
			if tc.wantErr {
				if err == nil {
					t.Fatalf("fileURIFromAbsPath(%q, windows=%v) = %q, nil; want an error", tc.abs, tc.windows, got)
				}
				return
			}
			if err != nil {
				t.Fatalf("fileURIFromAbsPath(%q, windows=%v): %v", tc.abs, tc.windows, err)
			}
			if got != tc.want {
				t.Errorf("fileURIFromAbsPath(%q, windows=%v) = %q, want %q", tc.abs, tc.windows, got, tc.want)
			}
		})
	}
}
