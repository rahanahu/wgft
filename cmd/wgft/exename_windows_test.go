//go:build windows

package main

import (
	"os"
	"testing"
)

// exeName reads os.Args[0], which the Go runtime sets from the path Explorer used to launch
// the process. This pins the scenario the mousetrap message exists for: a user
// double-clicking the file as downloaded from the Releases page
// (wgft-windows-amd64.exe), before renaming it to wgft.exe per docs/setup.md's Windows
// procedure. The backslash-separated path here is only meaningful on Windows - on Linux,
// filepath.Base does not treat '\' as a separator, so this test is build-tagged windows
// rather than written to be portable.
func TestExeName(t *testing.T) {
	original := os.Args
	t.Cleanup(func() {
		os.Args = original
	})

	cases := []struct {
		name string
		arg0 string
		want string
	}{
		{
			name: "downloaded release asset path",
			arg0: `C:\Users\me\Downloads\wgft-windows-amd64.exe`,
			want: "wgft-windows-amd64.exe",
		},
		{
			name: "empty argv[0]",
			arg0: "",
			want: "wgft.exe",
		},
		{
			name: "dot",
			arg0: ".",
			want: "wgft.exe",
		},
		{
			name: "bare separator",
			arg0: `\`,
			want: "wgft.exe",
		},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			os.Args = []string{c.arg0}
			if got := exeName(); got != c.want {
				t.Errorf("exeName() with os.Args[0] = %q = %q, want %q", c.arg0, got, c.want)
			}
		})
	}
}
