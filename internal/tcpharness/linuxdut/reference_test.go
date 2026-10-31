//go:build linux

package linuxdut

import (
	"os"
	"path/filepath"
	"regexp"
	"testing"
)

// TestReferenceReleaseMatchesLab checks that ReferenceRelease names the kernel lab/lab pins as
// LAB_KERNEL_ABI, so the Linux expected differences and the lab's reference VM move together.
func TestReferenceReleaseMatchesLab(t *testing.T) {
	b, err := os.ReadFile(filepath.Join("..", "..", "..", "lab", "lab"))
	if err != nil {
		t.Fatalf("reading lab/lab: %v", err)
	}
	m := regexp.MustCompile(`(?m)^LAB_KERNEL_ABI=(\S+)$`).FindSubmatch(b)
	if m == nil {
		t.Fatal("lab/lab has no LAB_KERNEL_ABI= line")
	}
	if got := string(m[1]); got != ReferenceRelease {
		t.Errorf("lab/lab pins LAB_KERNEL_ABI=%s, but linuxdut.ReferenceRelease is %s; bump both together", got, ReferenceRelease)
	}
}
