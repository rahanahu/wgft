package main

import (
	"os"
	"path/filepath"
	"testing"
)

// リポジトリの lab/suite.txt は読めて、分類が既知のものだけで、旧来の一式と同じ範囲を
// 既定で対象とする。分類を書き間違えると単独で流すべき確認が並列に混ざるので、ここで止める。
func TestRepoManifestIsValid(t *testing.T) {
	jobs, err := loadManifest(filepath.Join("..", "..", "lab", "suite.txt"))
	if err != nil {
		t.Fatal(err)
	}
	var def, heavy, optional int
	seen := map[string]bool{}
	for _, j := range jobs {
		if seen[j.Scenario] {
			t.Errorf("%q is listed twice", j.Scenario)
		}
		seen[j.Scenario] = true
		switch j.Class {
		case classParallel, classHeavy, classTiming, classGlobal:
		default:
			t.Errorf("%q has unknown class %q", j.Scenario, j.Class)
		}
		if j.Default {
			def++
		} else {
			optional++
		}
		if j.Class == classHeavy {
			heavy++
		}
	}
	// 既定の一式は、両モードの e2e と ipv6 と rates と lifecycle の 16 個の確認、
	// それに split-merge、import-export、connlimit
	want := []string{
		"e2e.sh kernel", "e2e.sh userspace", "ipv6.sh kernel", "ipv6.sh userspace",
		"split-merge.sh kernel", "import-export.sh kernel", "connlimit.sh",
		"rates.sh kernel", "rates.sh userspace",
	}
	for _, mode := range []string{"kernel", "userspace"} {
		for _, c := range []string{"1", "2", "3", "3b", "4", "5", "5b", "5c", "5d", "5e", "6", "7", "8", "9", "10", "11"} {
			want = append(want, "lifecycle.sh "+mode+" "+c)
		}
	}
	for _, w := range want {
		if !seen[w] {
			t.Errorf("the manifest is missing %q", w)
		}
	}
	if def != len(want) {
		t.Errorf("default jobs = %d, want %d", def, len(want))
	}
	if heavy == 0 {
		t.Error("no exclusive-heavy job: check 5, rates and connlimit must not run beside others")
	}
	if optional == 0 {
		t.Error("no optional job: version-skew.sh needs staged binaries and stays opt-in")
	}
}

// 分類の綴り違いと欄の足りない行は読み取りで落ちる。
func TestLoadManifestRejectsBadLines(t *testing.T) {
	dir := t.TempDir()
	for _, bad := range []string{
		"sometimes yes e2e.sh kernel\n",
		"parallel maybe e2e.sh kernel\n",
		"parallel yes\n",
		"# only comments\n",
	} {
		p := filepath.Join(dir, "m.txt")
		if err := os.WriteFile(p, []byte(bad), 0o644); err != nil {
			t.Fatal(err)
		}
		if _, err := loadManifest(p); err == nil {
			t.Errorf("loadManifest accepted %q", bad)
		}
	}
}

// countVerdicts は行頭の PASS / FAIL / SKIP だけを数える。
func TestCountVerdicts(t *testing.T) {
	p := filepath.Join(t.TempDir(), "log")
	body := "== kernel: start server\nPASS  a\nPASS  b\nFAIL  c: got 'x'\nSKIP  d (does not apply)\n" +
		"   this line mentions PASS but does not start with it\n"
	if err := os.WriteFile(p, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
	pass, fail, skip := countVerdicts(p)
	if pass != 2 || fail != 1 || skip != 1 {
		t.Errorf("got %d/%d/%d, want 2/1/1", pass, fail, skip)
	}
	if p, f, s := countVerdicts(filepath.Join(t.TempDir(), "missing")); p+f+s != 0 {
		t.Errorf("a missing log returned %d/%d/%d", p, f, s)
	}
}
