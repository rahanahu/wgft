// suite.go は lab/suite.txt の読み取りと、2 つの分類だけを持つ日程の組み立て。
// 並列に流せる仕事はプールで同時に流し、単独で流す仕事は 1 つずつ流す。
// メモリを見て加減する仕組みは持たない。
package main

import (
	"bufio"
	"fmt"
	"os"
	"strings"
)

// class は仕事の分類。parallel はプールで、exclusive-* は 1 つずつ流す。
type class string

const (
	classParallel class = "parallel"
	classHeavy    class = "exclusive-heavy"
	classTiming   class = "exclusive-timing"
	classGlobal   class = "exclusive-global"
	manifestPath        = "lab/suite.txt"
)

// exclusive は単独で流す分類か。3 つの exclusive-* は理由が違うだけで、日程の上では同じ扱い。
func (c class) exclusive() bool { return c == classHeavy || c == classTiming || c == classGlobal }

// job は 1 回流すシナリオ。
type job struct {
	Class    class  `json:"class"`
	Scenario string `json:"scenario"` // "lifecycle.sh kernel 3b" のような、スクリプト名と引数
	Default  bool   `json:"default"`
}

// loadManifest は lab/suite.txt を読む。
func loadManifest(path string) ([]job, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	var jobs []job
	sc := bufio.NewScanner(f)
	line := 0
	for sc.Scan() {
		line++
		t := strings.TrimSpace(sc.Text())
		if t == "" || strings.HasPrefix(t, "#") {
			continue
		}
		f := strings.Fields(t)
		if len(f) < 3 {
			return nil, fmt.Errorf("%s:%d: want <class> <default> <scenario> [args...]", path, line)
		}
		c := class(f[0])
		if c != classParallel && c != classHeavy && c != classTiming && c != classGlobal {
			return nil, fmt.Errorf("%s:%d: unknown class %q", path, line, f[0])
		}
		var def bool
		switch f[1] {
		case "yes":
			def = true
		case "no":
			def = false
		default:
			return nil, fmt.Errorf("%s:%d: default must be yes or no, not %q", path, line, f[1])
		}
		jobs = append(jobs, job{Class: c, Scenario: strings.Join(f[2:], " "), Default: def})
	}
	if err := sc.Err(); err != nil {
		return nil, err
	}
	if len(jobs) == 0 {
		return nil, fmt.Errorf("%s: no job", path)
	}
	return jobs, nil
}

// countVerdicts は 1 つのシナリオのログから PASS、FAIL、SKIP の行数を数える。
// 旧来の流し方と新しい流し方で同じ確認が流れたことを、行数の一致で確かめるために使う。
func countVerdicts(logPath string) (pass, fail, skip int) {
	f, err := os.Open(logPath)
	if err != nil {
		return 0, 0, 0
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 0, 64*1024), 4*1024*1024)
	for sc.Scan() {
		switch {
		case strings.HasPrefix(sc.Text(), "PASS "):
			pass++
		case strings.HasPrefix(sc.Text(), "FAIL "):
			fail++
		case strings.HasPrefix(sc.Text(), "SKIP "):
			skip++
		}
	}
	return pass, fail, skip
}
