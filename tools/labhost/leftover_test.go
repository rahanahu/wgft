package main

import (
	"strings"
	"testing"
)

// 後片付けの漏れがあれば run は失敗する。判定は summary だけを見る純粋な関数なので、
// 場面ごとに確かめられる。
func TestLeftoverFailures(t *testing.T) {
	clean := summary{Results: []jobResult{{Index: 0, Scenario: "e2e.sh kernel", SandboxID: "aaa111", Exit: 0}}}

	cases := []struct {
		name     string
		sum      summary
		want     int      // 期待する漏れの件数
		mentions []string // 文に含まれるべき語
	}{
		{name: "nothing left behind", sum: clean, want: 0},
		{
			name: "a namespace left behind",
			sum:  summary{Results: clean.Results, LeftoverNS: []string{"wgft-aaa111-vps"}},
			want: 1, mentions: []string{"namespaces", "wgft-aaa111-vps"},
		},
		{
			name: "a process left behind",
			sum:  summary{Results: clean.Results, LeftoverProcs: []string{"4242(wgft)"}},
			want: 1, mentions: []string{"processes", "4242(wgft)"},
		},
		{
			name: "a link left behind in the root namespace",
			sum:  summary{Results: clean.Results, LeftoverLinks: []string{"wgft0"}},
			want: 1, mentions: []string{"links", "wgft0"},
		},
		{
			name: "a workdir left behind that nobody asked to keep",
			sum:  summary{Results: clean.Results, LeftoverWorkdirs: []string{"bbb222"}},
			want: 1, mentions: []string{"workdirs", "bbb222"},
		},
		{
			// -keep-failed で残した作業ディレクトリは漏れではない。run はすでに失敗しているが、
			// その失敗を「漏れ」と呼んではならない
			name: "a workdir kept on purpose after a failed job",
			sum: summary{
				Results: []jobResult{{Index: 0, Scenario: "e2e.sh kernel", SandboxID: "ccc333", Exit: 1,
					Cleanup: DestroyReport{WorkdirKept: true}}},
				LeftoverWorkdirs: []string{"ccc333"},
			},
			want: 0,
		},
		{
			name: "one workdir kept on purpose and another leaked",
			sum: summary{
				Results: []jobResult{{Index: 0, SandboxID: "ccc333", Exit: 1,
					Cleanup: DestroyReport{WorkdirKept: true}}},
				LeftoverWorkdirs: []string{"ccc333", "ddd444"},
			},
			want: 1, mentions: []string{"ddd444"},
		},
		{
			// 仕事ごとの後片付けが自分で漏れを報告した場合も漏れ
			name: "a job reported its own cleanup leftovers",
			sum: summary{Results: []jobResult{{Index: 3, Scenario: "rates.sh kernel", SandboxID: "eee555",
				Cleanup: DestroyReport{LeftoverNS: []string{"wgft-eee555-lan"}, LeftoverPid: []string{"7(wgft)"}}}}},
			want: 1, mentions: []string{"job 3", "rates.sh kernel", "eee555", "wgft-eee555-lan"},
		},
		{
			name: "a job whose cleanup returned an error",
			sum: summary{Results: []jobResult{{Index: 1, Scenario: "ipv6.sh kernel", SandboxID: "fff666",
				Cleanup: DestroyReport{Errs: []string{"ip netns delete: busy"}}}}},
			want: 1, mentions: []string{"job 1", "cleanup"},
		},
		{
			name: "several kinds at once",
			sum: summary{Results: clean.Results, LeftoverNS: []string{"wgft-a-vps"},
				LeftoverProcs: []string{"9(echo)"}, LeftoverLinks: []string{"pub0"}},
			want: 3,
		},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := leftoverFailures(&c.sum)
			if len(got) != c.want {
				t.Fatalf("leftoverFailures returned %d entries (%v), want %d", len(got), got, c.want)
			}
			joined := strings.Join(got, " | ")
			for _, m := range c.mentions {
				if !strings.Contains(joined, m) {
					t.Errorf("the message %q does not mention %q", joined, m)
				}
			}
			for _, line := range got {
				if strings.HasPrefix(line, "PASS") || strings.HasPrefix(line, "FAIL") {
					t.Errorf("a leftover message must not start with a verdict word: %q", line)
				}
			}
		})
	}
}

// 漏れがあるときの終了の判定。run の終了コードはこの 3 つの条件の論理和で決まるので、
// その条件をここで固定する。
func TestRunFailsOnLeftoversAlone(t *testing.T) {
	// すべて PASS、中断なし、しかし netns が残っている
	s := summary{Pass: 29, Fail: 0, Interrupted: false,
		Results:    []jobResult{{SandboxID: "aaa111", Exit: 0}},
		LeftoverNS: []string{"wgft-aaa111-home"}}
	s.LeftoverFailures = leftoverFailures(&s)
	failed := s.Fail > 0 || s.Interrupted || len(s.LeftoverFailures) > 0
	if !failed {
		t.Error("a run with every job passing but a leftover namespace was judged successful")
	}
	if s.Fail != 0 {
		t.Error("a leftover must not be counted as a failing job")
	}
}
