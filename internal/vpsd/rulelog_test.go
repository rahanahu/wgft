//go:build linux

package vpsd

import (
	"strconv"
	"strings"
	"testing"
)

func TestBatchSummary(t *testing.T) {
	cases := []struct {
		name                    string
		op                      string
		added, updated, deleted []string
		generation              uint64
		changed                 bool
		want                    string
	}{
		{
			name:       "added only",
			op:         "cli rule add",
			added:      []string{"r_1"},
			want:       "rules: cli rule add: added [r_1]; generation 5",
			generation: 5, changed: true,
		},
		{
			name:       "mixed categories",
			op:         "ui import",
			added:      []string{"r_1", "r_2"},
			updated:    []string{"r_3"},
			deleted:    []string{"r_4"},
			generation: 7, changed: true,
			want: "rules: ui import: added [r_1 r_2], updated [r_3], deleted [r_4]; generation 7",
		},
		{
			name:       "unchanged suffix",
			op:         "cli rule deny add",
			updated:    []string{"r_1"},
			generation: 3,
			changed:    false,
			want:       "rules: cli rule deny add: updated [r_1]; generation 3 unchanged",
		},
		{
			name:       "no changes at all",
			op:         "api",
			generation: 2,
			changed:    false,
			want:       "rules: api: no changes; generation 2 unchanged",
		},
		{
			name:       "empty op defaults to api",
			op:         "",
			deleted:    []string{"r_1"},
			generation: 1,
			changed:    true,
			want:       "rules: api: deleted [r_1]; generation 1",
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := batchSummary(c.op, c.added, c.updated, c.deleted, c.generation, c.changed)
			if got != c.want {
				t.Errorf("batchSummary() = %q, want %q", got, c.want)
			}
		})
	}
}

func TestBatchSummaryTruncatesLongIDLists(t *testing.T) {
	ids := make([]string, 25)
	for i := range ids {
		ids[i] = "r_" + strconv.Itoa(i)
	}
	got := batchSummary("cli rule import", ids, nil, nil, 1, true)
	if !strings.Contains(got, "and 5 more") {
		t.Errorf("batchSummary() = %q, want it to mention 5 more ids", got)
	}
	// Only the first 20 ids should be listed verbatim.
	if strings.Contains(got, "r_24") {
		t.Errorf("batchSummary() = %q, should not list the 25th id", got)
	}
	if !strings.Contains(got, "r_19") {
		t.Errorf("batchSummary() = %q, should list the 20th id", got)
	}
}
