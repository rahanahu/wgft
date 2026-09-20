package main

import "testing"

// A run that executes nothing must not be able to succeed: -parallel 0 starts no worker, so the
// parallel jobs never run, and -repeat 0 empties the plan.
func TestValidateRunCounts(t *testing.T) {
	for _, tc := range []struct {
		parallel, repeat int
		ok               bool
	}{
		{1, 1, true},
		{8, 20, true},
		{0, 1, false},
		{-1, 1, false},
		{1, 0, false},
		{1, -3, false},
		{0, 0, false},
	} {
		err := validateRunCounts(tc.parallel, tc.repeat)
		if (err == nil) != tc.ok {
			t.Errorf("validateRunCounts(%d, %d) = %v, want ok=%v", tc.parallel, tc.repeat, err, tc.ok)
		}
	}
}
