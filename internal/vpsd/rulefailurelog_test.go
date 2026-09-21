//go:build linux

package vpsd

import (
	"errors"
	"reflect"
	"testing"
)

// A rule-local failure is logged when it starts and when its reason changes, and once when the
// rule stops failing, not on every retry.
func TestRuleFailureLog(t *testing.T) {
	bind := errors.New("bind failed: address already in use")
	var prev map[string]string
	var lines []string

	prev, lines = ruleFailureLog(prev, map[string]error{"r_a": bind})
	if !reflect.DeepEqual(lines, []string{"rule r_a: not active: bind failed: address already in use"}) {
		t.Errorf("start: %v", lines)
	}
	prev, lines = ruleFailureLog(prev, map[string]error{"r_a": bind})
	if len(lines) != 0 {
		t.Errorf("same failure on a retry: %v, want nothing", lines)
	}
	other := errors.New("bind failed: permission denied")
	prev, lines = ruleFailureLog(prev, map[string]error{"r_a": other})
	if !reflect.DeepEqual(lines, []string{"rule r_a: not active: bind failed: permission denied"}) {
		t.Errorf("changed reason: %v", lines)
	}
	prev, lines = ruleFailureLog(prev, nil)
	if !reflect.DeepEqual(lines, []string{"rule r_a: no longer failing"}) {
		t.Errorf("recovery: %v", lines)
	}
	if _, lines = ruleFailureLog(prev, nil); len(lines) != 0 {
		t.Errorf("after the recovery: %v, want nothing", lines)
	}
}
