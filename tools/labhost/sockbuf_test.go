package main

import (
	"errors"
	"strings"
	"testing"
)

func TestSockbufWatch(t *testing.T) {
	vals := map[string]string{}
	w := &sockbufWatch{read: func(p string) (string, error) {
		v, ok := vals[p]
		if !ok {
			return "", errors.New("absent")
		}
		return v, nil
	}}
	set := func(r, s string) {
		vals["/proc/sys/net/core/rmem_max"], vals["/proc/sys/net/core/wmem_max"] = r, s
	}

	set("7340032\n", "16777216\n")
	if got := w.check("the pool"); got != "" {
		t.Fatalf("baseline met: got warning %q", got)
	}

	set("212992\n", "7340032\n")
	got := w.check("the pool")
	for _, want := range []string{"before the pool", "net.core.rmem_max is 212992", "below the lab baseline of 7340032", "lab/lab net up"} {
		if !strings.Contains(got, want) {
			t.Errorf("warning %q lacks %q", got, want)
		}
	}
	if strings.Contains(got, "wmem_max") {
		t.Errorf("warning %q names wmem_max, which meets the baseline", got)
	}
	if strings.ContainsAny(got, "()") {
		t.Errorf("warning %q uses parentheses", got)
	}
	if again := w.check("lifecycle.sh userspace 12"); again != "" {
		t.Errorf("the same low values warned twice: %q", again)
	}

	set("212992\n", "212992\n")
	if got := w.check("rates.sh userspace"); !strings.Contains(got, "net.core.rmem_max is 212992 and net.core.wmem_max is 212992") {
		t.Errorf("changed low values: got %q", got)
	}

	set("7340032\n", "7340032\n")
	if got := w.check("rates.sh kernel"); got != "" {
		t.Errorf("baseline back: got %q", got)
	}
	set("212992\n", "212992\n")
	if got := w.check("exhaustion.sh userspace wgstall"); got == "" {
		t.Error("low again after the baseline came back: no warning")
	}

	delete(vals, "/proc/sys/net/core/rmem_max")
	vals["/proc/sys/net/core/wmem_max"] = "not a number"
	w.last = ""
	if got := w.check("the pool"); got != "" {
		t.Errorf("unreadable values: got %q", got)
	}
}
