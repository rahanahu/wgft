package admin

import (
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"

	"github.com/rahanahu/wgft/internal/vpsd/store"
)

// The disable and enable routes map the Backend's errors to the statuses design.md 7a.11 節 lists,
// and every failure body carries saved: true only for saved-not-published. Another route's failure
// body does not carry it.
func TestAgentChangeRoutesStatusAndSaved(t *testing.T) {
	st, err := store.Open(filepath.Join(t.TempDir(), "s.sqlite"))
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	var next error
	b := &fakeBackend{st: st, agentChange: func(op, name string) (AgentDisabledResponse, error) {
		if next != nil {
			return AgentDisabledResponse{}, next
		}
		return AgentDisabledResponse{Name: name, Disabled: op == "disable", Changed: true, Generation: 4}, nil
	}}
	srv := httptest.NewServer(New(b))
	defer srv.Close()

	type result struct {
		code int
		body map[string]any
	}
	post := func(path string) result {
		t.Helper()
		resp, err := http.Post(srv.URL+path, "application/json", nil)
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		var body map[string]any
		if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
			t.Fatal(err)
		}
		return result{resp.StatusCode, body}
	}

	for _, op := range []string{"disable", "enable"} {
		path := "/api/v1/agents/home/" + op
		next = nil
		if r := post(path); r.code != 200 || r.body["name"] != "home" || r.body["disabled"] != (op == "disable") ||
			r.body["changed"] != true || r.body["generation"] != float64(4) {
			t.Errorf("%s ok = %d %v", op, r.code, r.body)
		}
		for _, c := range []struct {
			err   error
			code  int
			saved bool
		}{
			{&store.AgentNotFoundError{Name: "home"}, 404, false},
			{&AgentChangeError{Saved: false, Err: errors.New("refused")}, 422, false},
			{&AgentChangeError{Saved: true, Err: errors.New("saved: not published")}, 422, true},
			{errors.New("database is locked"), 500, false},
		} {
			next = c.err
			r := post(path)
			if r.code != c.code || r.body["saved"] != c.saved || r.body["error"] != c.err.Error() {
				t.Errorf("%s with %v = %d %v, want %d saved:%v", op, c.err, r.code, r.body, c.code, c.saved)
			}
		}
	}

	resp, err := http.Post(srv.URL+"/api/v1/rules/batch", "application/json", nil)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	var body map[string]any
	json.NewDecoder(resp.Body).Decode(&body)
	if _, ok := body["saved"]; ok || resp.StatusCode != 400 {
		t.Errorf("another route's failure = %d %v, want no saved", resp.StatusCode, body)
	}
}

// The client turns a 422 with saved back into *AgentChangeError and leaves other failures plain.
func TestClientAgentChangeError(t *testing.T) {
	st, err := store.Open(filepath.Join(t.TempDir(), "s.sqlite"))
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	var next error
	b := &fakeBackend{st: st, agentChange: func(op, name string) (AgentDisabledResponse, error) {
		return AgentDisabledResponse{Name: name}, next
	}}
	srv := httptest.NewServer(New(b))
	defer srv.Close()
	c := &Client{Base: srv.URL}
	var ce *AgentChangeError
	for _, saved := range []bool{false, true} {
		next = &AgentChangeError{Saved: saved, Err: errors.New("x")}
		_, err := c.DisableAgent("home")
		if !errors.As(err, &ce) || ce.Saved != saved || err.Error() != "x" {
			t.Errorf("saved %v: %v", saved, err)
		}
	}
	next = &store.AgentNotFoundError{Name: "home"}
	if _, err := c.EnableAgent("home"); err == nil || errors.As(err, &ce) || err.Error() != `agent "home" is not registered` {
		t.Errorf("404 = %v, want a plain error", err)
	}
}
