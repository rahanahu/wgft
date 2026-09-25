package credentials

import (
	"encoding/json"
	"path/filepath"
	"strings"
	"testing"
)

// FuzzLoadUnmarshal feeds arbitrary bytes as the contents of agent.json (Load's json.Unmarshal,
// credentials.go): a corrupted file, an oversized value, or a value of the wrong JSON type in an
// otherwise well-typed field. agent.json is trusted local state, but it is also the one file most
// likely to be damaged by a crash mid-write, hand-edited by an operator, or (on a shared host)
// truncated or swapped by another process, and Load must degrade to an error rather than a panic
// or a value whose accessor methods panic.
//
// The property: json.Unmarshal into Credentials must never panic, and none of the methods that
// read its fields (RecordedMode, PreviousKey, PrivateKey, KeepPreviousKey) may panic either, no
// matter what strings or oversized numbers land in those fields. A well-formed Credentials value
// must also round-trip: writing it out with Save and reading it back with Load must yield the
// same JSON.
func FuzzLoadUnmarshal(f *testing.F) {
	f.Add([]byte(`{"name":"a","endpoint":"vps:51820","wg_private_key":"","mode":"kernel"}`))
	f.Add([]byte(`{"wg_private_key":"not-base64-at-all"}`))
	f.Add([]byte(`{"wg_private_key":"` + strings.Repeat("A", 1<<20) + `"}`)) // 1 MiB value
	f.Add([]byte(`{"mode":"neither-kernel-nor-userspace"}`))
	f.Add([]byte(`{"ip_forward_enabled_at":"not-a-time"}`))
	f.Add([]byte(`{"ip_forward_enabled_at":123}`))
	f.Add([]byte(`{"kernel_publication":"not-an-object"}`))
	f.Add([]byte(`{"kernel_publication":{}}`))
	f.Add([]byte(`{"kernel_unconverged":[1,2,3]}`))
	f.Add([]byte(`{"last_state":{"generation":-1}}`))
	f.Add([]byte(`{"name":123}`))
	f.Add([]byte(`not json`))
	f.Add([]byte(`{`))
	f.Add([]byte(`null`))
	f.Add([]byte(`[]`))
	f.Add([]byte(``))
	f.Add([]byte("\x00\x01\x02"))

	f.Fuzz(func(t *testing.T, data []byte) {
		var c Credentials
		if err := json.Unmarshal(data, &c); err != nil {
			return
		}
		// None of these accessors may panic, regardless of what strings or nested values made it
		// through JSON unmarshaling into a field of the "right" static type.
		mode := c.RecordedMode()
		if mode != ModeKernel && mode != ModeUserspace && mode != c.Mode {
			t.Fatalf("RecordedMode() = %q for Mode=%q, want ModeKernel, ModeUserspace or Mode itself", mode, c.Mode)
		}
		// PreviousKey documents that an empty PreviousWGPrivateKey means "no previous key", and
		// must therefore succeed with the zero key rather than trying to parse the empty string.
		if _, err := c.PreviousKey(); err != nil && c.PreviousWGPrivateKey == "" {
			t.Fatalf("PreviousKey() failed with an empty PreviousWGPrivateKey: %v", err)
		}
		// PrivateKey has no such empty-string carve-out (EnsureKey is what generates a key for an
		// empty WGPrivateKey); an error here is fine, a panic is not.
		_, _ = c.PrivateKey()
		c.KeepPreviousKey()

		// A value that survived Unmarshal must also survive a Save/Load round-trip: the file
		// format is not lossy for anything Unmarshal itself accepted.
		path := filepath.Join(t.TempDir(), "agent.json")
		if err := c.Save(path); err != nil {
			t.Fatalf("Save a successfully-Unmarshaled Credentials: %v", err)
		}
		got, err := Load(path)
		if err != nil {
			t.Fatalf("Load a just-Saved Credentials: %v", err)
		}
		wantJSON, err := json.Marshal(&c)
		if err != nil {
			t.Fatalf("Marshal the original Credentials: %v", err)
		}
		gotJSON, err := json.Marshal(got)
		if err != nil {
			t.Fatalf("Marshal the round-tripped Credentials: %v", err)
		}
		if string(wantJSON) != string(gotJSON) {
			t.Fatalf("Save/Load round-trip changed the value:\n original = %s\n reloaded = %s", wantJSON, gotJSON)
		}
	})
}
