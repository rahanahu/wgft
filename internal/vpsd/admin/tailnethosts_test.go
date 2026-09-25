package admin

import "testing"

// SetTailnetHosts:tailnet の IP と名前を許可し、差し替えた後は古いものを許可しない。
// --admin-host の名前(AllowedHosts)は差し替えに影響されない。
func TestSetTailnetHosts(t *testing.T) {
	s := &Server{AllowedHosts: []string{"admin.example"}}
	if s.hostAllowed("100.100.1.1") {
		t.Fatalf("tailnet IP allowed before SetTailnetHosts")
	}
	s.SetTailnetHosts([]string{"100.100.1.1", "vps.example.ts.net"})
	for _, h := range []string{"100.100.1.1", "vps.example.ts.net", "admin.example", "localhost"} {
		if !s.hostAllowed(h) {
			t.Errorf("hostAllowed(%q) = false after the first set", h)
		}
	}
	s.SetTailnetHosts([]string{"100.101.0.9"})
	for h, want := range map[string]bool{"100.101.0.9": true, "100.100.1.1": false, "vps.example.ts.net": false, "admin.example": true} {
		if got := s.hostAllowed(h); got != want {
			t.Errorf("hostAllowed(%q) = %v after the replacement, want %v", h, got, want)
		}
	}
}
