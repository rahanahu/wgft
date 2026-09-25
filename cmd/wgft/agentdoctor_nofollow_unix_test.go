//go:build unix

package main

import (
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"
)

// root で打つ agent doctor は、エージェントの利用者が書けるデータディレクトリの agent.json とロック
// ファイルを信頼しない(9・11 節)。どちらが FIFO でも止まらずに終わり、agent.json が symlink なら辿らずに
// FAILED にする。root の実行を模すため、Euid を 0 にする。
func TestAgentDoctorDoesNotFollowOrBlockOnPlantedFiles(t *testing.T) {
	for name, place := range map[string]func(t *testing.T, cred, lock string){
		"fifos": func(t *testing.T, cred, lock string) {
			if err := syscall.Mkfifo(cred, 0o600); err != nil {
				t.Fatal(err)
			}
			if err := syscall.Mkfifo(lock, 0o600); err != nil {
				t.Fatal(err)
			}
		},
		"symlink to a registered file": func(t *testing.T, cred, lock string) {
			real := filepath.Join(t.TempDir(), "real.json")
			writeTestCredentials(t, real, registeredCredentials())
			if err := os.Symlink(real, cred); err != nil {
				t.Fatal(err)
			}
		},
	} {
		t.Run(name, func(t *testing.T) {
			dir := t.TempDir()
			cred := filepath.Join(dir, "agent.json")
			place(t, cred, cred+".lock")
			in := testAgentDoctorInput(t, dir)
			in.Euid = func() int { return 0 }
			done := make(chan agentDoctorReport, 1)
			go func() { done <- agentDiagnose(in) }()
			var rep agentDoctorReport
			select {
			case rep = <-done:
			case <-time.After(10 * time.Second):
				t.Fatal("agent doctor blocked on a file planted in the data directory")
			}
			c, ok := findAgentCheck(rep, agentCheckCredentials)
			if !ok {
				t.Fatal("no agent.credentials check")
			}
			if c.Status != statusFailed || !strings.Contains(c.Detail, "is not one the agent reads") {
				t.Errorf("agent.credentials = %s: %s; want FAILED naming why the file is refused", c.Status, c.Detail)
			}
			for _, c := range rep.Checks {
				if strings.Contains(c.Detail, "cannot be read as JSON") {
					t.Errorf("%s says the file cannot be read as JSON; it was refused before parsing: %s", c.ID, c.Detail)
				}
			}
		})
	}
}
