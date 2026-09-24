package agent

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"

	"github.com/rahanahu/wgft/internal/agent/credentials"
	"github.com/rahanahu/wgft/proto"
)

// startedAgentCredentials は、登録済みでカーネルモードの記録を持つ認証情報ファイルの中身を作る。
// 鍵は持たない。停止中の rotate-key の後に起動したエージェントが、鍵を作って保存する前の状態である。
func startedAgentCredentials() *credentials.Credentials {
	return &credentials.Credentials{
		Name: "home", Endpoint: "203.0.113.1:8443", PermanentToken: "token",
		Mode: credentials.ModeKernel, PreviousWGPrivateKey: mustKey().String(),
	}
}

func mustKey() wgtypes.Key {
	k, err := wgtypes.GeneratePrivateKey()
	if err != nil {
		panic(err)
	}
	return k
}

func readFile(t *testing.T, path string) []byte {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// 稼働中のエージェントがロックを持つ間、agent pubkey は認証情報ファイルを読むだけで書かない。
func TestPublicKeyReadsOnlyWhileAgentRuns(t *testing.T) {
	path := filepath.Join(t.TempDir(), "agent.json")
	f := startedAgentCredentials()
	k := mustKey()
	f.WGPrivateKey = k.String()
	f.LastState = &proto.State{Generation: 7}
	if err := f.Save(path); err != nil {
		t.Fatal(err)
	}
	lock, err := credentials.Acquire(path)
	if err != nil {
		t.Fatal(err)
	}
	defer lock.Release()
	before := readFile(t, path)

	got, err := PublicKey(path)
	if err != nil {
		t.Fatal(err)
	}
	if got != k.PublicKey() {
		t.Errorf("public key %s, want the running agent's %s", got, k.PublicKey())
	}
	if after := readFile(t, path); !bytes.Equal(after, before) {
		t.Errorf("agent pubkey rewrote agent.json while the agent ran:\n%s", after)
	}
}

// 起動の途中のエージェントと agent pubkey が並行して書き手になる場面を作る。エージェントは鍵の無い
// 状態を保存した後、鍵と全体状態を順に保存していく。その間の agent pubkey は、鍵を作らず、エージェント
// の鍵か「まだ保存されていない」の誤りだけを返す。最後の認証情報ファイルは、エージェントが最後に
// 書いた内容のままである。
func TestPublicKeyDoesNotOverwriteARunningAgent(t *testing.T) {
	path := filepath.Join(t.TempDir(), "agent.json")
	lock, err := credentials.Acquire(path)
	if err != nil {
		t.Fatal(err)
	}
	defer lock.Release()
	f := startedAgentCredentials()
	if err := f.Save(path); err != nil {
		t.Fatal(err)
	}
	k := mustKey()

	const saves = 200
	before := readFile(t, path)
	// 鍵がまだ無い間の呼び出しは、鍵を作らず、ファイルも書かない
	if _, err := PublicKey(path); !errors.Is(err, errKeyNotSavedYet) {
		t.Fatalf("call before the agent saved its key: %v, want errKeyNotSavedYet", err)
	}
	if after := readFile(t, path); !bytes.Equal(after, before) {
		t.Fatalf("agent pubkey rewrote agent.json of a starting agent:\n%s", after)
	}

	keySaved := make(chan struct{})
	agentDone := make(chan error, 1)
	go func() {
		// エージェントの書き手。メモリの上の中身を保存のたびに全体で書き直す
		f.WGPrivateKey = k.String()
		for g := uint64(1); g <= saves; g++ {
			f.LastState = &proto.State{Generation: g}
			if err := retrySharingViolation(func() error { return f.Save(path) }); err != nil {
				agentDone <- err
				return
			}
			if g == 1 {
				close(keySaved)
			}
		}
		agentDone <- nil
	}()

	// 鍵の保存の後は、エージェントの保存と並行して呼ぶ。どれもエージェントの鍵を返す
	<-keySaved
	for i := 0; i < saves; i++ {
		var got wgtypes.Key
		err := retrySharingViolation(func() (err error) { got, err = PublicKey(path); return err })
		if err != nil {
			t.Fatalf("call %d: %v", i, err)
		}
		if got != k.PublicKey() {
			t.Fatalf("call %d returned %s, not the running agent's key %s", i, got, k.PublicKey())
		}
	}
	if err := <-agentDone; err != nil {
		t.Fatal(err)
	}
	g, err := credentials.Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if g.WGPrivateKey != k.String() || g.PermanentToken != "token" || g.Mode != credentials.ModeKernel ||
		g.LastState == nil || g.LastState.Generation != saves {
		t.Errorf("agent.json lost the running agent's state: key %t, token %q, mode %q, last_state %+v",
			g.WGPrivateKey == k.String(), g.PermanentToken, g.Mode, g.LastState)
	}
}

// 稼働中のエージェントがまだ鍵を保存していなければ、agent pubkey は鍵を作らずに誤りを返す。
// 以前は鍵を作って保存し、エージェントが書いた登録やモードの記録を古い内容で上書きしえた。
func TestPublicKeyDoesNotCreateAKeyWhileAgentStarts(t *testing.T) {
	path := filepath.Join(t.TempDir(), "agent.json")
	if err := startedAgentCredentials().Save(path); err != nil {
		t.Fatal(err)
	}
	lock, err := credentials.Acquire(path)
	if err != nil {
		t.Fatal(err)
	}
	defer lock.Release()
	before := readFile(t, path)
	if _, err := PublicKey(path); !errors.Is(err, errKeyNotSavedYet) {
		t.Errorf("err = %v, want errKeyNotSavedYet", err)
	}
	if after := readFile(t, path); !bytes.Equal(after, before) {
		t.Errorf("agent pubkey rewrote agent.json while the agent was starting:\n%s", after)
	}
}

// 判定の後に起動したエージェントがロックを持っていれば、稼働中として扱い、書かない。
func TestPublicKeyTreatsAnAgentThatStartedAfterTheCheckAsRunning(t *testing.T) {
	path := filepath.Join(t.TempDir(), "agent.json")
	if err := startedAgentCredentials().Save(path); err != nil {
		t.Fatal(err)
	}
	lock, err := credentials.Acquire(path)
	if err != nil {
		t.Fatal(err)
	}
	defer lock.Release()
	old := inspectLock
	inspectLock = func(string) (credentials.State, error) { return credentials.Unlocked, nil }
	t.Cleanup(func() { inspectLock = old })
	before := readFile(t, path)
	if _, err := PublicKey(path); !errors.Is(err, errKeyNotSavedYet) {
		t.Errorf("err = %v, want errKeyNotSavedYet", err)
	}
	if after := readFile(t, path); !bytes.Equal(after, before) {
		t.Errorf("agent pubkey rewrote agent.json although an agent held the lock:\n%s", after)
	}
}

// ロックファイルがあって誰も持っていなければ、agent pubkey はロックを取ってから鍵を作って保存する。
func TestPublicKeyWhileStoppedHoldsTheLockWhileWriting(t *testing.T) {
	path := filepath.Join(t.TempDir(), "agent.json")
	if err := startedAgentCredentials().Save(path); err != nil {
		t.Fatal(err)
	}
	lock, err := credentials.Acquire(path) // ロックファイルを作ってから放す。停止したエージェントの跡である
	if err != nil {
		t.Fatal(err)
	}
	lock.Release()
	var held credentials.State
	var savedKey string
	publicKeyLockedHook = func() {
		held, _ = credentials.Inspect(path)
		if g, err := credentials.Load(path); err == nil {
			savedKey = g.WGPrivateKey
		}
	}
	t.Cleanup(func() { publicKeyLockedHook = nil })
	got, err := PublicKey(path)
	if err != nil {
		t.Fatal(err)
	}
	if held != credentials.Locked {
		t.Errorf("the lock state right after saving agent.json was %v, want locked", held)
	}
	if savedKey == "" {
		t.Error("the hook ran before the key was saved; it must see the saved key")
	}
	g, err := credentials.Load(path)
	if err != nil {
		t.Fatal(err)
	}
	priv, err := g.PrivateKey()
	if err != nil || priv.PublicKey() != got {
		t.Errorf("saved key %v, %v; want the printed key %s", priv.PublicKey(), err, got)
	}
	if g.PermanentToken != "token" || g.Mode != credentials.ModeKernel {
		t.Errorf("agent pubkey dropped fields: token %q, mode %q", g.PermanentToken, g.Mode)
	}
	if state, _ := credentials.Inspect(path); state != credentials.Unlocked {
		t.Errorf("lock state after agent pubkey %v, want unlocked", state)
	}
}

// ロックファイルが無ければ、agent pubkey はロックファイルを作らずに鍵を作って保存する。一度も起動して
// いないデータディレクトリでの従来の動作であり、呼び出し元の権限のロックファイルを残さない。
func TestPublicKeyWithoutALockFileLeavesNone(t *testing.T) {
	path := filepath.Join(t.TempDir(), "agent.json")
	got, err := PublicKey(path)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(credentials.LockPath(path)); !os.IsNotExist(err) {
		t.Errorf("agent pubkey created a lock file: %v", err)
	}
	again, err := PublicKey(path)
	if err != nil || again != got {
		t.Errorf("second call = %s, %v; want the saved key %s", again, err, got)
	}
}

// 一度も起動していないデータディレクトリで、ユーザー空間モードのエージェントがロックを取ってから最初に
// 保存するまでの間は、agent.json がまだ無い。この場合も、鍵がまだ無い場合と同じ案内を返し、ファイルを
// 作らない。
func TestPublicKeyWithAHolderAndNoCredentialsFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "agent.json")
	lock, err := credentials.Acquire(path)
	if err != nil {
		t.Fatal(err)
	}
	defer lock.Release()
	if _, err := PublicKey(path); !errors.Is(err, errKeyNotSavedYet) {
		t.Errorf("err = %v, want errKeyNotSavedYet", err)
	}
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Errorf("agent pubkey created agent.json while another process held the lock: %v", err)
	}
}

// ロックの持ち主はエージェントとは限らない。停止中に別の CLI が書いている瞬間にも当たるので、案内は
// 稼働中のエージェントと言い切らず、データディレクトリを別のプロセスが使っていると言う。
func TestPublicKeyNamesTheHolderAsAnotherProcess(t *testing.T) {
	msg := errKeyNotSavedYet.Error()
	if !strings.Contains(msg, "another process is using the data directory") || strings.Contains(msg, "the running agent") {
		t.Errorf("message %q must say another process uses the data directory, not that the agent runs", msg)
	}
}
