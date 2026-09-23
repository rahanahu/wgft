package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"io/fs"
	"net"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/rahanahu/wgft/internal/agent/credentials"
	"github.com/rahanahu/wgft/internal/flock"
	"github.com/rahanahu/wgft/proto"
)

// このファイルは `wgft agent doctor`(設計文書 10.2c 節)の表のテストである。節が定めた規則を
// そのまま入力に写し、場面ごとの検査の状態と理由の符号を確かめる。節の対応をそのまま入力に
// 写すことで、実装者が途中で意味を解釈し直す余地を減らす(10.2c 節、所有者の決定)。

// agentDoctorTable は 10.2c 節の「検査の一覧と証拠の出どころ」の表そのものである。実装の
// agentCheckOrder と agentLiveOnly から作らずに書き下すのは、実装がこの表からずれたときに
// テストが落ちるようにするためである。
var agentDoctorTable = []struct {
	id      string
	group   string
	label   string
	verdict bool // 「総合判定」の列
}{
	{"host.platform", "Host", "platform", false},
	{"host.privileges", "Host", "privileges", false},
	{"host.interfaces", "Host", "interfaces", false},
	{"host.resolve", "Host", "endpoint resolve", false},
	{"agent.credentials", "Credentials", "credentials", true},
	{"agent.process", "Credentials", "process", true},
	{"agent.last_state", "Credentials", "last state", false},
	{"agent.control", "Connection", "control socket", false},
	{"stream.connection", "Connection", "control connection", false},
	{"stream.backoff", "Connection", "reconnect backoff", false},
	{"stream.liveness", "Connection", "liveness", false},
	{"tunnel.resolve", "Tunnel", "wg endpoint resolve", false},
	{"tunnel.local", "Tunnel", "tunnel", true},
	{"tunnel.watchdog", "Tunnel", "watchdog", false},
	{"tunnel.transfer", "Tunnel", "transfer", false},
	{"relay.listeners", "Relay", "listeners", true},
	{"relay.sessions", "Relay", "sessions", false},
	{"relay.refusals", "Relay", "refusals", false},
	{"relay.allow_targets", "Relay", "target allowlist", false},
}

// どの実行でも、10.2c 節の表の検査がすべて、表の順で、表の群と見出しと総合判定の区別を持って
// 出る。実行の状態によって項目そのものが消える形は採らない(10.2c 節)。
func TestAgentDoctorEmitsTheDesignTable(t *testing.T) {
	dir := t.TempDir()
	rep := agentDiagnose(testAgentDoctorInput(t, dir))
	if len(rep.Checks) != len(agentDoctorTable) {
		t.Fatalf("%d checks, want %d", len(rep.Checks), len(agentDoctorTable))
	}
	for i, want := range agentDoctorTable {
		got := rep.Checks[i]
		if got.ID != want.id {
			t.Errorf("check %d is %q, want %q", i, got.ID, want.id)
			continue
		}
		if got.Group != want.group || got.Label != want.label {
			t.Errorf("%s: group %q label %q, want %q and %q", got.ID, got.Group, got.Label, want.group, want.label)
		}
		if got.verdict != want.verdict {
			t.Errorf("%s: moves the overall verdict = %v, want %v", got.ID, got.verdict, want.verdict)
		}
		if got.Status == statusFailed && got.Next == "" {
			t.Errorf("%s is FAILED with nothing to check next; design 10.2a and 10.2c require it", got.ID)
		}
		if got.Status == "" || got.Detail == "" {
			t.Errorf("%s has an empty status or detail", got.ID)
		}
	}
}

// 診断は読むだけで何も変えない。ロックファイルも認証情報ファイルも作らない(10.2c 節)。
func TestAgentDoctorCreatesNothing(t *testing.T) {
	dir := t.TempDir()
	agentDiagnose(testAgentDoctorInput(t, dir))
	names, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(names) != 0 {
		var got []string
		for _, e := range names {
			got = append(got, e.Name())
		}
		t.Errorf("the data directory holds %v after a diagnosis; it must hold nothing", got)
	}
}

// 認証情報ファイルの読み取りは credentials.Load を通らない。Load は読み取りに続けて Windows の
// DACL を毎回書き直すので、診断が副作用を持たないという約束を破る(10.2c 節)。稼働の判定も
// flock.Acquire を通らない。Acquire はロックファイルを作る。
func TestAgentDoctorAvoidsTheWritingEntryPoints(t *testing.T) {
	b, err := os.ReadFile("agentdoctor.go")
	if err != nil {
		t.Fatal(err)
	}
	src := string(b)
	// 呼び出しの形だけを見る。この節の決定を説明する註釈が同じ名前を挙げるので、識別子だけでは
	// 註釈まで拾ってしまう。
	for _, banned := range []string{"credentials.Load(", "credentials.LoadOrNew(", "flock.Acquire(", "credentials.Acquire("} {
		if strings.Contains(src, banned) {
			t.Errorf("agentdoctor.go calls %s; it writes, and the static checks must only read", banned)
		}
	}
}

// 認証情報ファイルを読んでも、そのパーミッションと中身は変わらない。
func TestAgentDoctorLeavesTheCredentialsFileAlone(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "agent.json")
	writeTestCredentials(t, path, registeredCredentials())
	if err := os.Chmod(path, 0o600); err != nil {
		t.Fatal(err)
	}
	before, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	fi, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	agentDiagnose(testAgentDoctorInput(t, dir))
	after, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(before, after) {
		t.Error("the credentials file changed during a diagnosis")
	}
	fi2, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if fi.Mode() != fi2.Mode() {
		t.Errorf("the credentials file's mode changed from %v to %v during a diagnosis", fi.Mode(), fi2.Mode())
	}
}

// 何も壊れていない実行でも、試していない範囲を必ず出力する。黙っていると運用者が沈黙を健全と
// 読むためである(10.2a、10.2c 節)。一覧の項目と、人向けの出力に出ることの両方を固定する。
func TestAgentDoctorAlwaysNamesWhatItDidNotTest(t *testing.T) {
	dir := t.TempDir()
	writeTestCredentials(t, filepath.Join(dir, "agent.json"), registeredCredentials())
	holdTheLock(t, filepath.Join(dir, "agent.json"))
	rep := agentDiagnose(testAgentDoctorInput(t, dir))
	want := []string{"the server side", "reaching the vps", "the targets", "local settings"}
	var got []string
	for _, n := range rep.NotTested {
		got = append(got, n.ID)
		if strings.TrimSpace(n.Detail) == "" {
			t.Errorf("the untested item %q says nothing about what was not tested", n.ID)
		}
	}
	if strings.Join(got, ",") != strings.Join(want, ",") {
		t.Errorf("the untested items are %v, want %v", got, want)
	}
	var b bytes.Buffer
	writeAgentDoctorReport(&b, rep)
	for _, id := range want {
		if !strings.Contains(b.String(), id) {
			t.Errorf("the output does not name %q as untested:\n%s", id, b.String())
		}
	}
}

// `agent.json` から読んだ値には `agent ls` および 10.2a 節と同じ `last:` の接頭辞を付け、今の
// 観測と区別する(10.2c 節)。あわせて、節の表が `agent.credentials` の「見るもの」に挙げた証拠を
// すべて示すことを固定する。
func TestAgentDoctorShowsTheRecordedEvidence(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "agent.json")
	writeTestCredentials(t, path, registeredCredentials())
	if err := os.Chmod(path, 0o600); err != nil {
		t.Fatal(err)
	}
	rep := agentDiagnose(testAgentDoctorInput(t, dir))
	cred, _ := findAgentCheck(rep, agentCheckCredentials)
	last, _ := findAgentCheck(rep, agentCheckLastState)
	for _, c := range []agentDoctorCheck{cred, last} {
		if !strings.HasPrefix(c.Detail, "last:") {
			t.Errorf("%s reads %q; a value saved in agent.json carries the last: prefix, so it is not read as a current observation", c.ID, c.Detail)
		}
	}
	// 節の表が挙げる証拠。値そのものではなく、示していることを見る。
	for _, want := range []string{`"home"`, "203.0.113.10:8443", "sha256:012345678", "sha256:fedcba987"} {
		if !strings.Contains(cred.Detail, want) {
			t.Errorf("agent.credentials does not show %s: %q", want, cred.Detail)
		}
	}
	if runtime.GOOS != "windows" && !strings.Contains(cred.Detail, "mode 0600") {
		t.Errorf("agent.credentials does not show the credentials file's permissions: %q", cred.Detail)
	}
	if !strings.Contains(last.Detail, "generation 12") || !strings.Contains(last.Detail, "2 rules") {
		t.Errorf("agent.last_state does not show the recorded generation and rule count: %q", last.Detail)
	}
}

// 認証情報ファイルが他の利用者にも読める配置では、締め直し方を所見に添える。恒久トークンを
// 持つファイルなので、緩いまま黙って通さない。状態は下げない。緩いパーミッションは転送を
// 止めないためである。
func TestAgentDoctorNamesLooseCredentialsPermissions(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("the mode bits this check reads are not how Windows expresses the same thing")
	}
	dir := t.TempDir()
	path := filepath.Join(dir, "agent.json")
	writeTestCredentials(t, path, registeredCredentials())
	if err := os.Chmod(path, 0o644); err != nil {
		t.Fatal(err)
	}
	rep := agentDiagnose(testAgentDoctorInput(t, dir))
	cred, _ := findAgentCheck(rep, agentCheckCredentials)
	if cred.Status != statusOK {
		t.Errorf("agent.credentials = %s; a loose mode does not stop forwarding, so it does not lower the status", cred.Status)
	}
	if !strings.Contains(cred.Detail, "chmod 0600") {
		t.Errorf("agent.credentials does not say how to tighten a world-readable credentials file: %q", cred.Detail)
	}
}

// 権限の検査は、満たさなかった対象だけでなく満たした対象も示す。どこまで読めてどこから権限で
// 読めなかったかを示すほうが、運用者は直せる(10.2c 節)。
func TestAgentDoctorPrivilegesKeepsWhatItCouldRead(t *testing.T) {
	if os.Geteuid() == 0 || runtime.GOOS == "windows" {
		t.Skip("this scenario needs a file that refuses the running user; root refuses nothing and Windows does not answer os.Chmod that way")
	}
	dir := t.TempDir()
	path := filepath.Join(dir, "agent.json")
	writeTestCredentials(t, path, registeredCredentials())
	chmodForTest(t, path, 0)
	in := testAgentDoctorInput(t, dir)
	rep := agentDiagnose(in)
	priv, _ := findAgentCheck(rep, agentCheckPrivileges)
	if priv.Status != statusFailed {
		t.Fatalf("host.privileges = %s, want failed", priv.Status)
	}
	if !strings.Contains(priv.Detail, "agent.json cannot be read") {
		t.Errorf("host.privileges does not name the target it was refused: %q", priv.Detail)
	}
	if !strings.Contains(priv.Detail, "the data directory is readable") {
		t.Errorf("host.privileges drops the targets it did reach: %q", priv.Detail)
	}
	if !strings.Contains(priv.Detail, "new files can be created") {
		t.Errorf("host.privileges drops the targets it did reach: %q", priv.Detail)
	}
}

// want は 1 件の検査に期待する状態と理由の符号である。
type wantCheck struct {
	id     string
	status string
	reason string
}

// 10.2c 節の規則をそのまま入力にした表である。場面を並べ、その場面で節が定める状態と理由の符号を
// 書く。権限に依る場面は root では成り立たないので飛ばす。
func TestAgentDoctorScenarios(t *testing.T) {
	for _, tc := range []struct {
		name string
		// needsUnixPermissions は、Unix のパーミッションに依る場面である。root はすべて読める
		// ので権限で届かない場面そのものを作れず、Windows の os.Chmod は読み取りを禁じない。
		needsUnixPermissions bool
		// setup はデータディレクトリを場面の状態にし、入力に手を入れる。
		setup func(t *testing.T, in *agentDoctorInput)
		want  []wantCheck
		// wantExit は 10.2c 節の終了コードの表のとおりの値である。
		wantExit int
	}{
		{
			// データディレクトリが無い実行では、host.privileges はそれを作れる親ディレクトリの
			// 権限を見る。不在という事実そのものは agent.credentials が答える(10.2c 節)。
			name: "the data directory does not exist",
			setup: func(t *testing.T, in *agentDoctorInput) {
				in.DataDir = filepath.Join(in.DataDir, "not-created-yet")
				in.CredentialsPath = filepath.Join(in.DataDir, "agent.json")
			},
			want: []wantCheck{
				{agentCheckPrivileges, statusOK, ""},
				{agentCheckCredentials, statusFailed, agentReasonCredentialsMissing},
				{agentCheckProcess, statusFailed, agentReasonNotRunning},
			},
			wantExit: 1,
		},
		{
			name:  "the credentials file is missing",
			setup: func(t *testing.T, in *agentDoctorInput) {},
			want: []wantCheck{
				{agentCheckCredentials, statusFailed, agentReasonCredentialsMissing},
				// 中身に依存する検査は、手前の失敗によって試せなかった項目として SKIPPED。
				{agentCheckHostResolve, statusSkipped, agentReasonCredentialsMissing},
				{agentCheckLastState, statusSkipped, agentReasonCredentialsMissing},
				{agentCheckWGResolve, statusSkipped, agentReasonCredentialsMissing},
			},
			wantExit: 1,
		},
		{
			// まだ登録していないことは、診断を始められなかった失敗ではなく、エージェント自身の
			// 状態についての事実なので、2 ではなく agent.credentials の FAILED として 1 にする。
			name: "the credentials file is there but this host has not registered",
			setup: func(t *testing.T, in *agentDoctorInput) {
				writeTestCredentials(t, in.CredentialsPath, &credentials.Credentials{})
			},
			want: []wantCheck{
				{agentCheckCredentials, statusFailed, agentReasonNotRegistered},
				{agentCheckHostResolve, statusSkipped, agentReasonNotRegistered},
				{agentCheckLastState, statusSkipped, agentReasonNotRegistered},
				{agentCheckWGResolve, statusSkipped, agentReasonNotRegistered},
			},
			wantExit: 1,
		},
		{
			name: "the credentials file is there and this host is registered",
			setup: func(t *testing.T, in *agentDoctorInput) {
				writeTestCredentials(t, in.CredentialsPath, registeredCredentials())
				holdTheLock(t, in.CredentialsPath)
			},
			want: []wantCheck{
				{agentCheckCredentials, statusOK, ""},
				{agentCheckProcess, statusOK, ""},
				{agentCheckHostResolve, statusOK, ""},
				{agentCheckLastState, statusOK, ""},
				{agentCheckWGResolve, statusOK, ""},
			},
			wantExit: 0,
		},
		{
			// 中身が壊れていて JSON として読めないことも、1 の側である(10.2c 節)。
			name: "the credentials file is not JSON",
			setup: func(t *testing.T, in *agentDoctorInput) {
				if err := os.WriteFile(in.CredentialsPath, []byte("{not json"), 0o600); err != nil {
					t.Fatal(err)
				}
			},
			want: []wantCheck{
				{agentCheckCredentials, statusFailed, agentReasonCredentialsMalformed},
				{agentCheckHostResolve, statusSkipped, agentReasonCredentialsMalformed},
				{agentCheckLastState, statusSkipped, agentReasonCredentialsMalformed},
				{agentCheckWGResolve, statusSkipped, agentReasonCredentialsMalformed},
			},
			wantExit: 1,
		},
		{
			// ロックファイルが無いのは、一度も起動していない場合と運用者が消した場合がある。
			// どちらも稼働の証拠が無い点では同じであり、停止そのものは FAILED として扱う。
			name:  "there is no lock file",
			setup: func(t *testing.T, in *agentDoctorInput) {},
			want: []wantCheck{
				{agentCheckProcess, statusFailed, agentReasonNotRunning},
				{agentCheckControl, statusSkipped, agentReasonNotRunning},
				{agentCheckTunnelLocal, statusSkipped, agentReasonNotRunning},
				{agentCheckListeners, statusSkipped, agentReasonNotRunning},
				// 宛先の許可一覧だけが例外で、停止中は UNKNOWN になる。
				{agentCheckAllowTargets, statusUnknown, agentReasonNotRunning},
			},
			wantExit: 1,
		},
		{
			name: "the lock file is there and nobody holds it",
			setup: func(t *testing.T, in *agentDoctorInput) {
				l, err := flock.Acquire(in.CredentialsPath)
				if err != nil {
					t.Fatal(err)
				}
				if err := l.Release(); err != nil {
					t.Fatal(err)
				}
			},
			want: []wantCheck{
				{agentCheckProcess, statusFailed, agentReasonNotRunning},
				{agentCheckAllowTargets, statusUnknown, agentReasonNotRunning},
			},
			wantExit: 1,
		},
		{
			name: "the lock file is held by a running agent",
			setup: func(t *testing.T, in *agentDoctorInput) {
				writeTestCredentials(t, in.CredentialsPath, registeredCredentials())
				holdTheLock(t, in.CredentialsPath)
			},
			want: []wantCheck{
				{agentCheckProcess, statusOK, ""},
				// このデータディレクトリには制御ソケットが無いので、稼働中のプロセスからしか
				// 取れない検査は繋げなかった場合として並ぶ。稼働中に繋げない実行では、宛先の
				// 許可一覧も停止中の UNKNOWN ではなく SKIPPED である(10.2c 節)。
				{agentCheckControl, statusFailed, agentReasonControlUnreachable},
				{agentCheckTunnelLocal, statusSkipped, agentReasonControlUnreachable},
				{agentCheckAllowTargets, statusSkipped, agentReasonControlUnreachable},
			},
			// 制御ソケットに繋げないことは、終了コード 1 が答える問いに対して偽である。
			wantExit: 0,
		},
		{
			// ロックファイルがあるのに権限で開けない場合は、稼働中か停止中かを判定できないので、
			// 前提が崩れている実行として終了コード 2 の側に置く(10.2c 節)。
			name:                 "the lock file cannot be opened",
			needsUnixPermissions: true,
			setup: func(t *testing.T, in *agentDoctorInput) {
				writeTestCredentials(t, in.CredentialsPath, registeredCredentials())
				l, err := flock.Acquire(in.CredentialsPath)
				if err != nil {
					t.Fatal(err)
				}
				if err := l.Release(); err != nil {
					t.Fatal(err)
				}
				chmodForTest(t, flock.LockPath(in.CredentialsPath), 0)
			},
			want: []wantCheck{
				{agentCheckProcess, statusUnknown, agentReasonLockUnreadable},
				{agentCheckControl, statusSkipped, agentReasonRunStateUnknown},
				{agentCheckAllowTargets, statusUnknown, agentReasonRunStateUnknown},
			},
			wantExit: 2,
		},
		{
			// 層 1 の FAILED と層 2 の条件が同じ実行で同時に成り立つ場合、2 を優先する。2 は
			// 診断の結果を信頼できないことを表すためである(10.2c 節)。
			name:                 "a verdict check fails while some evidence cannot be read",
			needsUnixPermissions: true,
			setup: func(t *testing.T, in *agentDoctorInput) {
				l, err := flock.Acquire(in.CredentialsPath)
				if err != nil {
					t.Fatal(err)
				}
				if err := l.Release(); err != nil {
					t.Fatal(err)
				}
				chmodForTest(t, flock.LockPath(in.CredentialsPath), 0)
			},
			want: []wantCheck{
				// 認証情報ファイルが無いことは層 1 の FAILED である。
				{agentCheckCredentials, statusFailed, agentReasonCredentialsMissing},
				{agentCheckProcess, statusUnknown, agentReasonLockUnreadable},
			},
			wantExit: 2,
		},
		{
			// 全体状態を一度も受け取っていない事実を理由に示す(10.2c 節)。
			name: "no full state has ever been received",
			setup: func(t *testing.T, in *agentDoctorInput) {
				f := registeredCredentials()
				f.LastState = nil
				writeTestCredentials(t, in.CredentialsPath, f)
				holdTheLock(t, in.CredentialsPath)
			},
			want: []wantCheck{
				{agentCheckCredentials, statusOK, ""},
				{agentCheckLastState, statusUnknown, agentReasonNoLastState},
				{agentCheckWGResolve, statusUnknown, agentReasonNoLastState},
			},
			wantExit: 0,
		},
		{
			// 名前解決の失敗は、今後の再接続が危ういという証拠ではあっても、今この瞬間に転送を
			// 担えないという証拠ではない。状態は FAILED ではなく UNKNOWN にし、総合判定も終了
			// コードも動かさない(10.2c 節)。
			name: "the endpoint's name does not resolve",
			setup: func(t *testing.T, in *agentDoctorInput) {
				f := registeredCredentials()
				f.Endpoint = "vps.example.net:8443"
				f.LastState.WG.Endpoint = "vps.example.net:51820"
				writeTestCredentials(t, in.CredentialsPath, f)
				holdTheLock(t, in.CredentialsPath)
				in.Resolve = func(context.Context, string) ([]string, error) {
					return nil, errors.New("no such host")
				}
			},
			want: []wantCheck{
				{agentCheckHostResolve, statusUnknown, agentReasonResolveFailed},
				{agentCheckWGResolve, statusUnknown, agentReasonResolveFailed},
				{agentCheckProcess, statusOK, ""},
			},
			wantExit: 0,
		},
		{
			// 副作用なしには判定できない検査は、成功でも失敗でもない UNKNOWN とする。Windows の
			// 「新しいファイルを作れるか」が当たる(10.2c 節)。
			name: "whether a new file can be created cannot be determined",
			setup: func(t *testing.T, in *agentDoctorInput) {
				writeTestCredentials(t, in.CredentialsPath, registeredCredentials())
				holdTheLock(t, in.CredentialsPath)
				in.DirCreateAccess = func(string) (accessResult, error) {
					return accessNotDetermined, errors.New("ACLs are not evaluated here")
				}
			},
			want: []wantCheck{
				{agentCheckPrivileges, statusUnknown, agentReasonPermissionNotDetermined},
			},
			// 判定できないだけでは終了コードを動かさない。証拠そのものに権限で到達できなかった
			// 実行ではないためである。
			wantExit: 0,
		},
		{
			// 呼び出し元が権限で証拠に届かない実行は、診断が成立しなかった側に倒す。状態の語は
			// FAILED でよく、終了コードだけが 2 になる(10.2c 節)。
			name:                 "the data directory cannot be read",
			needsUnixPermissions: true,
			setup: func(t *testing.T, in *agentDoctorInput) {
				writeTestCredentials(t, in.CredentialsPath, registeredCredentials())
				holdTheLock(t, in.CredentialsPath)
				// 読めないが、たどれて書ける。新しいファイルを作る権限はあるままにする。
				chmodForTest(t, in.DataDir, 0o300)
			},
			want: []wantCheck{
				{agentCheckPrivileges, statusFailed, agentReasonPermissionDenied},
				{agentCheckProcess, statusOK, ""},
			},
			wantExit: 2,
		},
		{
			// agent.json があるのに権限で読めないことは 2 にする。呼び出し元がエージェントと同じ
			// 実行主体で動いていないために起きる失敗であり、エージェントが転送を担えるかどうかに
			// ついては何も述べない(10.2c 節)。
			name:                 "the credentials file cannot be read",
			needsUnixPermissions: true,
			setup: func(t *testing.T, in *agentDoctorInput) {
				writeTestCredentials(t, in.CredentialsPath, registeredCredentials())
				holdTheLock(t, in.CredentialsPath)
				chmodForTest(t, in.CredentialsPath, 0)
			},
			want: []wantCheck{
				{agentCheckCredentials, statusUnknown, agentReasonCredentialsUnreadable},
				{agentCheckHostResolve, statusSkipped, agentReasonCredentialsUnreadable},
				{agentCheckLastState, statusSkipped, agentReasonCredentialsUnreadable},
				{agentCheckWGResolve, statusSkipped, agentReasonCredentialsUnreadable},
			},
			wantExit: 2,
		},
		{
			// 節は層 2 の条件として `host.privileges` の失敗と `agent.credentials` の権限による
			// 読み取りの失敗を別々に挙げている。前の場面は両方を同時に成り立たせるので、
			// `agent.credentials` だけが終了コード 2 を出せるかどうかを固定できない。この場面は
			// `host.privileges` が見る権限を満たしたまま、読み取りだけを失敗させる。
			// 設定ファイルを権限で読めないことは、報告を拒む理由ではなく診断の結果である
			// (10.2c 節の層 2)。読めなかった事実を host.privileges が示し、その設定に依る
			// メモリのソフト上限の予測を host.platform が示さず、残りの検査は通常どおり答える。
			name: "the config file cannot be read",
			setup: func(t *testing.T, in *agentDoctorInput) {
				writeTestCredentials(t, in.CredentialsPath, registeredCredentials())
				holdTheLock(t, in.CredentialsPath)
				in.ConfigUnreadable = fs.ErrPermission
			},
			want: []wantCheck{
				{agentCheckPlatform, statusUnknown, agentReasonConfigUnreadable},
				{agentCheckPrivileges, statusFailed, agentReasonPermissionDenied},
				// 手前の失敗ではないので、認証情報とロックを読む検査はそのまま答える。
				{agentCheckCredentials, statusOK, ""},
				{agentCheckProcess, statusOK, ""},
				{agentCheckLastState, statusOK, ""},
			},
			wantExit: 2,
		},
		{
			// 設定ファイルが無い配置は正しい。値は環境変数と既定から決まるので、失敗にしない。
			name: "the config file does not exist",
			setup: func(t *testing.T, in *agentDoctorInput) {
				writeTestCredentials(t, in.CredentialsPath, registeredCredentials())
				holdTheLock(t, in.CredentialsPath)
				in.ConfigPath = filepath.Join(in.DataDir, "none.env")
				in.ConfigUnreadable = nil
			},
			want: []wantCheck{
				{agentCheckPlatform, statusOK, ""},
				{agentCheckPrivileges, statusOK, ""},
				{agentCheckCredentials, statusOK, ""},
			},
			wantExit: 0,
		},
		{
			name:                 "only the credentials file cannot be read",
			needsUnixPermissions: true,
			setup: func(t *testing.T, in *agentDoctorInput) {
				writeTestCredentials(t, in.CredentialsPath, registeredCredentials())
				holdTheLock(t, in.CredentialsPath)
				chmodForTest(t, in.CredentialsPath, 0)
				// host.privileges の 3 つの対象をすべて満たした状態に置く。差し替えるのは
				// 権限の判定だけで、認証情報ファイルの読み取りは実際のファイルに当たる。
				in.Readable = func(string, bool) (accessResult, error) { return accessAllowed, nil }
			},
			want: []wantCheck{
				{agentCheckPrivileges, statusOK, ""},
				{agentCheckProcess, statusOK, ""},
				{agentCheckCredentials, statusUnknown, agentReasonCredentialsUnreadable},
			},
			wantExit: 2,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if tc.needsUnixPermissions && (os.Geteuid() == 0 || runtime.GOOS == "windows") {
				t.Skip("this scenario needs a user that some file refuses; root refuses nothing and Windows does not answer os.Chmod that way")
			}
			in := testAgentDoctorInput(t, t.TempDir())
			tc.setup(t, &in)
			rep := agentDiagnose(in)
			for _, w := range tc.want {
				got, ok := findAgentCheck(rep, w.id)
				if !ok {
					t.Errorf("%s is missing from the report", w.id)
					continue
				}
				if got.Status != w.status || got.Reason != w.reason {
					t.Errorf("%s = %s/%q, want %s/%q; detail: %s", w.id, got.Status, got.Reason, w.status, w.reason, got.Detail)
				}
			}
			if code := agentDoctorExitCode(rep); code != tc.wantExit {
				t.Errorf("exit code = %d, want %d", code, tc.wantExit)
			}
		})
	}
}

// 終了コードの 3 つの層そのものを、報告を組み立てて確かめる(10.2c 節)。UNKNOWN、NOT TESTED、
// SKIPPED だけでは 0 のままであり、総合判定を動かさない検査の FAILED も 0 のままである。
func TestAgentDoctorExitLayers(t *testing.T) {
	for _, tc := range []struct {
		name   string
		checks []agentDoctorCheck
		want   int
	}{
		{"nothing failed", []agentDoctorCheck{{ID: agentCheckProcess, Status: statusOK, verdict: true}}, 0},
		{
			"only unknown and skipped",
			[]agentDoctorCheck{
				{ID: agentCheckHostResolve, Status: statusUnknown},
				{ID: agentCheckControl, Status: statusSkipped},
				{ID: agentCheckAllowTargets, Status: statusUnknown},
			},
			0,
		},
		{
			// 総合判定を動かさない検査は、FAILED でも終了コードを動かさない。所見としては出す。
			"a check outside the verdict failed",
			[]agentDoctorCheck{{ID: agentCheckInterfaces, Status: statusFailed}},
			0,
		},
		{
			"a verdict check failed",
			[]agentDoctorCheck{{ID: agentCheckProcess, Label: "process", Status: statusFailed, verdict: true}},
			1,
		},
		{
			// 層 2 は、状態の語が FAILED でなくても効く。
			"evidence could not be read",
			[]agentDoctorCheck{{ID: agentCheckProcess, Label: "process", Status: statusUnknown, verdict: true, evidenceUnreachable: true}},
			2,
		},
		{
			// 層 2 は層 1 に優先する。
			"both layers at once",
			[]agentDoctorCheck{
				{ID: agentCheckCredentials, Label: "credentials", Status: statusFailed, verdict: true},
				{ID: agentCheckPrivileges, Label: "privileges", Status: statusFailed, evidenceUnreachable: true},
			},
			2,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := agentDoctorExitCode(agentDoctorReport{Checks: tc.checks}); got != tc.want {
				t.Errorf("exit code = %d, want %d", got, tc.want)
			}
		})
	}
}

// 人向けの出力は群ごとに並び、FAILED には次に見るものが付き、History と試していない範囲を必ず
// 出す(10.2a、10.2c 節)。`Result:` の行は持たない。
func TestAgentDoctorHumanOutput(t *testing.T) {
	dir := t.TempDir()
	writeTestCredentials(t, filepath.Join(dir, "agent.json"), registeredCredentials())
	var b bytes.Buffer
	writeAgentDoctorReport(&b, agentDiagnose(testAgentDoctorInput(t, dir)))
	out := b.String()
	at := 0
	for _, want := range []string{"Host\n", "Credentials\n", "Connection\n", "Tunnel\n", "Relay\n", "History\n", "Not tested by this command\n"} {
		i := strings.Index(out[at:], want)
		if i < 0 {
			t.Fatalf("the output has no %q after the previous heading:\n%s", want, out)
		}
		at += i
	}
	for _, want := range []string{
		"process            FAILED",
		"Check: start it and read why it stopped",
		"the agent is not running, so its live state was not read",
		"when it broke      NOT AVAILABLE",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("the output has no %q:\n%s", want, out)
		}
	}
	if strings.Contains(out, "Result:") {
		t.Error("the output has a Result: line; agent doctor does not follow a path, so it cannot name where traffic stopped")
	}
}

// 層 2 に当たる実行でも報告は出し、どこまで読めてどこから権限で読めなかったかを示す。root での
// 実行し直しは案内しない(10.2c 節)。
func TestAgentDoctorHumanOutputSaysWhenEvidenceIsMissing(t *testing.T) {
	var b bytes.Buffer
	writeAgentDoctorReport(&b, agentDoctorReport{Checks: []agentDoctorCheck{
		{ID: agentCheckPrivileges, Group: agentGroupHost, Label: "privileges", Status: statusFailed,
			Reason: agentReasonPermissionDenied, Detail: "the data directory cannot be read", Next: agentSamePrincipalNext,
			evidenceUnreachable: true},
	}})
	out := b.String()
	if !strings.Contains(out, "Incomplete") {
		t.Errorf("the output does not say the report is incomplete:\n%s", out)
	}
	if !strings.Contains(out, "run this command as the user the agent runs as") {
		t.Errorf("the output does not say to re-run it as the agent's own user:\n%s", out)
	}
	// 地の文に埋め込む側は、ピリオドの後なので文として始まる。
	if !strings.Contains(out, "forward. Run this command as") {
		t.Errorf("the sentence after the period starts in lower case:\n%s", out)
	}
	if strings.Contains(strings.ToLower(out), "as root") || strings.Contains(out, "sudo") {
		t.Errorf("the output tells the operator to re-run as root; that hides the broken assumption:\n%s", out)
	}
}

// 稼働を判定できない実行では、宛先の許可一覧の所見も「判定できなかった」に揃える。同じ報告の
// agent.process が判定できなかったと述べている横で、この検査だけがエージェントは動いていないと
// 断定すると、動いているエージェントについて事実でないことを述べる(10.2c 節)。
func TestAgentDoctorAllowTargetsWhenTheRunStateIsUnknown(t *testing.T) {
	unknown := agentRunState{State: flock.Unknown, Err: errors.New("permission denied"), PermissionDenied: true}
	checks := agentLiveChecks(agentDoctorInput{}, unknown, agentLive{Kind: liveNotAttempted})
	var allow agentDoctorCheck
	for _, c := range checks {
		if c.ID == agentCheckAllowTargets {
			allow = c
		}
	}
	if allow.Status != statusUnknown || allow.Reason != agentReasonRunStateUnknown {
		t.Fatalf("relay.allow_targets = %s/%q, want %s/%q", allow.Status, allow.Reason, statusUnknown, agentReasonRunStateUnknown)
	}
	if strings.Contains(allow.Detail, "no process holds it now") {
		t.Errorf("relay.allow_targets says the agent is stopped although the run state could not be determined: %q", allow.Detail)
	}
	if !strings.Contains(allow.Detail, "could not be determined") {
		t.Errorf("relay.allow_targets does not say the run state could not be determined: %q", allow.Detail)
	}
	if strings.HasPrefix(allow.Next, "start the agent") {
		t.Errorf("relay.allow_targets tells the operator to start an agent that may already be running: %q", allow.Next)
	}
	// 停止していると判定できた実行は、今までどおり停止中の文面のままである。
	stopped := agentLiveChecks(agentDoctorInput{}, agentRunState{State: flock.Absent}, agentLive{Kind: liveNotAttempted})
	for _, c := range stopped {
		if c.ID != agentCheckAllowTargets {
			continue
		}
		if !strings.Contains(c.Detail, "no process holds it now") {
			t.Errorf("a stopped agent's relay.allow_targets lost the stopped wording: %q", c.Detail)
		}
	}
}

// 設定ファイルを権限で読めない実行でも、`agent doctor` は報告を出し、終了コード 2 で終わる。
// 実機で見つかった欠陥は、この経路が報告を組む手前で終了コード 3 の拒否になっていたことである。
func TestAgentDoctorReportsAnUnreadableConfigFile(t *testing.T) {
	if runtime.GOOS == "windows" || os.Geteuid() == 0 {
		t.Skip("this scenario needs a file that refuses the running user; root refuses nothing and Windows does not answer os.Chmod that way")
	}
	dir := t.TempDir()
	config := filepath.Join(dir, "agent.env")
	if err := os.WriteFile(config, []byte("WGFT_MAX_UDP_FLOWS=2048\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	chmodForTest(t, config, 0)
	var out bytes.Buffer
	root := newRootCmd()
	root.SetArgs([]string{"agent", "doctor", "--config", config, "--data-dir", filepath.Join(dir, "data")})
	root.SetOut(&out)
	root.SetErr(io.Discard)
	err := root.Execute()
	if got := exitCode(err); err == nil || got != exitUnavailable {
		t.Fatalf("err=%v exitCode=%d, want %d; an unreadable config file is a finding, not a reason to refuse the report", err, got, exitUnavailable)
	}
	report := out.String()
	for _, want := range []string{"Host\n", "Credentials\n", "Relay\n", "privileges         FAILED", "cannot be read", "Not tested by this command\n"} {
		if !strings.Contains(report, want) {
			t.Errorf("the report has no %q:\n%s", want, report)
		}
	}
	// 「refusing to start」は起動を拒む経路の文であり、何も起動しないこのコマンドには当たらない。
	// 報告の所見に拒否の文面をそのまま流し込む形も同じ文を持ち込むので、両方を見る。
	if strings.Contains(err.Error(), "refusing to start") || strings.Contains(report, "refusing to start") {
		t.Errorf("agent doctor says it refuses to start; it starts nothing: %v\n%s", err, report)
	}
	// 予測は、エージェントが読むのと同じ設定を読めた実行でだけ示す。
	if strings.Contains(report, "the memory soft limit would be") {
		t.Errorf("the report predicts the memory soft limit from the defaults although the settings could not be read:\n%s", report)
	}
}

// 設定ファイルの手前のディレクトリが通り抜けを拒む実行では、ファイル自身の持ち主とパーミッションを
// 読めていない。所見も次の一手も、読めていないものを名指ししない。運用者が直すのはディレクトリで
// あって、ファイルではない。
func TestAgentDoctorDoesNotBlameTheFileADirectoryHides(t *testing.T) {
	if runtime.GOOS == "windows" || os.Geteuid() == 0 {
		t.Skip("this scenario needs a directory that refuses the running user; root refuses nothing and Windows does not answer os.Chmod that way")
	}
	dir := t.TempDir()
	closed := filepath.Join(dir, "closed")
	if err := os.Mkdir(closed, 0o700); err != nil {
		t.Fatal(err)
	}
	config := filepath.Join(closed, "agent.env")
	if err := os.WriteFile(config, []byte("WGFT_NAME=home\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	chmodForTest(t, closed, 0)

	in := testAgentDoctorInput(t, dir)
	in.ConfigPath = config
	in.ConfigUnreadable = fs.ErrPermission
	priv, _ := findAgentCheck(agentDiagnose(in), agentCheckPrivileges)
	if priv.Status != statusFailed || priv.Reason != agentReasonPermissionDenied {
		t.Fatalf("host.privileges = %s/%q, want failed/%q", priv.Status, priv.Reason, agentReasonPermissionDenied)
	}
	if !strings.Contains(priv.Detail, "a directory above it refuses the way in") {
		t.Errorf("host.privileges does not say which side refused: %q", priv.Detail)
	}
	if strings.Contains(priv.Detail, "the file is mode") {
		t.Errorf("host.privileges states the file's mode although it could not read it: %q", priv.Detail)
	}
	// 次の一手が、読めていないファイルの持ち主とパーミッションを直せと述べてはならない。
	if strings.Contains(priv.Next, "the file's own owner, group and mode refuse it") {
		t.Errorf("the next step blames the file although a directory above it refused: %q", priv.Next)
	}
	if !strings.Contains(priv.Next, "directory on the way to the config file") {
		t.Errorf("the next step does not send the operator to the directories: %q", priv.Next)
	}
}

// ファイル自身を読めた実行では、逆に、その持ち主とパーミッションを名指しする。エージェントを
// 動かす利用者で実行し直しても読めない配置で、運用者が次に見るものである。
func TestAgentDoctorNamesTheConfigFileItCouldStat(t *testing.T) {
	if runtime.GOOS == "windows" || os.Geteuid() == 0 {
		t.Skip("the facts this check reads are the Unix owner and mode; Windows does not answer os.Chmod that way")
	}
	dir := t.TempDir()
	config := filepath.Join(dir, "agent.env")
	if err := os.WriteFile(config, []byte("WGFT_NAME=home\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	chmodForTest(t, config, 0)

	in := testAgentDoctorInput(t, dir)
	in.ConfigPath = config
	in.ConfigUnreadable = fs.ErrPermission
	priv, _ := findAgentCheck(agentDiagnose(in), agentCheckPrivileges)
	if !strings.Contains(priv.Detail, "the file is mode 0000") {
		t.Errorf("host.privileges does not state the file's own mode: %q", priv.Detail)
	}
	if !strings.Contains(priv.Next, "the file's own owner, group and mode refuse it") {
		t.Errorf("the next step does not name the file it could read: %q", priv.Next)
	}
}

// 設定ファイルを読めない実行では、データディレクトリを既定値から取る。登録と稼働について断定する
// 所見は、見たディレクトリがその既定値であることを添える。読めなかったファイルが別のディレクトリを
// 指していれば、登録済みで稼働中のホストについて偽になるためである。
func TestAgentDoctorSaysWhenTheDataDirCameFromTheDefaults(t *testing.T) {
	dir := t.TempDir()
	in := testAgentDoctorInput(t, dir)
	in.ConfigUnreadable = fs.ErrPermission
	in.DataDirAssumed = true
	rep := agentDiagnose(in)
	for _, id := range []string{agentCheckCredentials, agentCheckProcess} {
		c, _ := findAgentCheck(rep, id)
		if c.Status != statusFailed {
			t.Fatalf("%s = %s, want failed; this scenario needs the claims that assert", id, c.Status)
		}
		if !strings.Contains(c.Detail, "the default, because "+in.ConfigPath) {
			t.Errorf("%s asserts without saying the data directory came from the defaults: %q", id, c.Detail)
		}
	}
	// 設定を読めた実行の文面は変えない。
	plain := agentDiagnose(testAgentDoctorInput(t, dir))
	for _, id := range []string{agentCheckCredentials, agentCheckProcess} {
		c, _ := findAgentCheck(plain, id)
		if strings.Contains(c.Detail, "the default, because") {
			t.Errorf("%s carries the note although the config file was read: %q", id, c.Detail)
		}
	}
}

// 設定ファイルが無い配置は正しい。無いことを失敗にせず、報告はそのまま出る。
//
// 主張は OS に依らない形にしてある。`host.privileges` の状態そのものは OS で分かれ、Windows では
// 新しいファイルを作れるかどうかを副作用なしに判定できないので UNKNOWN になる(10.2c 節)。
// この場面が固定するのは、読めない設定ファイルの扱いが不在のファイルに及ばないことである。
func TestAgentDoctorAcceptsAMissingConfigFile(t *testing.T) {
	dir := t.TempDir()
	missing := filepath.Join(dir, "none.env")
	var out bytes.Buffer
	root := newRootCmd()
	root.SetArgs([]string{"agent", "doctor", "--config", missing, "--data-dir", filepath.Join(dir, "data")})
	root.SetOut(&out)
	root.SetErr(io.Discard)
	err := root.Execute()
	// 認証情報ファイルが無いので総合判定は FAILED であり、終了コードは 1 である。証拠に権限で
	// 届かなかった実行ではないので 2 ではない。不在のファイルを読めない扱いにすると 2 になる。
	if got := exitCode(err); err == nil || got != 1 {
		t.Fatalf("err=%v exitCode=%d, want 1", err, got)
	}
	report := out.String()
	if strings.Contains(report, "privileges         FAILED") {
		t.Errorf("a missing config file failed host.privileges:\n%s", report)
	}
	// 所見が設定ファイルの名前を出すのは、読めなかった対象として並べるときだけである。
	if strings.Contains(report, missing) {
		t.Errorf("the report names the missing config file as evidence it could not read:\n%s", report)
	}
	if !strings.Contains(report, "the memory soft limit would be") {
		t.Errorf("the report does not predict the memory soft limit although the settings were read:\n%s", report)
	}
}

// root で実行した host.privileges の扱いを、10.2c 節の規則をそのまま入力に写して確かめる。root は
// ファイルのパーミッションを迂回するので、読めたことはエージェント自身の利用者について何も述べない。
// そのため root の実行では、拒まれた対象が無ければ OK ではなく UNKNOWN とし、層 2 には数えない。
// 終了コードは他の検査が決める。root でない実行の扱いは変えない。
func TestAgentDoctorPrivilegesUnderRoot(t *testing.T) {
	for _, tc := range []struct {
		name string
		euid int
		// setup は場面の残りを作る。healthy は稼働中で何も壊れていないエージェントである。
		setup      func(t *testing.T, in *agentDoctorInput)
		wantStatus string
		wantReason string
		// wantRootWording は、所見と次の一手が root の迂回を述べることである。
		wantRootWording bool
		wantExit        int
	}{
		{
			name: "root, a healthy running agent", euid: 0, setup: healthyAgentForTest,
			wantStatus: statusUnknown, wantReason: agentReasonRunningAsRoot, wantRootWording: true, wantExit: 0,
		},
		{
			// 層 1 の FAILED は root でもそのまま効く。root の UNKNOWN が 2 に倒すことはない。
			name: "root, a stopped agent", euid: 0, setup: stoppedAgentForTest,
			wantStatus: statusUnknown, wantReason: agentReasonRunningAsRoot, wantRootWording: true, wantExit: 1,
		},
		{
			// root でも拒まれた対象がある実行は、迂回が及ばない拒否という事実があるので、層 2 の
			// FAILED のままとする。
			name: "root, and a target refuses it anyway", euid: 0,
			setup: func(t *testing.T, in *agentDoctorInput) {
				healthyAgentForTest(t, in)
				in.Readable = func(string, bool) (accessResult, error) { return accessDenied, fs.ErrPermission }
			},
			wantStatus: statusFailed, wantReason: agentReasonPermissionDenied, wantExit: 2,
		},
		{
			// root の実行は、拒まれた対象が無ければ、判定できない対象があっても running_as_root に
			// なる。判定できない理由より、この実行が答えられない理由のほうが先に立つ(10.2c 節)。
			name: "root, and a target cannot be decided", euid: 0,
			setup: func(t *testing.T, in *agentDoctorInput) {
				healthyAgentForTest(t, in)
				in.DirCreateAccess = func(string) (accessResult, error) {
					return accessNotDetermined, errors.New("read-only file system")
				}
			},
			wantStatus: statusUnknown, wantReason: agentReasonRunningAsRoot, wantRootWording: true, wantExit: 0,
		},
		{
			name: "not root, a healthy running agent", euid: 1000, setup: healthyAgentForTest,
			wantStatus: statusOK, wantExit: 0,
		},
		{
			name: "not root, a stopped agent", euid: 1000, setup: stoppedAgentForTest,
			wantStatus: statusOK, wantExit: 1,
		},
		{
			// Windows の os.Geteuid は -1 を返す。root の分岐に入らない。
			name: "no uid, as on Windows", euid: -1, setup: healthyAgentForTest,
			wantStatus: statusOK, wantExit: 0,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			in := testAgentDoctorInput(t, t.TempDir())
			euid := tc.euid
			in.Euid = func() int { return euid }
			tc.setup(t, &in)
			rep := agentDiagnose(in)
			c, ok := findAgentCheck(rep, agentCheckPrivileges)
			if !ok {
				t.Fatal("host.privileges is missing from the report")
			}
			if c.Status != tc.wantStatus || c.Reason != tc.wantReason {
				t.Errorf("host.privileges = %s/%q, want %s/%q; detail: %s", c.Status, c.Reason, tc.wantStatus, tc.wantReason, c.Detail)
			}
			if tc.wantStatus == statusUnknown && c.evidenceUnreachable {
				t.Error("the root run counts as evidence out of reach; running as root alone must not end in exit code 2")
			}
			saysBypass := strings.Contains(c.Detail, "root bypasses file permissions") &&
				strings.Contains(c.Detail, "cannot say whether the user the agent runs as can reach them")
			if saysBypass != tc.wantRootWording {
				t.Errorf("the detail says root bypasses permissions = %v, want %v: %q", saysBypass, tc.wantRootWording, c.Detail)
			}
			if tc.wantRootWording {
				for _, want := range []string{"run this command as that user", "if the agent itself runs as root, this result is expected"} {
					if !strings.Contains(c.Next, want) {
						t.Errorf("the next step has no %q: %q", want, c.Next)
					}
				}
			}
			if code := agentDoctorExitCode(rep); code != tc.wantExit {
				t.Errorf("exit code = %d, want %d", code, tc.wantExit)
			}
		})
	}
}

// 差し替えられていない実効 uid の入口は、このプロセスの実効 uid を答える。既定が別の値を返すと、
// root の実行を見分ける判定が実際の実行に効かない。
func TestAgentDoctorDefaultEuidIsTheProcessEuid(t *testing.T) {
	in := agentDoctorInput{}.withDefaults()
	if got, want := in.Euid(), os.Geteuid(); got != want {
		t.Errorf("the default Euid() = %d, want os.Geteuid() = %d", got, want)
	}
}

// healthyAgentForTest は、登録済みで稼働中の、何も壊れていないエージェントの場面を作る。
func healthyAgentForTest(t *testing.T, in *agentDoctorInput) {
	t.Helper()
	writeTestCredentials(t, in.CredentialsPath, registeredCredentials())
	holdTheLock(t, in.CredentialsPath)
	in.Dial = fakeDoctorSocket(t, liveReply(healthyLiveResponse()))
}

// stoppedAgentForTest は、登録済みで止まっているエージェントの場面を作る。
func stoppedAgentForTest(t *testing.T, in *agentDoctorInput) {
	t.Helper()
	writeTestCredentials(t, in.CredentialsPath, registeredCredentials())
}

// --- 助け ---

func testAgentDoctorInput(t *testing.T, dir string) agentDoctorInput {
	t.Helper()
	return agentDoctorInput{
		Now:             time.Date(2026, 9, 23, 12, 0, 0, 0, time.UTC),
		DataDir:         dir,
		CredentialsPath: filepath.Join(dir, "agent.json"),
		ConfigPath:      filepath.Join(dir, "agent.env"),
		Version:         "v1.0.0",
		Platform:        "linux/amd64",
		User:            "running as tester, uid 1000",
		MemoryLimitEnv:  "",
		Resolve: func(context.Context, string) ([]string, error) {
			return []string{"203.0.113.10"}, nil
		},
		Interfaces: func() ([]net.Interface, error) {
			return []net.Interface{{Index: 1, Name: "lo", Flags: net.FlagUp | net.FlagLoopback}}, nil
		},
		// 既定の場面では「新しいファイルを作れる」を与える。OS ごとの判定そのものは
		// TestDirCreateAccess が確かめる。この表が確かめるのは 10.2c 節の規則であり、走らせた
		// OS が答えを変えてはならない。
		DirCreateAccess: func(string) (accessResult, error) { return accessAllowed, nil },
		// 既定の場面は root でない利用者で走らせる。root の場面は明示して与える。テストを root で
		// 走らせても、場面の答えが変わらないようにするためである。
		Euid: func() int { return 1000 },
	}
}

// 新しいファイルを作れるかどうかの判定は、Unix では答えが出て、Windows では出ない。Windows だけ
// 黙って OK を返す形にはしない(10.2c 節)。
func TestDirCreateAccess(t *testing.T) {
	got, err := dirCreateAccess(t.TempDir())
	if runtime.GOOS == "windows" {
		if got != accessNotDetermined {
			t.Errorf("dirCreateAccess on Windows = %d, want accessNotDetermined; there is no way to answer it without creating a file", got)
		}
		if err == nil {
			t.Error("dirCreateAccess on Windows must say why it cannot answer")
		}
		return
	}
	if got != accessAllowed || err != nil {
		t.Errorf("dirCreateAccess on a writable directory = %d, %v; want accessAllowed", got, err)
	}
}

// registeredCredentials は登録の済んだ認証情報である。宛先はどちらもリテラルのアドレスにして
// あるので、既定の場面では名前解決を必要としない。
func registeredCredentials() *credentials.Credentials {
	return &credentials.Credentials{
		Name:                "home",
		Endpoint:            "203.0.113.10:8443",
		CertSHA256:          "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
		PermanentToken:      "not-a-real-value",
		UsedJoinTokenSHA256: "fedcba9876543210fedcba9876543210fedcba9876543210fedcba9876543210",
		LastState: &proto.State{
			Generation: 12,
			WG:         proto.WGConfig{Endpoint: "203.0.113.10:51820", Address: "10.200.0.2/24", MTU: 1420},
			Rules: []proto.AgentRule{
				{ID: "r_1", Proto: proto.TCP, ListenPort: proto.PortRange{Lo: 2456, Hi: 2456}, Target: "192.168.1.20:2456", Enabled: true},
				{ID: "r_2", Proto: proto.UDP, ListenPort: proto.PortRange{Lo: 2457, Hi: 2458}, Target: "192.168.1.20:2457", Enabled: true},
			},
		},
	}
}

func writeTestCredentials(t *testing.T, path string, f *credentials.Credentials) {
	t.Helper()
	b, err := json.Marshal(f)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, b, 0o600); err != nil {
		t.Fatal(err)
	}
}

// holdTheLock は、稼働中のエージェントを模してロックを取ったままにする。
func holdTheLock(t *testing.T, credentialsPath string) {
	t.Helper()
	l, err := flock.Acquire(credentialsPath)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { l.Release() })
}

// chmodForTest は権限を絞り、後片付けで戻す。戻さないと t.TempDir の削除が失敗する。
func chmodForTest(t *testing.T, path string, mode os.FileMode) {
	t.Helper()
	fi, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(path, mode); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.Chmod(path, fi.Mode().Perm()) })
}

func findAgentCheck(rep agentDoctorReport, id string) (agentDoctorCheck, bool) {
	for _, c := range rep.Checks {
		if c.ID == id {
			return c, true
		}
	}
	return agentDoctorCheck{}, false
}

// agentDoctorExitCode は報告の終了コードである。exitCode と同じ振り分けを通すので、終了コード 2 を
// 表す型を取り違えていれば落ちる。
func agentDoctorExitCode(rep agentDoctorReport) int {
	err := agentDoctorExit(rep)
	if err == nil {
		return 0
	}
	return exitCode(err)
}
