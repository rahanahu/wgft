package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
	"net"
	"os"
	"path/filepath"
	"reflect"
	"regexp"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/rahanahu/wgft/internal/agent"
	"github.com/rahanahu/wgft/internal/agent/credentials"
	"github.com/rahanahu/wgft/internal/flock"
	"github.com/rahanahu/wgft/internal/vpsd/doctor"
	"github.com/rahanahu/wgft/proto"
)

// このファイルは `wgft agent doctor --json`(設計文書 10.2c 節の「機械向けの出力」)のテストである。
// 形そのもの、人向けの出力との一致、終了コードとの一致、理由の符号と設計文書の一致を確かめる。
// 形と値は 7a.11 節の保証の対象なので、名前の変更も削除もここで落ちる。

// agentJSONScenarios は、JSON の形と人向けの出力との一致を確かめる場面である。任意のフィールド
// (reason、evidence_unreachable、next)が現れる実行と現れない実行の両方を含める。
var agentJSONScenarios = []struct {
	name       string
	setup      func(t *testing.T, in *agentDoctorInput)
	wantStatus string
}{
	{"the credentials file is missing", func(t *testing.T, in *agentDoctorInput) {}, statusFailed},
	{"not registered", func(t *testing.T, in *agentDoctorInput) {
		writeTestCredentials(t, in.CredentialsPath, &credentials.Credentials{})
	}, statusFailed},
	{"a stopped agent", stoppedAgentForTest, statusFailed},
	{"a healthy running agent", healthyAgentForTest, statusOK},
	{"a healthy running agent, diagnosed as root", func(t *testing.T, in *agentDoctorInput) {
		healthyAgentForTest(t, in)
		in.Euid = func() int { return 0 }
	}, statusOK},
	{"the running agent waits for its first full state", func(t *testing.T, in *agentDoctorInput) {
		writeTestCredentials(t, in.CredentialsPath, registeredCredentials())
		holdTheLock(t, in.CredentialsPath)
		in.Dial = fakeDoctorSocket(t, liveReply(runtimeResponse(func(st *agent.DoctorRuntimeState) {
			st.Tunnel = agent.DoctorTunnel{State: proto.StatusError, Reason: "no tunnel; full state not received"}
			st.Rules, st.Budgets = nil, nil
		})))
	}, statusOK},
	{"the lock file cannot be read", func(t *testing.T, in *agentDoctorInput) {
		writeTestCredentials(t, in.CredentialsPath, registeredCredentials())
		in.Inspect = func(string) (flock.State, error) { return flock.Unknown, fs.ErrPermission }
	}, statusUnknown},
	{"the control socket refuses this command's permissions", func(t *testing.T, in *agentDoctorInput) {
		writeTestCredentials(t, in.CredentialsPath, registeredCredentials())
		holdTheLock(t, in.CredentialsPath)
		in.Dial = func(string) (net.Conn, error) { return nil, &net.OpError{Op: "dial", Err: fs.ErrPermission} }
	}, statusUnknown},
	{"a verdict check fails while some evidence cannot be read", func(t *testing.T, in *agentDoctorInput) {
		in.Readable = func(string, bool) (accessResult, error) { return accessDenied, fs.ErrPermission }
	}, statusUnknown},
}

// agentJSONTopKeys と agentJSONCheckKeys は、JSON の各階層が持つフィールドとその型である。
// 7a.11 節の規則で、フィールドは増えるだけで、名前が変わったり消えたりしない。この表を変える
// ときは、設計文書 10.2c 節の「機械向けの出力」を先に直す。
var (
	agentJSONTopKeys = map[string]string{
		"status": "string", "checked_at": "string", "data_dir": "string",
		"checks": "array", "history": "object", "not_tested": "array",
	}
	agentJSONCheckKeys = map[string]string{
		"id": "string", "status": "string", "reason": "string", "evidence_unreachable": "bool",
		"group": "string", "label": "string", "detail": "string", "next": "string",
	}
	// agentJSONCheckOptional は、値が無いときに省くフィールドである。
	agentJSONCheckOptional = map[string]bool{"reason": true, "evidence_unreachable": true, "next": true}
	agentJSONHistoryKeys   = map[string]string{"available": "bool", "detail": "string"}
	agentJSONNotTestedKeys = map[string]string{"id": "string", "detail": "string"}
)

// jsonKind は、encoding/json が any に読んだ値の種類を名前で返す。
func jsonKind(v any) string {
	switch v.(type) {
	case string:
		return "string"
	case bool:
		return "bool"
	case float64:
		return "number"
	case []any:
		return "array"
	case map[string]any:
		return "object"
	case nil:
		return "null"
	}
	return fmt.Sprintf("%T", v)
}

// checkJSONObject は、obj が want のフィールドを want の型で持ち、それ以外を持たないことを
// 確かめる。optional に無いフィールドは必ずある。
func checkJSONObject(t *testing.T, where string, obj map[string]any, want map[string]string, optional map[string]bool) {
	t.Helper()
	for k, v := range obj {
		kind, ok := want[k]
		if !ok {
			t.Errorf("%s has the field %q, which the design does not define", where, k)
			continue
		}
		if got := jsonKind(v); got != kind {
			t.Errorf("%s.%s is a %s, want a %s", where, k, got, kind)
		}
	}
	for k := range want {
		if _, ok := obj[k]; !ok && !optional[k] {
			t.Errorf("%s has no %q", where, k)
		}
	}
}

// diagnoseJSON は報告を --json と同じ経路で書き、読み戻す。
func diagnoseJSON(t *testing.T, rep agentDoctorReport) map[string]any {
	t.Helper()
	var b bytes.Buffer
	if err := writeAgentDoctorJSON(&b, rep); err != nil {
		t.Fatal(err)
	}
	var got map[string]any
	if err := json.Unmarshal(b.Bytes(), &got); err != nil {
		t.Fatalf("the output is not one JSON object: %v\n%s", err, b.String())
	}
	return got
}

// JSON の形を、フィールドの名前と型の水準で固定する(10.2c 節の「機械向けの出力」)。
func TestAgentDoctorJSONShape(t *testing.T) {
	seenOptional := map[string]bool{}
	for _, sc := range agentJSONScenarios {
		t.Run(sc.name, func(t *testing.T) {
			in := testAgentDoctorInput(t, t.TempDir())
			sc.setup(t, &in)
			rep := agentDiagnose(in)
			got := diagnoseJSON(t, rep)
			checkJSONObject(t, "the report", got, agentJSONTopKeys, nil)
			if got["status"] != sc.wantStatus {
				t.Errorf("status = %v, want %q", got["status"], sc.wantStatus)
			}
			if got["checked_at"] != "2026-09-23T12:00:00Z" {
				t.Errorf("checked_at = %v, want the diagnosis time in RFC 3339 UTC", got["checked_at"])
			}
			if got["data_dir"] != in.DataDir {
				t.Errorf("data_dir = %v, want %q", got["data_dir"], in.DataDir)
			}
			checks, _ := got["checks"].([]any)
			if len(checks) != len(agentDoctorTable) {
				t.Fatalf("%d checks, want every check in the design table, %d", len(checks), len(agentDoctorTable))
			}
			for i, raw := range checks {
				c, ok := raw.(map[string]any)
				if !ok {
					t.Fatalf("checks[%d] is a %s, want an object", i, jsonKind(raw))
				}
				checkJSONObject(t, fmt.Sprintf("checks[%d]", i), c, agentJSONCheckKeys, agentJSONCheckOptional)
				for k := range agentJSONCheckOptional {
					if _, ok := c[k]; ok {
						seenOptional[k] = true
					}
				}
				if c["id"] != agentDoctorTable[i].id {
					t.Errorf("checks[%d] is %v, want %q: the design table's order", i, c["id"], agentDoctorTable[i].id)
				}
				_, hasReason := c["reason"]
				if c["status"] == statusOK && hasReason {
					t.Errorf("%v is ok but carries a reason; an ok check omits it", c["id"])
				}
				if c["status"] != statusOK && !hasReason {
					t.Errorf("%v is %v without a reason", c["id"], c["status"])
				}
				if v, ok := c["evidence_unreachable"]; ok && v != true {
					t.Errorf("%v carries evidence_unreachable=%v; it is present only as true", c["id"], v)
				}
			}
			h, _ := got["history"].(map[string]any)
			checkJSONObject(t, "history", h, agentJSONHistoryKeys, nil)
			if h["available"] != false {
				t.Errorf("history.available = %v; this version keeps no history", h["available"])
			}
			nt, _ := got["not_tested"].([]any)
			if len(nt) == 0 {
				t.Error("not_tested is empty; it is present on every run, including a healthy one")
			}
			for i, raw := range nt {
				n, _ := raw.(map[string]any)
				checkJSONObject(t, fmt.Sprintf("not_tested[%d]", i), n, agentJSONNotTestedKeys, nil)
			}
		})
	}
	// 場面の組が、省きうるフィールドの現れる実行を少なくとも 1 つずつ含むことを確かめる。含まないと、
	// そのフィールドの名前と型をこのテストが一度も見ない。
	for k := range agentJSONCheckOptional {
		if !seenOptional[k] {
			t.Errorf("no scenario shows %q, so its name and type are never checked", k)
		}
	}
}

// 値の語彙を確かめる。最上位の status は総合判定の 3 つ、checks[].status は 10.2a 節の 5 つ、
// checks[].reason は設計文書の表の符号である。人向けの語(OK、FAILED)を JSON に書くと落ちる。
func TestAgentDoctorJSONVocabulary(t *testing.T) {
	statuses := map[string]bool{statusOK: true, statusFailed: true, statusUnknown: true, statusNotTested: true, statusSkipped: true}
	reasons := map[string]bool{}
	for _, v := range agentReasonValues(t) {
		reasons[v] = true
	}
	for _, sc := range agentJSONScenarios {
		in := testAgentDoctorInput(t, t.TempDir())
		sc.setup(t, &in)
		got := agentDoctorJSONOf(agentDiagnose(in))
		switch got.Status {
		case statusOK, statusFailed, statusUnknown:
		default:
			t.Errorf("%s: status %q is not one of ok, failed, unknown", sc.name, got.Status)
		}
		for _, c := range got.Checks {
			if !statuses[c.Status] {
				t.Errorf("%s: %s has the status %q, which is not one of design 10.2a's five", sc.name, c.ID, c.Status)
			}
			if c.Reason != "" && !reasons[c.Reason] {
				t.Errorf("%s: %s has the reason %q, which is not an agent doctor reason code", sc.name, c.ID, c.Reason)
			}
		}
	}
}

// 同じ事実を表すフィールドは、`server doctor --json` と同じ名前を持つ(10.2c 節)。型は共有しない
// ので、名前が揃っていることはここで確かめる。
func TestAgentDoctorJSONSharesServerDoctorNames(t *testing.T) {
	for _, pair := range []struct {
		agent, server any
	}{
		{agentDoctorJSON{}, doctor.Report{}},
		{agentDoctorJSONCheck{}, doctor.Check{}},
		{agentDoctorJSONHistory{}, doctor.History{}},
		{agentDoctorJSONNotTested{}, doctor.NotTested{}},
	} {
		at, st := reflect.TypeOf(pair.agent), reflect.TypeOf(pair.server)
		shared := 0
		for i := 0; i < at.NumField(); i++ {
			af := at.Field(i)
			sf, ok := st.FieldByName(af.Name)
			if !ok {
				continue
			}
			shared++
			if a, s := af.Tag.Get("json"), sf.Tag.Get("json"); a != s {
				t.Errorf("%s.%s is tagged %q, but server doctor's %s.%s is tagged %q; the same fact carries the same name", at.Name(), af.Name, a, st.Name(), sf.Name, s)
			}
		}
		if shared == 0 {
			t.Errorf("%s shares no field with %s", at.Name(), st.Name())
		}
	}
}

// JSON の各項目は、人向けの出力と同じ報告から写す。状態、理由、所見が食い違わないことを、同じ
// 報告を両方の形で書いて確かめる。人向けの行は見出しと状態の語で探す。
func TestAgentDoctorJSONMatchesTheHumanOutput(t *testing.T) {
	for _, sc := range agentJSONScenarios {
		t.Run(sc.name, func(t *testing.T) {
			in := testAgentDoctorInput(t, t.TempDir())
			sc.setup(t, &in)
			rep := agentDiagnose(in)
			got := agentDoctorJSONOf(rep)
			if len(got.Checks) != len(rep.Checks) {
				t.Fatalf("%d checks in JSON, %d in the report", len(got.Checks), len(rep.Checks))
			}
			var human bytes.Buffer
			writeAgentDoctorReport(&human, rep)
			for i, c := range rep.Checks {
				j := got.Checks[i]
				if j.ID != c.ID || j.Status != c.Status || j.Reason != c.Reason || j.EvidenceUnreachable != c.evidenceUnreachable ||
					j.Group != c.Group || j.Label != c.Label || j.Detail != c.Detail || j.Next != c.Next {
					t.Errorf("checks[%d] in JSON = %+v, want the report's %+v", i, j, c)
				}
				// 値だけを示す検査(valueOnly)が UNKNOWN の実行では、10.2c 節の Observed values
				// 節が状態語を出さず、ラベルと値だけを示す(2026-09-24 の所有者の決定)。JSON は
				// この実行でも status: "unknown" を持つので、人向けの出力の側だけがこの形を採る。
				// 長い detail は行をまたいで折り返されるので、空白をたたんで比べる。
				if c.valueOnly && j.Status == statusUnknown {
					if !strings.Contains(normalizeWhitespace(human.String()), normalizeWhitespace(j.Detail)) {
						t.Errorf("the human output has no observed value for %q, which JSON reports for %s: %q\n%s", j.Label, j.ID, j.Detail, human.String())
					}
					if humanHasLine(human.String(), j.Label, statusWord(j.Status)) {
						t.Errorf("the observed value %q still prints its status word %s in the human output:\n%s", j.Label, statusWord(j.Status), human.String())
					}
					continue
				}
				if !humanHasLine(human.String(), j.Label, statusWord(j.Status)) {
					t.Errorf("the human output has no %q line reading %s, which JSON reports for %s:\n%s", j.Label, statusWord(j.Status), j.ID, human.String())
				}
			}
		})
	}
}

// normalizeWhitespace は、連続する空白と改行を 1 個の空白にたたむ。Observed values 節の長い
// detail は wrapAt で複数行に折り返されるので、折り返しをまたいだ一致を見るのに使う。
func normalizeWhitespace(s string) string {
	return strings.Join(strings.Fields(s), " ")
}

// humanHasLine は、人向けの出力に、その見出しとその状態の語の行があるかどうかである。行の形は
// writeLine が決める。
func humanHasLine(out, label, word string) bool {
	prefix := fmt.Sprintf("  %-*s %s", labelWidth, label, word)
	for _, line := range strings.Split(out, "\n") {
		if strings.HasPrefix(line, prefix) {
			return true
		}
	}
	return false
}

// 最上位の status と終了コードは同じ判定から決まる。ok は 0、failed は 1、unknown は 2 である。
func TestAgentDoctorJSONStatusIsTheExitCode(t *testing.T) {
	want := map[string]int{statusOK: 0, statusFailed: 1, statusUnknown: exitUnavailable}
	for _, sc := range agentJSONScenarios {
		in := testAgentDoctorInput(t, t.TempDir())
		sc.setup(t, &in)
		rep := agentDiagnose(in)
		status := agentDoctorJSONOf(rep).Status
		if code := agentDoctorExitCode(rep); code != want[status] {
			t.Errorf("%s: JSON status %q with exit code %d, want %d", sc.name, status, code, want[status])
		}
	}
}

// root で実行した場合、host.privileges は JSON でも UNKNOWN と running_as_root になり、終了コード
// 2 に倒す条件には数えない(10.2c 節)。
func TestAgentDoctorJSONUnderRoot(t *testing.T) {
	in := testAgentDoctorInput(t, t.TempDir())
	healthyAgentForTest(t, &in)
	in.Euid = func() int { return 0 }
	got := diagnoseJSON(t, agentDiagnose(in))
	if got["status"] != statusOK {
		t.Errorf("status = %v, want ok: running as root alone does not decide the verdict", got["status"])
	}
	checks, _ := got["checks"].([]any)
	for _, raw := range checks {
		c, _ := raw.(map[string]any)
		if c["id"] != agentCheckPrivileges {
			continue
		}
		if c["status"] != statusUnknown || c["reason"] != agentReasonRunningAsRoot {
			t.Errorf("host.privileges = %v/%v, want %s/%s", c["status"], c["reason"], statusUnknown, agentReasonRunningAsRoot)
		}
		if _, ok := c["evidence_unreachable"]; ok {
			t.Error("host.privileges carries evidence_unreachable under root; running as root alone is not exit code 2")
		}
		return
	}
	t.Fatal("host.privileges is missing from the JSON")
}

// --json は終了コードを変えない。コマンドを --json の有無だけ変えて 2 回走らせ、終了コード、
// 最上位の status、検査ごとの状態の語を突き合わせる。出力は JSON の 1 オブジェクトだけである。
func TestAgentDoctorJSONKeepsTheExitCode(t *testing.T) {
	for _, tc := range []struct {
		name                 string
		needsUnixPermissions bool
		setup                func(t *testing.T, data, config string)
		// wantExit は期待する終了コードである。-1 は OS によって値が変わりうる場面で、値そのものは
		// 比べず、--json の有無で変わらないことだけを確かめる。
		wantExit int
	}{
		{name: "the credentials file is missing", setup: func(t *testing.T, data, config string) {}, wantExit: 1},
		{name: "not registered", setup: func(t *testing.T, data, config string) {
			writeTestCredentials(t, filepath.Join(data, "agent.json"), &credentials.Credentials{})
		}, wantExit: 1},
		{name: "a stopped agent", setup: func(t *testing.T, data, config string) {
			writeTestCredentials(t, filepath.Join(data, "agent.json"), registeredCredentials())
		}, wantExit: 1},
		{name: "an agent holds the lock but has no control socket", setup: func(t *testing.T, data, config string) {
			writeTestCredentials(t, filepath.Join(data, "agent.json"), registeredCredentials())
			holdTheLock(t, filepath.Join(data, "agent.json"))
		}, wantExit: -1},
		{name: "the config file cannot be read", needsUnixPermissions: true, setup: func(t *testing.T, data, config string) {
			if err := os.WriteFile(config, []byte("WGFT_MAX_UDP_FLOWS=2048\n"), 0o600); err != nil {
				t.Fatal(err)
			}
			chmodForTest(t, config, 0)
		}, wantExit: exitUnavailable},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if tc.needsUnixPermissions && (os.Geteuid() == 0 || runtime.GOOS == "windows") {
				t.Skip("this scenario needs a file that refuses the running user; root refuses nothing and Windows does not answer os.Chmod that way")
			}
			dir := t.TempDir()
			data, config := filepath.Join(dir, "data"), filepath.Join(dir, "agent.env")
			if err := os.Mkdir(data, 0o700); err != nil {
				t.Fatal(err)
			}
			tc.setup(t, data, config)
			run := func(extra ...string) (string, int) {
				var out, errOut bytes.Buffer
				root := newRootCmd()
				root.SetArgs(append([]string{"agent", "doctor", "--config", config, "--data-dir", data}, extra...))
				root.SetOut(&out)
				root.SetErr(&errOut)
				err := root.Execute()
				code := 0
				if err != nil {
					code = exitCode(err)
				}
				return out.String(), code
			}
			humanOut, humanCode := run()
			jsonOut, jsonCode := run("--json")
			if humanCode != jsonCode {
				t.Errorf("exit code %d without --json, %d with it; --json must not change it", humanCode, jsonCode)
			}
			if tc.wantExit >= 0 && jsonCode != tc.wantExit {
				t.Errorf("exit code = %d, want %d", jsonCode, tc.wantExit)
			}
			var got agentDoctorJSON
			dec := json.NewDecoder(strings.NewReader(jsonOut))
			dec.DisallowUnknownFields()
			if err := dec.Decode(&got); err != nil {
				t.Fatalf("the --json output is not the model: %v\n%s", err, jsonOut)
			}
			if dec.More() {
				t.Errorf("the --json output holds more than one JSON value:\n%s", jsonOut)
			}
			want := map[string]int{statusOK: 0, statusFailed: 1, statusUnknown: exitUnavailable}
			if code, ok := want[got.Status]; !ok || code != jsonCode {
				t.Errorf("status %q with exit code %d; ok is 0, failed 1, unknown 2", got.Status, jsonCode)
			}
			for _, c := range got.Checks {
				if !humanHasLine(humanOut, c.Label, statusWord(c.Status)) {
					t.Errorf("%s reads %s in JSON, but the human output of the same host has no such line:\n%s", c.ID, c.Status, humanOut)
				}
			}
		})
	}
}

// --- 理由の符号と設計文書の照合 ---

// agentReasonValues は、agentdoctor*.go の agentReason で始まる定数の値を、
// ソースから読んで返す。実装に符号を足して設計文書に書かない変更と、2 つの定数に同じ値を与える
// 変更を、ここから落とす。
func agentReasonValues(t *testing.T) map[string]string {
	t.Helper()
	out := map[string]string{}
	fset := token.NewFileSet()
	// 符号を持つファイルが増えても漏れないよう、名前を並べずに agentdoctor*.go をすべて読む。
	names, err := filepath.Glob("agentdoctor*.go")
	if err != nil {
		t.Fatal(err)
	}
	for _, name := range names {
		if strings.HasSuffix(name, "_test.go") {
			continue
		}
		f, err := parser.ParseFile(fset, name, nil, 0)
		if err != nil {
			t.Fatal(err)
		}
		for _, decl := range f.Decls {
			gd, ok := decl.(*ast.GenDecl)
			if !ok || gd.Tok != token.CONST {
				continue
			}
			for _, spec := range gd.Specs {
				vs := spec.(*ast.ValueSpec)
				for i, id := range vs.Names {
					if !strings.HasPrefix(id.Name, "agentReason") || i >= len(vs.Values) {
						continue
					}
					lit, ok := vs.Values[i].(*ast.BasicLit)
					if !ok || lit.Kind != token.STRING {
						t.Fatalf("%s is not a string literal; the reason codes are written out", id.Name)
					}
					v, err := strconv.Unquote(lit.Value)
					if err != nil {
						t.Fatal(err)
					}
					out[id.Name] = v
				}
			}
		}
	}
	if len(out) == 0 {
		t.Fatal("no agentReason constant found")
	}
	return out
}

// designSection10_2c は設計文書の 10.2c 節の本文を返す。
func designSection10_2c(t *testing.T) string {
	t.Helper()
	b, err := os.ReadFile("../../docs/design.md")
	if err != nil {
		t.Fatal(err)
	}
	s := strings.ReplaceAll(string(b), "\r\n", "\n")
	start := strings.Index(s, "\n### 10.2c ")
	if start < 0 {
		t.Fatal("design.md has no 10.2c section")
	}
	end := strings.Index(s[start+1:], "\n### ")
	if end < 0 {
		t.Fatal("design.md's 10.2c section has no end")
	}
	return s[start : start+1+end]
}

// designTableColumn は、見出しの行が header で始まる表の 1 列目の、バッククォートで囲んだ値を返す。
func designTableColumn(t *testing.T, section, header string) []string {
	t.Helper()
	lines := strings.Split(section, "\n")
	for i, line := range lines {
		if !strings.HasPrefix(line, header) {
			continue
		}
		var out []string
		for _, row := range lines[i+2:] {
			if !strings.HasPrefix(row, "| `") {
				break
			}
			cell := strings.TrimPrefix(row, "| `")
			out = append(out, cell[:strings.Index(cell, "`")])
		}
		return out
	}
	t.Fatalf("design.md's 10.2c section has no table headed %q", header)
	return nil
}

// 理由の符号は、実装と設計文書の表で同じ集合であり、1 つの符号は 1 つの定数だけが持つ(10.2c 節の
// 「機械向けの出力」)。符号は 7a.11 節の保証の対象なので、設計文書に書かずに増やすことも、2 つの
// 事実に同じ符号を当てることもできない。
func TestAgentDoctorReasonsMatchTheDesign(t *testing.T) {
	consts := agentReasonValues(t)
	byValue := map[string][]string{}
	for name, v := range consts {
		byValue[v] = append(byValue[v], name)
	}
	for v, names := range byValue {
		if len(names) > 1 {
			sort.Strings(names)
			t.Errorf("the reason code %q is held by %v; one code names one fact", v, names)
		}
	}
	design := designTableColumn(t, designSection10_2c(t), "| 理由の符号 |")
	inDesign := map[string]bool{}
	for _, v := range design {
		if inDesign[v] {
			t.Errorf("design.md lists the reason code %q twice", v)
		}
		inDesign[v] = true
		if _, ok := byValue[v]; !ok {
			t.Errorf("design.md lists the reason code %q, which the implementation does not have", v)
		}
	}
	for v := range byValue {
		if !inDesign[v] {
			t.Errorf("the implementation has the reason code %q, which design.md's 10.2c table does not list", v)
		}
	}
}

// 検査の ID も、実装と設計文書の表で同じ並びである。
func TestAgentDoctorCheckIDsMatchTheDesign(t *testing.T) {
	design := designTableColumn(t, designSection10_2c(t), "| 検査の ID |")
	if !reflect.DeepEqual(design, agentCheckOrder) {
		t.Errorf("design.md's 10.2c table lists %v, the implementation %v", design, agentCheckOrder)
	}
	for _, id := range agentCheckOrder {
		// 10.2a 節と同じく、群と名前をドットで区切り、名前は小文字とアンダースコアだけで書く。
		parts := strings.Split(id, ".")
		if len(parts) != 2 || !isLowerSnake(parts[0]) || !isLowerSnake(parts[1]) {
			t.Errorf("check id %q is not group.name in lower_snake_case", id)
		}
	}
	for _, v := range agentReasonValues(t) {
		if !isLowerSnake(v) {
			t.Errorf("reason code %q is not lower_snake_case", v)
		}
	}
}

func isLowerSnake(s string) bool {
	if s == "" || s[0] == '_' || s[len(s)-1] == '_' {
		return false
	}
	for _, r := range s {
		if (r < 'a' || r > 'z') && r != '_' {
			return false
		}
	}
	return true
}

// 1 つの符号が 1 つの事実だけを表すことを、取り違えやすかった 2 組で確かめる。agent.json が全体
// 状態を持たないことと、稼働中のエージェントが全体状態をまだ持たずトンネルが無いことは別の事実
// である。ロックファイルを読めないことは、agent.process でも、それに続く SKIPPED でも同じ符号で
// ある(手前の失敗の符号を引き継ぐ規則)。
func TestAgentDoctorReasonsNameOneFactEach(t *testing.T) {
	// agent.json に全体状態が無い、停止中のエージェント。
	in := testAgentDoctorInput(t, t.TempDir())
	f := registeredCredentials()
	f.LastState = nil
	writeTestCredentials(t, in.CredentialsPath, f)
	stored, _ := findAgentCheck(agentDiagnose(in), agentCheckLastState)

	// 全体状態をまだ持たない、稼働中のエージェント。
	in = testAgentDoctorInput(t, t.TempDir())
	writeTestCredentials(t, in.CredentialsPath, f)
	holdTheLock(t, in.CredentialsPath)
	in.Dial = fakeDoctorSocket(t, liveReply(runtimeResponse(func(st *agent.DoctorRuntimeState) {
		st.Tunnel = agent.DoctorTunnel{State: proto.StatusError, Reason: "no tunnel; full state not received"}
		st.Rules, st.Budgets = nil, nil
	})))
	live, _ := findAgentCheck(agentDiagnose(in), agentCheckTunnelLocal)
	if stored.Reason == "" || live.Reason == "" || stored.Reason == live.Reason {
		t.Errorf("agent.last_state without a stored state reads %q and tunnel.local while the running agent waits for one reads %q; "+
			"these are two facts and need two codes", stored.Reason, live.Reason)
	}

	// ロックファイルを読めない実行。
	in = testAgentDoctorInput(t, t.TempDir())
	in.Inspect = func(string) (flock.State, error) { return flock.Unknown, errors.New("input/output error") }
	rep := agentDiagnose(in)
	process, _ := findAgentCheck(rep, agentCheckProcess)
	for _, id := range []string{agentCheckControl, agentCheckTunnelLocal, agentCheckAllowTargets} {
		c, _ := findAgentCheck(rep, id)
		if c.Reason != process.Reason {
			t.Errorf("%s reads %q while agent.process reads %q; a check skipped for an earlier failure carries that failure's code", id, c.Reason, process.Reason)
		}
	}
}

// checked_at は、診断した時刻を秒の単位の RFC 3339 の UTC で書く。今の時刻が UTC でなく秒未満を
// 持つ実行でも、形は変わらない(10.2c 節)。
func TestAgentDoctorJSONCheckedAtIsUTC(t *testing.T) {
	in := testAgentDoctorInput(t, t.TempDir())
	in.Now = time.Date(2026, 9, 23, 21, 0, 0, 123456789, time.FixedZone("UTC+9", 9*3600))
	if got := agentDoctorJSONOf(agentDiagnose(in)).CheckedAt; got != "2026-09-23T12:00:00Z" {
		t.Errorf("checked_at = %q, want 2026-09-23T12:00:00Z", got)
	}
}

// data_dir は、実際に調べたディレクトリの絶対パスを正規化した値である。相対パスや . と .. を含む
// パスで指定しても、同じディレクトリは同じ値になる(10.2c 節)。
func TestAgentDoctorJSONDataDirIsAbsolute(t *testing.T) {
	in := testAgentDoctorInput(t, t.TempDir())
	in.DataDir = filepath.Join("not-created", ".", "x", "..", "data") + string(filepath.Separator)
	in.CredentialsPath = filepath.Join(in.DataDir, "agent.json")
	want, err := filepath.Abs(filepath.Join("not-created", "data"))
	if err != nil {
		t.Fatal(err)
	}
	if got := agentDoctorJSONOf(agentDiagnose(in)).DataDir; got != want {
		t.Errorf("data_dir = %q, want %q", got, want)
	}
}

// 制御ソケットに権限で繋げない実行では、終了コード 2 に倒す条件に当たるのは agent.control だけで
// ある。それに続いて SKIPPED になった検査は、証拠に権限で届かなかったのではなく、試さなかった
// だけなので evidence_unreachable を持たない。
func TestAgentDoctorJSONControlSocketRefused(t *testing.T) {
	in := testAgentDoctorInput(t, t.TempDir())
	writeTestCredentials(t, in.CredentialsPath, registeredCredentials())
	holdTheLock(t, in.CredentialsPath)
	in.Dial = func(string) (net.Conn, error) { return nil, &net.OpError{Op: "dial", Err: fs.ErrPermission} }
	got := agentDoctorJSONOf(agentDiagnose(in))
	if got.Status != statusUnknown {
		t.Errorf("status = %q, want unknown", got.Status)
	}
	skipped := 0
	for _, c := range got.Checks {
		switch {
		case c.ID == agentCheckControl:
			if !c.EvidenceUnreachable || c.Reason != agentReasonControlUnreachable {
				t.Errorf("agent.control = %s/%s evidence_unreachable=%v, want failed/%s and true", c.Status, c.Reason, c.EvidenceUnreachable, agentReasonControlUnreachable)
			}
		case c.EvidenceUnreachable:
			t.Errorf("%s carries evidence_unreachable; only agent.control could not be read with these permissions", c.ID)
		case c.Status == statusSkipped:
			skipped++
		}
	}
	if skipped == 0 {
		t.Error("no check was skipped behind the refused control socket")
	}
}

// ロックファイルを読めない原因が権限でない実行は、稼働中かどうかを判定できないだけで、終了コード 2
// に倒す条件には当たらない(10.2c 節の層 2 は権限で届かない場合に限る)。
func TestAgentDoctorJSONLockReadErrorIsNotAPermissionFailure(t *testing.T) {
	in := testAgentDoctorInput(t, t.TempDir())
	writeTestCredentials(t, in.CredentialsPath, registeredCredentials())
	in.Inspect = func(string) (flock.State, error) { return flock.Unknown, errors.New("input/output error") }
	rep := agentDiagnose(in)
	got := agentDoctorJSONOf(rep)
	for _, c := range got.Checks {
		if c.ID == agentCheckProcess && (c.Status != statusUnknown || c.Reason != agentReasonLockUnreadable) {
			t.Errorf("agent.process = %s/%s, want unknown/%s", c.Status, c.Reason, agentReasonLockUnreadable)
		}
		if c.EvidenceUnreachable {
			t.Errorf("%s carries evidence_unreachable, but the lock file failed for a reason other than permissions", c.ID)
		}
	}
	if got.Status != statusOK {
		t.Errorf("status = %q, want ok", got.Status)
	}
	if code := agentDoctorExitCode(rep); code != 0 {
		t.Errorf("exit code = %d, want 0", code)
	}
}

// 報告を作る前に止まる誤り、つまり引数やフラグの誤りの 2 と設定の誤りの 3 では、--json を付けても
// 標準出力に何も書かない。誤りは標準エラー出力に出る(10.2c 節)。
func TestAgentDoctorJSONWritesNothingWhenNoReportIsBuilt(t *testing.T) {
	dir := t.TempDir()
	bad := filepath.Join(dir, "bad.env")
	if err := os.WriteFile(bad, []byte("WGFT_MAX_UDP_FLOWS=abc\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	none := filepath.Join(dir, "none.env")
	for _, tc := range []struct {
		name string
		args []string
		want int
	}{
		{"an unknown flag", []string{"--bogus", "--config", none}, exitUnavailable},
		{"an extra argument", []string{"extra", "--config", none}, exitUnavailable},
		{"a bad setting", []string{"--config", bad, "--data-dir", dir}, exitRefusal},
	} {
		var out bytes.Buffer
		root := newRootCmd()
		root.SetArgs(append([]string{"agent", "doctor", "--json"}, tc.args...))
		root.SetOut(&out)
		root.SetErr(&bytes.Buffer{})
		err := root.Execute()
		if code := exitCode(err); err == nil || code != tc.want {
			t.Errorf("%s: err=%v exit code %d, want %d", tc.name, err, code, tc.want)
		}
		if out.Len() != 0 {
			t.Errorf("%s: stdout holds %q; no report was built, so there is no JSON to print", tc.name, out.String())
		}
	}
}

// 設計文書 10.2c 節の「機械向けの出力」の例は、節が定める規則を満たす。例は値を省いているので
// JSON としては読まず、最上位の status、検査の id の並び、フィールドの名前だけを取り出して照らす。
func TestAgentDoctorJSONDesignExampleFollowsTheRules(t *testing.T) {
	sec := designSection10_2c(t)
	i := strings.Index(sec, "#### 機械向けの出力")
	if i < 0 {
		t.Fatal("design.md's 10.2c section has no 機械向けの出力 subsection")
	}
	start := strings.Index(sec[i:], "```json\n")
	if start < 0 {
		t.Fatal("the subsection has no json example")
	}
	block := sec[i+start+len("```json\n"):]
	block = block[:strings.Index(block, "```")]

	status := regexp.MustCompile(`^\{"status":"(\w+)"`).FindStringSubmatch(block)
	if status == nil {
		t.Fatalf("the example does not start with the top-level status:\n%s", block)
	}
	// 例に出る検査は、表の順に並ぶ。
	ids := regexp.MustCompile(`"id":"([a-z_]+\.[a-z_]+)"`).FindAllStringSubmatch(block, -1)
	if len(ids) == 0 {
		t.Fatalf("the example shows no check:\n%s", block)
	}
	last := -1
	for _, m := range ids {
		at := agentCheckIndex(m[1])
		if at == len(agentCheckOrder) {
			t.Errorf("the example shows %q, which is not a check id", m[1])
			continue
		}
		if at < last {
			t.Errorf("the example lists %q after a check that comes later in the design table", m[1])
		}
		last = at
	}
	// フィールドの名前は、模型が持つものだけである。
	known := map[string]bool{}
	for _, set := range []map[string]string{agentJSONTopKeys, agentJSONCheckKeys, agentJSONHistoryKeys, agentJSONNotTestedKeys} {
		for k := range set {
			known[k] = true
		}
	}
	for _, m := range regexp.MustCompile(`"([a-z_]+)":`).FindAllStringSubmatch(block, -1) {
		if !known[m[1]] {
			t.Errorf("the example uses the field %q, which the model does not have", m[1])
		}
	}
	// 最上位の status は、例の検査から決まる値と一致する。終了コード 2 に倒す条件は、総合判定を
	// 動かす検査の FAILED に優先する。
	verdict := map[string]bool{}
	for _, row := range agentDoctorTable {
		verdict[row.id] = row.verdict
	}
	want := statusOK
	for _, m := range regexp.MustCompile(`\{"id":"([a-z_.]+)","status":"(\w+)"([^{}]*)\}`).FindAllStringSubmatch(block, -1) {
		switch {
		case strings.Contains(m[3], `"evidence_unreachable":true`):
			want = statusUnknown
		case want == statusOK && m[2] == statusFailed && verdict[m[1]]:
			want = statusFailed
		}
	}
	if status[1] != want {
		t.Errorf("the example's top-level status is %q, but its checks make it %q", status[1], want)
	}
}

// 制御ソケットに繋げない原因のうち、パスが長すぎる場合は別の事実なので別の符号を持つ。どちらの
// 場合も、それに続いて SKIPPED になった検査は agent.control と同じ符号を持つ(10.2c 節)。
func TestAgentDoctorControlSocketCodesNameOneFactEach(t *testing.T) {
	reasons := map[string]string{}
	for _, tc := range []struct {
		name     string
		err      error
		longPath bool
	}{
		{"no socket", &net.OpError{Op: "dial", Err: syscall.ENOENT}, false},
		{"path too long", &net.OpError{Op: "dial", Err: syscall.EINVAL}, true},
	} {
		in := testAgentDoctorInput(t, t.TempDir())
		if tc.longPath {
			useLongSocketPath(t, &in)
		}
		writeTestCredentials(t, in.CredentialsPath, registeredCredentials())
		holdTheLock(t, in.CredentialsPath)
		in.Dial = func(string) (net.Conn, error) { return nil, tc.err }
		rep := agentDiagnose(in)
		control, _ := findAgentCheck(rep, agentCheckControl)
		reasons[tc.name] = control.Reason
		for _, id := range []string{agentCheckStreamConn, agentCheckTunnelLocal, agentCheckListeners, agentCheckAllowTargets} {
			c, _ := findAgentCheck(rep, id)
			if c.Status != statusSkipped || c.Reason != control.Reason {
				t.Errorf("%s: %s = %s/%q, want skipped/%q as agent.control", tc.name, id, c.Status, c.Reason, control.Reason)
			}
		}
	}
	if reasons["no socket"] == reasons["path too long"] {
		t.Errorf("a missing socket and a socket path too long both read %q; they are two facts with two fixes", reasons["no socket"])
	}
}

// `--json` は、人向けの出力が値だけを示す検査を「Observed values」節に分けて状態語を省く形に
// 変わっても、一切変わらない(10.2c 節、2026-09-24 の所有者の決定、7a.11 節)。内部の模型、検査の
// id、状態、理由の符号、終了コードは変えないという約束を、この 6 つの検査の値で固定する。id と
// status は表のテストが既に固定しているので、ここでは status と reason の組を場面ごとに書き下す。
func TestAgentDoctorJSONValueOnlyChecksAreUnaffectedByObservedValues(t *testing.T) {
	for _, sc := range []struct {
		name   string
		setup  func(t *testing.T, in *agentDoctorInput)
		want   string // 6 つに共通の status
		reason string // 6 つに共通の reason
	}{
		{"a stopped agent", stoppedAgentForTest, statusSkipped, agentReasonNotRunning},
		{"a healthy running agent", healthyAgentForTest, statusUnknown, agentReasonNoThreshold},
	} {
		t.Run(sc.name, func(t *testing.T) {
			in := testAgentDoctorInput(t, t.TempDir())
			sc.setup(t, &in)
			rep := agentDiagnose(in)
			got := agentDoctorJSONOf(rep)
			for _, id := range []string{
				agentCheckStreamBackfl, agentCheckStreamLive, agentCheckWatchdog,
				agentCheckTransfer, agentCheckSessions, agentCheckRefusals,
			} {
				var found *agentDoctorJSONCheck
				for i := range got.Checks {
					if got.Checks[i].ID == id {
						found = &got.Checks[i]
						break
					}
				}
				if found == nil {
					t.Fatalf("%s: %s is missing from the JSON", sc.name, id)
				}
				if found.Status != sc.want || found.Reason != sc.reason {
					t.Errorf("%s: %s = %s/%q, want %s/%q", sc.name, id, found.Status, found.Reason, sc.want, sc.reason)
				}
				// 人向けの出力は値を読めた行に Next を出さないが、--json は next を持ち続ける。
				if found.Status == statusUnknown && found.Next == "" {
					t.Errorf("%s: %s carries no next in the JSON; the human output leaves it out, not the JSON", sc.name, id)
				}
			}
		})
	}
}

// この検査の内部の印(agentDoctorCheck.valueOnly)は人向けの出力だけが読み、`--json` には出さない
// (10.2c 節、2026-09-24 の所有者の決定)。agentdoctorjson.go がこの識別子を読むようになれば、
// うっかり機械向けの保証にまで染み出すので、静的にも塞いでおく。
func TestAgentDoctorJSONNeverReadsValueOnly(t *testing.T) {
	b, err := os.ReadFile("agentdoctorjson.go")
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(b), "valueOnly") {
		t.Error("agentdoctorjson.go reads valueOnly; it must stay an internal marker for the human output alone")
	}
}
