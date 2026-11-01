package wgstack

// 凍結した Go の wgstack の記録 (docs/design/v2/test-tooling.md の 4 節) のうち、package の中の試験から作る
// 記録の作り方と、git に入れた記録を Go の wgstack で照らし直す試験。

import (
	"bytes"
	"encoding/json"
	"fmt"
	"math/rand/v2"
	"os"
	"path/filepath"
	"runtime"
	"runtime/debug"
	"slices"
	"strconv"
	"strings"
	"testing"

	"github.com/rahanahu/wgft/internal/dutproto"
)

// recordSetEnv は作る記録の集まり。git (既定) は git に入れる集まり、full は手元の cache に作る大きな集まり。
const recordSetEnv = "WGFT_WGSTACK_RECORD_SET"

// recordCheckPlatform は、記録を作れる組 (linux/amd64、GOAMD64=v1、commit の指定) でなければ試験を止める。
// CUBIC の浮動小数点の値は compiler が積和の命令を使うかで最後の桁が変わりうるので、作る環境を 1 つに決める。
func recordCheckPlatform(t *testing.T) {
	t.Helper()
	if runtime.GOOS != "linux" || runtime.GOARCH != "amd64" || goamd64() != "v1" {
		t.Fatalf("recordings are made on linux/amd64 with GOAMD64=v1 only; this is %s/%s with GOAMD64=%q; use scripts/wgstack-record.sh",
			runtime.GOOS, runtime.GOARCH, goamd64())
	}
	if os.Getenv(recordCommitEnv) == "" {
		t.Fatalf("set %s to the last commit of the Go wgstack's product code; scripts/wgstack-record.sh does", recordCommitEnv)
	}
}

// goamd64 は、この試験のバイナリを作った GOAMD64 の水準。amd64 でなければ空。
func goamd64() string {
	if bi, ok := debug.ReadBuildInfo(); ok {
		for _, st := range bi.Settings {
			if st.Key == "GOAMD64" {
				return st.Value
			}
		}
	}
	return ""
}

// variant4b は 4b の変種:輻輳の制御は NewReno、boost は与えない。相手は SACK も timestamp も示さない。
// wgstack-rs.md の PR 4b がデータの転送まで一致させる記録である。
var (
	ccNewReno  = CongestionNewReno
	boostNever = BoostNever
)

// specNoFlip は、試験が boost を内部から切り替える種の記録の変種:切り替えを止める。切り替えは frame に無い
// 操作で、記録はそこで終わるためである。boost の方針は既定のままなので、需要による boost の取得と floor への
// 戻りは記録に残る。
func specNoFlip(s recSpec) recSpec {
	s.variant = "noflip"
	s.name += ".noflip"
	return s
}

func spec4b(s recSpec) recSpec {
	s.variant, s.cc, s.boost = "4b", &ccNewReno, &boostNever
	s.name += ".4b"
	return s
}

// fuzzCorePrograms は FuzzCore の記録の入力:FuzzCore の f.Add の列、repo の corpus、種から作った列。
// 4b の変種では fuzzCoreRun が SYN に SACK-permitted と timestamp を付けない。
func fuzzCorePrograms(t *testing.T, generated int) map[string][]byte {
	t.Helper()
	progs := map[string][]byte{}
	for i, p := range fuzzCoreSeeds {
		progs[fmt.Sprintf("seed-%d", i+1)] = p
	}
	dir := filepath.Join("testdata", "fuzz", "FuzzCore")
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range entries {
		b, err := os.ReadFile(filepath.Join(dir, e.Name()))
		if err != nil {
			t.Fatal(err)
		}
		p, err := parseFuzzBytes(string(b))
		if err != nil {
			t.Fatalf("%s: %v", e.Name(), err)
		}
		progs["corpus-"+e.Name()] = p
	}
	for i := range generated {
		r := rand.New(rand.NewPCG(uint64(i+1), 0xc0de))
		p := make([]byte, 200+r.IntN(400))
		for j := range p {
			p[j] = byte(r.Uint32())
		}
		progs[fmt.Sprintf("gen-%d", i+1)] = p
	}
	return progs
}

// parseFuzzBytes は `go test fuzz v1` の形式の 1 つの []byte の値を読む。
func parseFuzzBytes(s string) ([]byte, error) {
	lines := strings.Split(strings.TrimSpace(s), "\n")
	if len(lines) != 2 || lines[0] != "go test fuzz v1" {
		return nil, fmt.Errorf("not a go test fuzz v1 file with one value")
	}
	v, ok := strings.CutPrefix(lines[1], "[]byte(")
	if !ok || !strings.HasSuffix(v, ")") {
		return nil, fmt.Errorf("the value is not a []byte")
	}
	u, err := strconv.Unquote(strings.TrimSuffix(v, ")"))
	if err != nil {
		return nil, err
	}
	return []byte(u), nil
}

// recordSet は作る記録の集まりの大きさ。
type recordSet struct {
	fuzzGenerated     int
	rxSeeds, txSeeds  []uint64
	advSeeds          []uint64
	rx4b, tx4b, adv4b []uint64
	length            int // stream の長さの上限。0 なら試験の既定
}

func recordSetFor(t *testing.T) recordSet {
	switch v := os.Getenv(recordSetEnv); v {
	case "", "git":
		// 種は、git の記録の上限 (test-tooling.md の 4 節) に収まり、選択が偏らないように、測った大きさから
		// 選んだ。送信の stream の試験は、損失の多い種で 1 つの記録が 1 MB 近くになるので、その種を除く
		return recordSet{
			fuzzGenerated: 8,
			rxSeeds:       []uint64{5, 9, 10}, txSeeds: []uint64{4, 5, 6, 7, 9, 15}, advSeeds: []uint64{1, 2, 3, 6, 9, 12, 15},
			rx4b: []uint64{1, 4}, tx4b: []uint64{1, 4, 6, 7}, adv4b: []uint64{1, 2, 3, 7},
			length: 30000,
		}
	case "full":
		seq := func(n uint64) []uint64 {
			var s []uint64
			for i := range n {
				s = append(s, i+1)
			}
			return s
		}
		return recordSet{fuzzGenerated: 200, rxSeeds: seq(100), txSeeds: seq(80), advSeeds: seq(200),
			rx4b: seq(40), tx4b: seq(40), adv4b: seq(40)}
	default:
		t.Fatalf("%s=%q; want git or full", recordSetEnv, v)
	}
	return recordSet{}
}

// TestWriteRecordings は、FuzzCore、受信と送信の stream の試験、敵対的な送り手の試験を、記録を求めて流し、
// WGFT_WGSTACK_RECORD の directory に書く。Go の wgstack の boost の枠の集まりはプロセスで 1 つだが、testNet
// は Device ごとに自分の集まりを持つ。それでも記録は 1 つずつ順に作る。各試験は記録のために変えた選択で
// 通ることも確かめる。
func TestWriteRecordings(t *testing.T) {
	dir := recordDir(t)
	recordCheckPlatform(t)
	set := recordSetFor(t)
	shorten := func(n int) int {
		if set.length > 0 {
			return min(n, set.length)
		}
		return n
	}
	for _, for4b := range []bool{false, true} {
		progs := fuzzCorePrograms(t, set.fuzzGenerated)
		names := slices.Sorted(func(yield func(string) bool) {
			for k := range progs {
				if !yield(k) {
					return
				}
			}
		})
		for _, name := range names {
			spec := recSpec{dir: dir, source: "fuzzcore", name: name, test: "FuzzCore"}
			if for4b {
				spec = spec4b(spec)
			}
			t.Run(spec.name, func(t *testing.T) { fuzzCoreRun(t, progs[name], spec) })
		}
	}
	for _, seed := range set.rxSeeds {
		cfg := rxStreamCfg(seed)
		cfg.length = shorten(cfg.length)
		cfg.rec = recSpec{dir: dir, source: "stream-rx", name: fmt.Sprintf("seed-%d", seed), test: "TestReceiveStreamIntegrity", seed: seed}
		if cfg.boostFlip {
			cfg.boostFlip, cfg.rec = false, specNoFlip(cfg.rec)
		}
		t.Run("rx-"+cfg.rec.name, func(t *testing.T) { runRx(t, cfg) })
	}
	for _, seed := range set.rx4b {
		cfg := rxStreamCfg(seed)
		cfg.length = shorten(cfg.length)
		cfg.ts, cfg.sack, cfg.boostFlip = false, false, false
		cfg.rec = spec4b(recSpec{dir: dir, source: "stream-rx", name: fmt.Sprintf("seed-%d", seed), test: "TestReceiveStreamIntegrity", seed: seed})
		t.Run("rx-"+cfg.rec.name, func(t *testing.T) { runRx(t, cfg) })
	}
	for _, seed := range set.txSeeds {
		cfg := txStreamCfg(seed)
		cfg.length = shorten(cfg.length)
		cfg.rec = recSpec{dir: dir, source: "stream-tx", name: fmt.Sprintf("seed-%d", seed), test: "TestSendStreamIntegrity", seed: seed}
		if cfg.boost {
			cfg.boost, cfg.rec = false, specNoFlip(cfg.rec)
		}
		t.Run("tx-"+cfg.rec.name, func(t *testing.T) { runTx(t, cfg) })
	}
	for _, seed := range set.tx4b {
		cfg := txStreamCfg(seed)
		cfg.length = shorten(cfg.length)
		cfg.ts, cfg.sack, cfg.boost = false, false, false
		cfg.rec = spec4b(recSpec{dir: dir, source: "stream-tx", name: fmt.Sprintf("seed-%d", seed), test: "TestSendStreamIntegrity", seed: seed})
		t.Run("tx-"+cfg.rec.name, func(t *testing.T) { runTx(t, cfg) })
	}
	for _, seed := range set.advSeeds {
		cfg := adversaryCfg(seed)
		cfg.length = shorten(cfg.length)
		cfg.rec = recSpec{dir: dir, source: "adversarial", name: fmt.Sprintf("seed-%d", seed), test: "TestAdversarialSender", seed: seed}
		if cfg.boos {
			cfg.boos, cfg.rec = false, specNoFlip(cfg.rec)
		}
		t.Run("adv-"+cfg.rec.name, func(t *testing.T) { runAudit(t, cfg) })
	}
	for _, seed := range set.adv4b {
		cfg := adversaryCfg(seed)
		cfg.length = shorten(cfg.length)
		cfg.ts, cfg.sack, cfg.nr, cfg.boos, cfg.icmp = false, false, true, false, false
		cfg.rec = spec4b(recSpec{dir: dir, source: "adversarial", name: fmt.Sprintf("seed-%d", seed), test: "TestAdversarialSender", seed: seed})
		t.Run("adv-"+cfg.rec.name, func(t *testing.T) { runAudit(t, cfg) })
	}
}

// recordingsDir は repo の記録の置き場。
const recordingsDir = "../../testdata/wgstack-rec"

// replayDirEnv は TestRecordingsReplay が照らす別の directory (手元の cache の大きな集まり)。
const replayDirEnv = "WGFT_WGSTACK_REPLAY_DIR"

// TestRecordingsReplay は記録を凍結した Go の wgstack に流し直し、すべての応答が byte の単位で記録と同じで
// あることを確かめる。STATS、BOUND、HELD は種類だけを比べる。記録が今の Go の wgstack と dutserve の振る舞いを
// 写していること、meta の印が frame から求めた印と同じであることも、ここで確かめる。
func TestRecordingsReplay(t *testing.T) {
	// 記録は amd64 の GOAMD64=v1 で作った。arm64 と GOAMD64=v3 以上では compiler が積和の命令を使い、
	// CUBIC の浮動小数点の値の最後の桁が変わりうる (4 節)
	if lvl := goamd64(); runtime.GOARCH != "amd64" || (lvl != "v1" && lvl != "v2") {
		t.Skipf("the recordings were made on amd64 with GOAMD64=v1; this build is %s with GOAMD64=%q, where fused multiply-add may change CUBIC's values", runtime.GOARCH, lvl)
	}
	// 記録の中の Device は捨てた packet などを log に書く。照らし直しの出力を埋めないように黙らせる。
	// この試験の並行な副試験だけが Device を動かす間に置き換え、すべてが終わってから戻す
	quiet := logf
	logf = func(string, ...any) {}
	t.Cleanup(func() { logf = quiet })
	dir := recordingsDir
	if d := os.Getenv(replayDirEnv); d != "" {
		dir = d
	}
	var files []string
	err := filepath.WalkDir(dir, func(p string, d os.DirEntry, err error) error {
		if err == nil && !d.IsDir() && strings.HasSuffix(p, ".rec.gz") {
			files = append(files, p)
		}
		return err
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(files) == 0 {
		t.Fatalf("no recordings under %s", dir)
	}
	if testing.Short() {
		files = files[:min(len(files), 20)]
	}
	for _, f := range files {
		rel, _ := filepath.Rel(dir, f)
		t.Run(rel, func(t *testing.T) {
			t.Parallel()
			replayRecording(t, f)
		})
	}
}

func replayRecording(t *testing.T, path string) {
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	meta, frames, err := dutproto.ReadRecord(bytes.NewReader(b))
	if err != nil {
		t.Fatal(err)
	}
	fr, err := dutproto.SplitFrames(frames)
	if err != nil {
		t.Fatal(err)
	}
	if tags := dutproto.Tags(fr); !slices.Equal(tags, meta.Tags) {
		t.Errorf("meta tags %v, the frames give %v", meta.Tags, tags)
	}
	if meta.Variant == "4b" && !dutproto.Within(meta.Tags, dutproto.Stage4bTags) {
		t.Errorf("a recording of the 4b variant has the tags %v, beyond %v", meta.Tags, dutproto.Stage4bTags)
	}
	if len(fr) < 2 || fr[0].Kind != dutproto.KindHello {
		t.Fatalf("the recording does not start with HELLO")
	}
	var srv *dutServer
	defer func() {
		if srv != nil {
			srv.dev.Close()
		}
	}()
	for i := 0; i < len(fr); i += 2 {
		req, err := dutproto.Decode(fr[i].Kind, fr[i].Body)
		if err != nil {
			t.Fatalf("request %d: %v", i/2, err)
		}
		var resp dutproto.Msg
		var perr *protoError
		if h, ok := req.(*dutproto.Hello); ok && srv == nil {
			srv, perr = newDUTServerWith(h, true)
			resp = &dutproto.HelloOK{Engine: dutserveEngine, Version: dutproto.Version}
		} else {
			resp, perr = srv.handle(req)
		}
		if perr != nil {
			t.Fatalf("request %d %s: protocol error %s", i/2, dutproto.Format(req), perr.msg)
		}
		got := dutproto.AppendFrame(nil, resp)
		want := fr[i+1]
		switch req.Kind() {
		case dutproto.KindStats, dutproto.KindBound, dutproto.KindHeld:
			if resp.Kind() != want.Kind {
				t.Fatalf("request %d %s: answered %s, recorded %s", i/2, req.Kind(), resp.Kind(), want.Kind)
			}
			continue
		}
		if !bytes.Equal(got, want.Bytes) {
			wm, _ := dutproto.Decode(want.Kind, want.Body)
			t.Fatalf("request %d %s:\n got  %s\n want %s", i/2, dutproto.Format(req), dutproto.Format(resp), formatOr(wm, want))
		}
	}
}

func formatOr(m dutproto.Msg, f dutproto.RawFrame) string {
	if m == nil {
		return fmt.Sprintf("undecodable %s", f.Kind)
	}
	return dutproto.Format(m)
}

// divergence は意図した違いの一覧 (testdata/wgstack-rec/divergences.json) の 1 行。
type divergence struct {
	Record   string `json:"record"`   // source/name
	Request  int    `json:"request"`  // 最初に食い違う応答の、要求の番号 (0 は HELLO)
	Response string `json:"response"` // Rust の応答の frame の 16 進
	Reason   string `json:"reason"`
}

// TestDivergencesList は意図した違いの一覧の形を確かめる:どの行も git の記録を指し、番号が記録の中にあり、
// 応答が 1 つの応答の frame で、理由を持つ。
func TestDivergencesList(t *testing.T) {
	b, err := os.ReadFile(filepath.Join(recordingsDir, "divergences.json"))
	if err != nil {
		t.Fatal(err)
	}
	var list []divergence
	dec := json.NewDecoder(bytes.NewReader(b))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&list); err != nil {
		t.Fatal(err)
	}
	seen := map[string]bool{}
	for _, d := range list {
		if seen[d.Record] {
			t.Errorf("%s: more than one line; a replay stops at the first difference", d.Record)
		}
		seen[d.Record] = true
		rb, err := os.ReadFile(filepath.Join(recordingsDir, d.Record+".rec.gz"))
		if err != nil {
			t.Errorf("%s: %v", d.Record, err)
			continue
		}
		_, frames, err := dutproto.ReadRecord(bytes.NewReader(rb))
		if err != nil {
			t.Errorf("%s: %v", d.Record, err)
			continue
		}
		fr, _ := dutproto.SplitFrames(frames)
		if d.Request <= 0 || 2*d.Request >= len(fr) {
			t.Errorf("%s: request %d is not a request after HELLO in the recording", d.Record, d.Request)
		}
		raw, err := hexBytes(d.Response)
		if err != nil {
			t.Errorf("%s: response: %v", d.Record, err)
			continue
		}
		rf, err := dutproto.SplitFrames(append(dutproto.AppendFrame(nil, &dutproto.Now{}), raw...))
		if err != nil || len(rf) != 2 {
			t.Errorf("%s: the response is not one response frame", d.Record)
		}
		if strings.TrimSpace(d.Reason) == "" {
			t.Errorf("%s: no reason", d.Record)
		}
	}
}

func hexBytes(s string) ([]byte, error) {
	var b dutproto.Bytes
	err := b.UnmarshalText([]byte(s))
	return b, err
}

// recordingsBudget は git に入れる記録の合計の上限 (test-tooling.md の 4 節)。
const recordingsBudget = 5 << 20

// TestRecordingsBudget は git の記録の合計が上限に収まることを確かめる。
func TestRecordingsBudget(t *testing.T) {
	var total int64
	err := filepath.WalkDir(recordingsDir, func(p string, d os.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return err
		}
		fi, err := d.Info()
		if err == nil {
			total += fi.Size()
		}
		return err
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("the recordings take %d bytes of %d", total, recordingsBudget)
	if total > recordingsBudget {
		t.Errorf("the recordings take %d bytes, over the budget of %d", total, recordingsBudget)
	}
}
