//go:build linux

package vpsd

import (
	"database/sql"
	"errors"
	"fmt"
	"net/netip"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/rahanahu/wgft/internal/vpsd/store"
)

// ip-mismatch の確認済みの組の扱い(仕様 5.2 節)。judgeIPMismatch に観測を直接与え、1 回の
// 呼び出しを 15 秒ごとの 1 回として回を進める。

const (
	ackStream = "198.51.100.7"
	ackWG     = "203.0.113.9"
	otherWG   = "203.0.113.10"
)

type mismatchDriver struct {
	t      *testing.T
	d      *Daemon
	st     *store.Store
	counts map[string]int
}

func newMismatchDriver(t *testing.T, path string) *mismatchDriver {
	t.Helper()
	st, err := store.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })
	// 確認済みの組は登録済みのエージェントにだけ残る。開き直し(再起動)では登録済みのまま
	if _, err := st.AgentByName("home"); errors.Is(err, sql.ErrNoRows) {
		tok, err := st.IssueJoinToken("home", time.Hour)
		if err != nil {
			t.Fatal(err)
		}
		if _, _, err := st.Register(tok, "home", "203.0.113.2", netip.MustParsePrefix("10.200.0.0/24")); err != nil {
			t.Fatal(err)
		}
	} else if err != nil {
		t.Fatal(err)
	}
	return &mismatchDriver{t: t, d: newTestDaemon(t, okWGStatusDataplane{}, st), st: st, counts: map[string]int{}}
}

// tick は 1 回分の観測を n 回与える。
func (m *mismatchDriver) tick(n int, streamIP, wgIP string) {
	for i := 0; i < n; i++ {
		m.d.judgeIPMismatch(m.counts, []ipObservation{{Agent: "home", StreamIP: streamIP, WGIP: wgIP}})
	}
}

func (m *mismatchDriver) warnings() []store.Warning {
	m.t.Helper()
	ws, err := m.st.AgentWarnings("home")
	if err != nil {
		m.t.Fatal(err)
	}
	var out []store.Warning
	for _, w := range ws {
		if w.Kind == store.WarnIPMismatch {
			out = append(out, w)
		}
	}
	return out
}

func (m *mismatchDriver) acks() []store.Ack {
	m.t.Helper()
	a, err := m.st.WarningAcks(store.WarnIPMismatch)
	if err != nil {
		m.t.Fatal(err)
	}
	return a
}

// warnAndDismiss は食い違いを 8 回観測して警告を出させ、管理者の「警告を消す」を行う。
func (m *mismatchDriver) warnAndDismiss() {
	m.t.Helper()
	m.tick(8, ackStream, ackWG)
	if len(m.warnings()) != 1 {
		m.t.Fatalf("8 mismatches must warn, got %+v", m.warnings())
	}
	if err := m.d.DismissWarning("home", store.WarnIPMismatch, ""); err != nil {
		m.t.Fatal(err)
	}
	if len(m.warnings()) != 0 || len(m.acks()) != 1 {
		m.t.Fatalf("after dismiss: warnings %+v, acks %+v", m.warnings(), m.acks())
	}
}

// 警告が 8 回目でちょうど出ることを確かめながら、7 回までは出ないことも確かめる。
func (m *mismatchDriver) expectWarnAfterNormalCount(streamIP, wgIP string) {
	m.t.Helper()
	m.tick(7, streamIP, wgIP)
	if ws := m.warnings(); len(ws) != 0 {
		m.t.Fatalf("7 observations must not warn yet, got %+v", ws)
	}
	m.tick(1, streamIP, wgIP)
	ws := m.warnings()
	if len(ws) != 1 || ws[0].Detail != store.IPMismatchDetail(streamIP, wgIP) {
		m.t.Fatalf("the 8th observation must warn about %s / %s, got %+v", streamIP, wgIP, ws)
	}
}

func TestMismatchAckSuppressesSamePair(t *testing.T) {
	m := newMismatchDriver(t, filepath.Join(t.TempDir(), "s.sqlite"))
	m.warnAndDismiss()
	m.tick(200, ackStream, ackWG)
	if ws := m.warnings(); len(ws) != 0 {
		t.Fatalf("the acknowledged pair must not warn again, got %+v", ws)
	}
	if len(m.acks()) != 1 {
		t.Fatalf("the acknowledgement must stay while the pair continues, got %+v", m.acks())
	}
}

func TestMismatchAckClearedOnMatch(t *testing.T) {
	m := newMismatchDriver(t, filepath.Join(t.TempDir(), "s.sqlite"))
	m.warnAndDismiss()
	m.tick(1, ackStream, ackStream)
	if a := m.acks(); len(a) != 0 {
		t.Fatalf("a matching observation must discard the acknowledgement, got %+v", a)
	}
	m.expectWarnAfterNormalCount(ackStream, ackWG)
}

func TestMismatchAckClearedOnPairChange(t *testing.T) {
	m := newMismatchDriver(t, filepath.Join(t.TempDir(), "s.sqlite"))
	m.warnAndDismiss()
	m.tick(1, ackStream, otherWG)
	if a := m.acks(); len(a) != 0 {
		t.Fatalf("a different pair must discard the acknowledgement, got %+v", a)
	}
	// 新しい組は 1 回目を観測済み。残り 7 回で警告になる(通常の 8 回)
	m.tick(6, ackStream, otherWG)
	if ws := m.warnings(); len(ws) != 0 {
		t.Fatalf("the new pair must not warn before 8 observations, got %+v", ws)
	}
	m.tick(1, ackStream, otherWG)
	ws := m.warnings()
	if len(ws) != 1 || ws[0].Detail != store.IPMismatchDetail(ackStream, otherWG) {
		t.Fatalf("the 8th observation of the new pair must warn about it, got %+v", ws)
	}
}

func TestMismatchAckKeptWhileUnobserved(t *testing.T) {
	m := newMismatchDriver(t, filepath.Join(t.TempDir(), "s.sqlite"))
	m.warnAndDismiss()
	m.tick(20, "", ackWG)
	m.tick(20, ackStream, "")
	m.tick(20, "", "")
	if a := m.acks(); len(a) != 1 {
		t.Fatalf("unobserved ticks must keep the acknowledgement, got %+v", a)
	}
	m.tick(50, ackStream, ackWG)
	if ws := m.warnings(); len(ws) != 0 {
		t.Fatalf("the acknowledged pair must stay suppressed after unobserved ticks, got %+v", ws)
	}
}

func TestMismatchAckKeptAcrossRestart(t *testing.T) {
	path := filepath.Join(t.TempDir(), "s.sqlite")
	m := newMismatchDriver(t, path)
	m.warnAndDismiss()
	m.st.Close()

	// 再起動:store を開き直し、連続回数(メモリ上)は失われる。接続が揃うまでは観測できない
	m2 := newMismatchDriver(t, path)
	m2.tick(4, "", "")
	m2.tick(2, "", ackWG)
	if a := m2.acks(); len(a) != 1 {
		t.Fatalf("the acknowledgement must survive a restart and the incomplete observations after it, got %+v", a)
	}
	m2.tick(50, ackStream, ackWG)
	if ws := m2.warnings(); len(ws) != 0 {
		t.Fatalf("the acknowledged pair must stay suppressed after a restart, got %+v", ws)
	}
}

// ip-flapping の「消す」は今までどおり行を消すだけで、確認済みの組を作らない。
func TestFlappingDismissUnchanged(t *testing.T) {
	m := newMismatchDriver(t, filepath.Join(t.TempDir(), "s.sqlite"))
	if err := m.st.AddWarning("home", store.WarnIPFlapping, "wg endpoint alternated between 198.51.100.7 and 203.0.113.9"); err != nil {
		t.Fatal(err)
	}
	if err := m.d.DismissWarning("home", store.WarnIPFlapping, ""); err != nil {
		t.Fatal(err)
	}
	ws, _ := m.st.AgentWarnings("home")
	if len(ws) != 0 {
		t.Fatalf("flapping warning must be removed, got %+v", ws)
	}
	for _, kind := range []string{store.WarnIPFlapping, store.WarnIPMismatch} {
		if a, _ := m.st.WarningAcks(kind); len(a) != 0 {
			t.Fatalf("dismissing ip-flapping must not record an acknowledgement, got %+v", a)
		}
	}
	// 確認済みの組が無いので、食い違いは通常どおり警告になる
	m.expectWarnAfterNormalCount(ackStream, ackWG)
}

// 確認済みの組が無い間は、組が変わっても連続回数を数え直さない(今までどおり)。
func TestMismatchWithoutAckKeepsCountingAcrossPairs(t *testing.T) {
	m := newMismatchDriver(t, filepath.Join(t.TempDir(), "s.sqlite"))
	m.tick(4, ackStream, ackWG)
	m.tick(4, ackStream, otherWG)
	ws := m.warnings()
	if len(ws) != 1 || ws[0].Detail != store.IPMismatchDetail(ackStream, otherWG) {
		t.Fatalf("8 consecutive mismatches over two pairs must warn, got %+v", ws)
	}
}

// IPv4 射影の IPv6 で観測しても、正規化した組として確認済みと照合する。
func TestMismatchAckMatchesNormalizedIPs(t *testing.T) {
	m := newMismatchDriver(t, filepath.Join(t.TempDir(), "s.sqlite"))
	m.warnAndDismiss()
	m.tick(50, "::ffff:"+ackStream, ackWG)
	if ws := m.warnings(); len(ws) != 0 {
		t.Fatalf("an IPv4-mapped observation of the acknowledged pair must stay suppressed, got %+v", ws)
	}
	if len(m.acks()) != 1 {
		t.Fatalf("the acknowledgement must stay, got %+v", m.acks())
	}
}

// 監視の回が確認済みの組を読んだ後、警告を記録する前に管理者が警告を消しても、消した警告は
// 戻らない。記録は確認済みの組との照合と同じ文で行う。
func TestMismatchDismissDuringTickDoesNotComeBack(t *testing.T) {
	m := newMismatchDriver(t, filepath.Join(t.TempDir(), "s.sqlite"))
	m.tick(8, ackStream, ackWG)
	if len(m.warnings()) != 1 {
		t.Fatalf("8 mismatches must warn, got %+v", m.warnings())
	}
	// 連続回数は 8 以上のまま。次の回は確認済みの組が無い状態を読み、その直後に消す操作が入る
	m.d.afterMismatchAcksRead = func() {
		m.d.afterMismatchAcksRead = nil
		if err := m.d.DismissWarning("home", store.WarnIPMismatch, ""); err != nil {
			t.Fatal(err)
		}
	}
	m.tick(1, ackStream, ackWG)
	if m.d.afterMismatchAcksRead != nil {
		t.Fatal("the hook did not run")
	}
	if ws := m.warnings(); len(ws) != 0 {
		t.Fatalf("a warning dismissed during the tick must not come back, got %+v", ws)
	}
	if len(m.acks()) != 1 {
		t.Fatalf("the dismissal must be recorded, got %+v", m.acks())
	}
	m.tick(50, ackStream, ackWG)
	if ws := m.warnings(); len(ws) != 0 {
		t.Fatalf("the acknowledged pair must stay suppressed, got %+v", ws)
	}
}

// 確認済みの組を読めない回は、判定そのものを飛ばす。連続回数を進めず、警告も出さない。
func TestMismatchTickSkippedWhenAcksUnreadable(t *testing.T) {
	path := filepath.Join(t.TempDir(), "s.sqlite")
	m := newMismatchDriver(t, path)
	logs := captureLog(t)
	// 別の接続で表の名前を変え、WarningAcks だけを失敗させる。warnings の表はそのまま使える
	raw, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	defer raw.Close()
	if _, err := raw.Exec("ALTER TABLE warning_acks RENAME TO warning_acks_hidden"); err != nil {
		t.Fatal(err)
	}
	m.tick(20, ackStream, ackWG)
	if n := m.counts["home"]; n != 0 {
		t.Fatalf("an unreadable tick must not advance the count, got %d", n)
	}
	if ws := m.warnings(); len(ws) != 0 {
		t.Fatalf("an unreadable tick must not warn, got %+v", ws)
	}
	if !strings.Contains(logs.String(), "ip mismatch watch: reading acknowledged mismatches") {
		t.Fatalf("the skipped tick must be logged, got %q", logs.String())
	}
	if _, err := raw.Exec("ALTER TABLE warning_acks_hidden RENAME TO warning_acks"); err != nil {
		t.Fatal(err)
	}
	// 読めるようになった後は 1 回目から数える
	m.expectWarnAfterNormalCount(ackStream, ackWG)
}

// ipMismatchStep 自身も、確認済みの組には警告を求めない。記録の側(AddIPMismatchWarning)も
// 確認済みの組を記録しないので、この判定は判定の段と記録の段の二重の守りの片方である。
func TestMismatchStepDoesNotWarnForAcknowledgedPair(t *testing.T) {
	acks := []store.Ack{{Agent: "home", Kind: store.WarnIPMismatch, StreamIP: ackStream, WGIP: ackWG}}
	count := 0
	for i := 0; i < 20; i++ {
		var warn bool
		var discard []store.Ack
		count, warn, discard = ipMismatchStep(count, ackStream, ackWG, acks)
		if warn || len(discard) != 0 {
			t.Fatalf("tick %d: warn = %v, discard = %+v; an acknowledged pair must neither warn nor be discarded", i+1, warn, discard)
		}
	}
}

func (m *mismatchDriver) hasWarning(streamIP, wgIP string) bool {
	m.t.Helper()
	for _, w := range m.warnings() {
		if w.Detail == store.IPMismatchDetail(streamIP, wgIP) {
			return true
		}
	}
	return false
}

func rotatedWG(i int) string { return fmt.Sprintf("203.0.113.%d", 100+i) }

// 確認済みの組が無い間は組が変わっても連続回数を数え直さないので、食い違いが 2 分続いた後は、
// 観測のたびに新しい組の行が 1 行ずつ増える。行はエージェントごとに MaxIPMismatchWarnings 行で
// 止まり、検知は続く。上限で消えた組は確認済みにならず、再び観測すれば警告に戻る(仕様 5.2 節)。
func TestMismatchRowsCappedWhilePairsRotate(t *testing.T) {
	m := newMismatchDriver(t, filepath.Join(t.TempDir(), "s.sqlite"))
	m.tick(7, ackStream, ackWG)
	const extra = 20
	for i := 0; i < store.MaxIPMismatchWarnings+extra; i++ {
		m.tick(1, ackStream, rotatedWG(i))
		if i < store.MaxIPMismatchWarnings {
			if n := len(m.warnings()); n != i+1 {
				t.Fatalf("after %d rotated observations: %d rows, want one new row per observation", i+1, n)
			}
		}
	}
	if n := len(m.warnings()); n != store.MaxIPMismatchWarnings {
		t.Fatalf("rows = %d, want %d", n, store.MaxIPMismatchWarnings)
	}
	if !m.hasWarning(ackStream, rotatedWG(store.MaxIPMismatchWarnings+extra-1)) {
		t.Fatal("the latest pair must be kept")
	}
	if m.hasWarning(ackStream, rotatedWG(0)) {
		t.Fatal("the oldest pair must be trimmed")
	}
	if a := m.acks(); len(a) != 0 {
		t.Fatalf("trimming must not record acknowledgements, got %+v", a)
	}
	// 消えた組を再び観測すれば、連続回数は 8 以上のままなので、その回に警告に戻る
	m.tick(1, ackStream, rotatedWG(0))
	if !m.hasWarning(ackStream, rotatedWG(0)) || len(m.warnings()) != store.MaxIPMismatchWarnings {
		t.Fatalf("the trimmed pair observed again must warn again within the cap, got %d rows", len(m.warnings()))
	}
}

// 確認済みの組は、上限で行が消えた後も警告にならない。上限は確認済みの組を変えない。
func TestMismatchAckSuppressesAfterCapTrims(t *testing.T) {
	m := newMismatchDriver(t, filepath.Join(t.TempDir(), "s.sqlite"))
	m.warnAndDismiss()
	before := m.acks()
	// 監視の回を通すと別の組の観測が確認済みの組を捨てるので、行は store に直接記録する
	for i := 0; i < store.MaxIPMismatchWarnings+10; i++ {
		if added, _, err := m.st.AddIPMismatchWarning("home", ackStream, rotatedWG(i)); err != nil || !added {
			t.Fatalf("AddIPMismatchWarning(%d) = %v, %v", i, added, err)
		}
	}
	if n := len(m.warnings()); n != store.MaxIPMismatchWarnings {
		t.Fatalf("rows = %d, want %d", n, store.MaxIPMismatchWarnings)
	}
	if after := m.acks(); len(after) != 1 || after[0] != before[0] {
		t.Fatalf("acknowledgements after trimming = %+v, want unchanged %+v", after, before)
	}
	m.tick(50, ackStream, ackWG)
	if m.hasWarning(ackStream, ackWG) {
		t.Fatal("the acknowledged pair must stay suppressed after trimming")
	}
	if len(m.acks()) != 1 || len(m.warnings()) != store.MaxIPMismatchWarnings {
		t.Fatalf("after observing the acknowledged pair: acks %+v, %d rows", m.acks(), len(m.warnings()))
	}
}

// 食い違いが続く間、"detected IP mismatch" のログは行を新しく作った回の 1 回だけである。時刻を更新
// するだけの観測では書かない。組が変われば新しい行になるので、もう 1 回書く。
func TestMismatchDetectionLogsOncePerPair(t *testing.T) {
	m := newMismatchDriver(t, filepath.Join(t.TempDir(), "s.sqlite"))
	logs := captureLog(t)
	count := func() int { return strings.Count(logs.String(), "detected IP mismatch") }
	m.tick(7, ackStream, ackWG)
	if n := count(); n != 0 {
		t.Fatalf("7 observations must not log a detection, got %d", n)
	}
	m.tick(1, ackStream, ackWG)
	if n := count(); n != 1 {
		t.Fatalf("the 8th observation must log the detection once, got %d\n%s", n, logs.String())
	}
	m.tick(40, ackStream, ackWG)
	if n := count(); n != 1 {
		t.Fatalf("a continuing mismatch must not log again, got %d\n%s", n, logs.String())
	}
	if ws := m.warnings(); len(ws) != 1 {
		t.Fatalf("the continuing mismatch must keep one refreshed row, got %+v", ws)
	}
	// 組が変われば新しい行になり、もう 1 回書く。続く間は書かない
	m.tick(1, ackStream, otherWG)
	if n := count(); n != 2 {
		t.Fatalf("a new pair must log once, got %d\n%s", n, logs.String())
	}
	m.tick(10, ackStream, otherWG)
	if n := count(); n != 2 {
		t.Fatalf("the new pair continuing must not log again, got %d\n%s", n, logs.String())
	}
	// 警告を消すと確認済みの組になり、書かない
	if err := m.d.DismissWarning("home", store.WarnIPMismatch, ""); err != nil {
		t.Fatal(err)
	}
	m.tick(10, ackStream, otherWG)
	if n := count(); n != 2 {
		t.Fatalf("an acknowledged pair must not log, got %d\n%s", n, logs.String())
	}
}
