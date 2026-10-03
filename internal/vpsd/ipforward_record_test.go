//go:build linux

package vpsd

import (
	"bytes"
	"errors"
	"log"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/rahanahu/wgft/internal/vpsd/store"
)

// The two-stage ip_forward record (design.md 6.1 節): a planned record before the write, and the
// confirmed record saved together with the planned record's removal after it. These tests run
// enableIPForward against a real server database, with the kernel value and chosen database
// writes replaced.

var errInjected = errors.New("injected")

// faultyRecords is a real server database whose writes can be made to fail one by one.
type faultyRecords struct {
	*store.Store
	failPlanned, failDelete, failConfirm bool
}

func (f *faultyRecords) SetMeta(key string, value []byte) error {
	if f.failPlanned && key == store.MetaIPForwardWriteStartedAt {
		return errInjected
	}
	return f.Store.SetMeta(key, value)
}

func (f *faultyRecords) DeleteMeta(key string) error {
	if f.failDelete {
		return errInjected
	}
	return f.Store.DeleteMeta(key)
}

func (f *faultyRecords) SetMetaAndDelete(key string, value []byte, del string) error {
	if f.failConfirm {
		return errInjected
	}
	return f.Store.SetMetaAndDelete(key, value, del)
}

// fakeIPForward is the kernel value. write records the database's records as they were at the
// moment of the write.
type fakeIPForward struct {
	t        *testing.T
	st       *store.Store
	value    bool
	readErr  error
	writeErr error
	// crash makes write stop the caller right after the value is written, the way a killed
	// process would.
	crash  bool
	writes int
	// atWrite is what the database held when write ran.
	atWrite records
}

type records struct{ planned, confirmed string }

func readRecords(t *testing.T, st *store.Store) records {
	t.Helper()
	get := func(key string) string {
		b, err := st.GetMeta(key)
		if errors.Is(err, store.ErrNotFound) {
			return ""
		}
		if err != nil {
			t.Fatalf("reading %s: %v", key, err)
		}
		return string(b)
	}
	return records{planned: get(store.MetaIPForwardWriteStartedAt), confirmed: get(store.MetaIPForwardSetAt)}
}

var errCrash = errors.New("crashed")

func (k *fakeIPForward) ops() ipForwardOps {
	clock := time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC)
	return ipForwardOps{
		read: func() (bool, error) { return k.value, k.readErr },
		write: func() error {
			k.writes++
			k.atWrite = readRecords(k.t, k.st)
			if k.writeErr != nil {
				return k.writeErr
			}
			k.value = true
			if k.crash {
				panic(errCrash)
			}
			return nil
		},
		now: func() time.Time { clock = clock.Add(time.Second); return clock },
	}
}

func newRecordsDB(t *testing.T) *store.Store {
	t.Helper()
	st, err := store.Open(filepath.Join(t.TempDir(), "s.sqlite"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })
	return st
}

func captureStdLog(t *testing.T) *bytes.Buffer {
	t.Helper()
	var buf bytes.Buffer
	prev := log.Writer()
	log.SetOutput(&buf)
	t.Cleanup(func() { log.SetOutput(prev) })
	return &buf
}

// TestIPForwardRecordsPlannedBeforeAndConfirmedAfterTheWrite checks the normal path: the planned
// record is in the database when the value is written, and afterwards only the confirmed record
// remains.
func TestIPForwardRecordsPlannedBeforeAndConfirmedAfterTheWrite(t *testing.T) {
	st := newRecordsDB(t)
	k := &fakeIPForward{t: t, st: st}
	if f := enableIPForward(k.ops(), &faultyRecords{Store: st}); f != nil {
		t.Fatalf("finding: %v", f)
	}
	if k.writes != 1 || !k.value {
		t.Fatalf("writes = %d, value = %v; want one write of 1", k.writes, k.value)
	}
	if k.atWrite != (records{planned: "2026-01-02T03:04:06Z"}) {
		t.Errorf("at the write the database held %+v; want only the planned record", k.atWrite)
	}
	if got := readRecords(t, st); got != (records{confirmed: "2026-01-02T03:04:07Z"}) {
		t.Errorf("after the write the database holds %+v; want only the confirmed record", got)
	}
}

// TestIPForwardAlreadyOneWritesAndRecordsNothing checks that a value of 1 is left alone, and a
// planned record a previous start left behind is kept as evidence that it may have written.
func TestIPForwardAlreadyOneWritesAndRecordsNothing(t *testing.T) {
	st := newRecordsDB(t)
	k := &fakeIPForward{t: t, st: st, value: true}
	if f := enableIPForward(k.ops(), &faultyRecords{Store: st}); f != nil || k.writes != 0 {
		t.Fatalf("finding %v, writes %d; want neither", f, k.writes)
	}
	if got := readRecords(t, st); got != (records{}) {
		t.Errorf("database holds %+v; want no record", got)
	}
	if err := st.SetMeta(store.MetaIPForwardWriteStartedAt, []byte("earlier")); err != nil {
		t.Fatal(err)
	}
	if f := enableIPForward(k.ops(), &faultyRecords{Store: st}); f != nil || k.writes != 0 {
		t.Fatalf("finding %v, writes %d; want neither", f, k.writes)
	}
	if got := readRecords(t, st); got != (records{planned: "earlier"}) {
		t.Errorf("database holds %+v; want the earlier planned record kept", got)
	}
}

// TestIPForwardUnreadableWritesWithoutRecords checks that an unreadable value is set to 1 but not
// recorded, since wgft cannot say it was 0.
func TestIPForwardUnreadableWritesWithoutRecords(t *testing.T) {
	st := newRecordsDB(t)
	k := &fakeIPForward{t: t, st: st, readErr: errInjected}
	if f := enableIPForward(k.ops(), &faultyRecords{Store: st}); f != nil {
		t.Fatalf("finding: %v", f)
	}
	if k.writes != 1 {
		t.Errorf("writes = %d, want 1", k.writes)
	}
	if got := readRecords(t, st); got != (records{}) {
		t.Errorf("database holds %+v; want no record", got)
	}
}

// TestIPForwardUnreadableAndUnwritableDoesNotClaimZero checks that a value that could not be read
// and could not be set is not reported as 0: the finding names both errors, says the value is
// unknown, and still points at the commands that read and set it.
func TestIPForwardUnreadableAndUnwritableDoesNotClaimZero(t *testing.T) {
	st := newRecordsDB(t)
	readErr, writeErr := errors.New("read boom"), errors.New("write boom")
	k := &fakeIPForward{t: t, st: st, readErr: readErr, writeErr: writeErr}
	f := enableIPForward(k.ops(), &faultyRecords{Store: st})
	if f == nil {
		t.Fatal("no finding")
	}
	s := f.String()
	if strings.Contains(s, "is 0") {
		t.Errorf("finding claims the value is 0: %q", s)
	}
	for _, want := range []string{"could not be read: read boom", "setting it to 1 failed too: write boom", "unknown", "sysctl net.ipv4.ip_forward\n", "sysctl -w net.ipv4.ip_forward=1"} {
		if !strings.Contains(s, want) {
			t.Errorf("finding lacks %q: %q", want, s)
		}
	}
	if got := readRecords(t, st); got != (records{}) {
		t.Errorf("database holds %+v; want no record", got)
	}
}

// TestIPForwardZeroAndUnwritableKeepsTheWriteFailureFinding checks that a value read as 0 that
// cannot be set keeps the wording that says it is 0.
func TestIPForwardZeroAndUnwritableKeepsTheWriteFailureFinding(t *testing.T) {
	st := newRecordsDB(t)
	k := &fakeIPForward{t: t, st: st, writeErr: errors.New("write boom")}
	f := enableIPForward(k.ops(), &faultyRecords{Store: st})
	want := "net.ipv4.ip_forward: is 0 and could not be set to 1: write boom; kernel-mode forwarding will not work until this is set\n    sysctl -w net.ipv4.ip_forward=1"
	if f == nil || f.String() != want {
		t.Errorf("finding = %v; want %q", f, want)
	}
}

// TestIPForwardWritesEvenWhenThePlannedRecordFails checks that a failed planned record is warned
// about before the write and does not stop the write (design.md 11b 節). When the confirmed record
// is then saved, nothing is missing and no finding is raised.
func TestIPForwardWritesEvenWhenThePlannedRecordFails(t *testing.T) {
	st := newRecordsDB(t)
	logs := captureStdLog(t)
	k := &fakeIPForward{t: t, st: st}
	var warnedBeforeWrite bool
	o := k.ops()
	write := o.write
	o.write = func() error {
		warnedBeforeWrite = strings.Contains(logs.String(), "is about to set it to 1 failed")
		return write()
	}
	if f := enableIPForward(o, &faultyRecords{Store: st, failPlanned: true}); f != nil {
		t.Fatalf("finding: %v", f)
	}
	if k.writes != 1 || !k.value {
		t.Fatalf("writes = %d, value = %v; want the value written", k.writes, k.value)
	}
	if !warnedBeforeWrite {
		t.Errorf("no warning before the write; log:\n%s", logs)
	}
	if got := readRecords(t, st); got.confirmed == "" || got.planned != "" {
		t.Errorf("database holds %+v; want only the confirmed record", got)
	}
}

// TestIPForwardRaisesAFindingWhenNeitherRecordIsSaved checks the only case that leaves no record of
// the change: the planned and the confirmed record both fail. The value is still written, and the
// startup finding says teardown may not know.
func TestIPForwardRaisesAFindingWhenNeitherRecordIsSaved(t *testing.T) {
	st := newRecordsDB(t)
	k := &fakeIPForward{t: t, st: st}
	f := enableIPForward(k.ops(), &faultyRecords{Store: st, failPlanned: true, failConfirm: true})
	if k.writes != 1 || !k.value {
		t.Fatalf("writes = %d, value = %v; want the value written", k.writes, k.value)
	}
	if f == nil {
		t.Fatal("no finding")
	}
	if s := f.String(); !strings.Contains(s, "net.ipv4.ip_forward: wgft set it from 0 to 1 at") || !strings.Contains(s, "may not know that wgft changed it") {
		t.Errorf("finding = %q", s)
	}
	if got := readRecords(t, st); got != (records{}) {
		t.Errorf("database holds %+v; want no record", got)
	}
}

// TestIPForwardWriteFailureRemovesThePlannedRecord checks that a failed write leaves the value 0,
// returns the existing finding, and removes the planned record; when the removal fails too, the
// planned record stays and a warning is logged.
func TestIPForwardWriteFailureRemovesThePlannedRecord(t *testing.T) {
	for _, failDelete := range []bool{false, true} {
		st := newRecordsDB(t)
		logs := captureStdLog(t)
		k := &fakeIPForward{t: t, st: st, writeErr: errInjected}
		f := enableIPForward(k.ops(), &faultyRecords{Store: st, failDelete: failDelete})
		if f == nil || !strings.Contains(f.String(), "is 0 and could not be set to 1") {
			t.Errorf("failDelete %v: finding = %v; want the write failure", failDelete, f)
		}
		if k.atWrite.planned == "" {
			t.Errorf("failDelete %v: no planned record at the write", failDelete)
		}
		got := readRecords(t, st)
		if got.confirmed != "" {
			t.Errorf("failDelete %v: confirmed record %q after a failed write", failDelete, got.confirmed)
		}
		if failDelete {
			if got.planned == "" || !strings.Contains(logs.String(), "removing the record that wgft was about to set") {
				t.Errorf("failDelete: database %+v, log %q; want the planned record kept and a warning", got, logs)
			}
		} else if got.planned != "" {
			t.Errorf("planned record %q left after a failed write", got.planned)
		}
	}
}

// TestIPForwardCrashAfterTheWriteLeavesThePlannedRecord checks the window the planned record
// exists for: the process stops right after writing 1 and before the confirmed record. The
// planned record stays and no confirmed record is claimed.
func TestIPForwardCrashAfterTheWriteLeavesThePlannedRecord(t *testing.T) {
	st := newRecordsDB(t)
	k := &fakeIPForward{t: t, st: st, crash: true}
	func() {
		defer func() {
			if r := recover(); r != errCrash {
				t.Fatalf("recovered %v, want the simulated crash", r)
			}
		}()
		enableIPForward(k.ops(), &faultyRecords{Store: st})
	}()
	if !k.value {
		t.Fatal("the value was not written before the crash")
	}
	if got := readRecords(t, st); got.planned == "" || got.confirmed != "" {
		t.Errorf("database holds %+v; want only the planned record", got)
	}
}

// TestIPForwardConfirmFailureLeavesThePlannedRecord checks that a failed confirm transaction keeps
// the planned record, adds no confirmed record, and only warns.
func TestIPForwardConfirmFailureLeavesThePlannedRecord(t *testing.T) {
	st := newRecordsDB(t)
	logs := captureStdLog(t)
	k := &fakeIPForward{t: t, st: st}
	if f := enableIPForward(k.ops(), &faultyRecords{Store: st, failConfirm: true}); f != nil {
		t.Fatalf("finding: %v", f)
	}
	if got := readRecords(t, st); got.planned == "" || got.confirmed != "" {
		t.Errorf("database holds %+v; want only the planned record", got)
	}
	if !strings.Contains(logs.String(), "may have changed it") {
		t.Errorf("no warning; log:\n%s", logs)
	}
}

// TestServerInfoReportsOnlyTheConfirmedIPForwardRecord checks that ip_forward_set_at keeps its
// meaning (design.md 7a.11 節): the planned record is not exposed in the admin API.
func TestServerInfoReportsOnlyTheConfirmedIPForwardRecord(t *testing.T) {
	st := newRecordsDB(t)
	if err := st.SetMeta(store.MetaIPForwardWriteStartedAt, []byte("2026-01-02T03:04:05Z")); err != nil {
		t.Fatal(err)
	}
	info, err := (&Daemon{st: st}).ServerInfo()
	if err != nil {
		t.Fatal(err)
	}
	if info.IPForwardSetAt != "" {
		t.Errorf("IPForwardSetAt = %q with only the planned record; want empty", info.IPForwardSetAt)
	}
	if err := st.SetMetaAndDelete(store.MetaIPForwardSetAt, []byte("2026-01-02T03:04:06Z"), store.MetaIPForwardWriteStartedAt); err != nil {
		t.Fatal(err)
	}
	if info, err = (&Daemon{st: st}).ServerInfo(); err != nil || info.IPForwardSetAt != "2026-01-02T03:04:06Z" {
		t.Errorf("IPForwardSetAt = %q, %v; want the confirmed record", info.IPForwardSetAt, err)
	}
}
