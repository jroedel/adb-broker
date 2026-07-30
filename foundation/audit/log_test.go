package audit

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

// installLog creates an empty log file the way the installer would, so no test
// ever depends on Open being able to create one — it deliberately cannot.
func installLog(t *testing.T) string {
	t.Helper()

	path := filepath.Join(t.TempDir(), "audit.log")

	f, err := os.Create(path)
	if err != nil {
		t.Fatalf("create log: %v", err)
	}

	if err := f.Close(); err != nil {
		t.Fatalf("close log: %v", err)
	}

	return path
}

// sampleRecord builds a plausible record, with Seq, Prev and Hash filled in
// with nonsense so tests can prove Append ignores them.
func sampleRecord(op string, uid int) Record {
	return Record{
		Seq:            999,
		TS:             time.Date(2026, 7, 30, 16, 52, 3, 114_000_000, time.UTC),
		Op:             op,
		CallerUID:      uid,
		ClientAsserted: "/sdcard/Download/x.txt",
		Serial:         "R58MA0ABCDE",
		PathB64:        "L3NkY2FyZC9Eb3dubG9hZC94LnR4dA==",
		Decision:       "allow",
		Result:         "ok",
		Bytes:          4096,
		SHA256:         "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08",
		Prev:           strings.Repeat("a", 64),
		Hash:           strings.Repeat("b", 64),
	}
}

func appendSamples(t *testing.T, l *Log, n int) []Record {
	t.Helper()

	out := make([]Record, 0, n)
	for i := range n {
		r, err := l.Append(sampleRecord("push", 1000+i))
		if err != nil {
			t.Fatalf("Append %d: %v", i+1, err)
		}
		out = append(out, r)
	}

	return out
}

func readLines(t *testing.T, path string) []string {
	t.Helper()

	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read log: %v", err)
	}

	return strings.Split(strings.TrimSuffix(string(b), "\n"), "\n")
}

func writeLines(t *testing.T, path string, lines []string) {
	t.Helper()

	if err := os.WriteFile(path, []byte(strings.Join(lines, "\n")+"\n"), 0o600); err != nil {
		t.Fatalf("write log: %v", err)
	}
}

// TestAppendFirstRecordPrevIsZeroHash pins hash_0 = 32 zero bytes.
func TestAppendFirstRecordPrevIsZeroHash(t *testing.T) {
	l, err := Open(installLog(t))
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer l.Close()

	if got := l.Head(); got != [32]byte{} {
		t.Errorf("empty log head = %x, want 32 zero bytes", got)
	}

	r, err := l.Append(sampleRecord("push", 1000))
	if err != nil {
		t.Fatalf("Append: %v", err)
	}

	if want := strings.Repeat("0", 64); r.Prev != want {
		t.Errorf("first record Prev = %q, want 64 hex zeros", r.Prev)
	}
}

// TestAppendAssignsSequenceAndChain covers the rule that Seq, Prev and Hash are
// the log's business: whatever the caller put there is discarded.
func TestAppendAssignsSequenceAndChain(t *testing.T) {
	l, err := Open(installLog(t))
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer l.Close()

	recs := appendSamples(t, l, 3)

	for i, r := range recs {
		if want := uint64(i + 1); r.Seq != want {
			t.Errorf("record %d: Seq = %d, want %d", i, r.Seq, want)
		}

		if r.Hash == strings.Repeat("b", 64) {
			t.Errorf("record %d: caller-supplied Hash survived", i)
		}

		switch i {
		case 0:
			if r.Prev != strings.Repeat("0", 64) {
				t.Errorf("record 0: Prev = %q, want 64 zeros", r.Prev)
			}
		default:
			if r.Prev != recs[i-1].Hash {
				t.Errorf("record %d: Prev = %q, want previous Hash %q", i, r.Prev, recs[i-1].Hash)
			}
		}
	}

	if got := l.Seq(); got != 3 {
		t.Errorf("Seq() = %d, want 3", got)
	}
}

// TestAppendRoundTripsThroughFile checks the on-disk line format both ways: what
// Append stored is what TailRecord and VerifyChain read back.
func TestAppendRoundTripsThroughFile(t *testing.T) {
	path := installLog(t)

	l, err := Open(path)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}

	recs := appendSamples(t, l, 3)

	if err := l.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	tail, err := TailRecord(path)
	if err != nil {
		t.Fatalf("TailRecord: %v", err)
	}

	if !tail.TS.Equal(recs[2].TS) {
		t.Errorf("tail TS = %v, want %v", tail.TS, recs[2].TS)
	}

	tail.TS, recs[2].TS = time.Time{}, time.Time{}
	if tail != recs[2] {
		t.Errorf("tail round trip changed the record:\n got: %+v\nwant: %+v", tail, recs[2])
	}

	f, err := os.Open(path)
	if err != nil {
		t.Fatalf("open for verify: %v", err)
	}
	defer f.Close()

	sum, err := VerifyChain(f)
	if err != nil {
		t.Fatalf("VerifyChain: %v", err)
	}

	if sum.Records != 3 || sum.LastSeq != 3 || sum.LastHash != recs[2].Hash {
		t.Errorf("Summary = %+v, want 3 records, LastSeq 3, LastHash %s", sum, recs[2].Hash)
	}
}

// TestVerifyChainDetectsEdit is the property the chain exists for: altering a
// record's contents is caught, and named by sequence number.
func TestVerifyChainDetectsEdit(t *testing.T) {
	path := installLog(t)

	l, err := Open(path)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}

	appendSamples(t, l, 3)
	l.Close()

	lines := readLines(t, path)
	edited := strings.Replace(lines[1], `"caller_uid":1001`, `"caller_uid":1002`, 1)
	if edited == lines[1] {
		t.Fatalf("test setup: nothing edited in %s", lines[1])
	}
	lines[1] = edited

	sum, err := VerifyChain(strings.NewReader(strings.Join(lines, "\n") + "\n"))

	var ce *ChainError
	if !errors.As(err, &ce) {
		t.Fatalf("VerifyChain error = %v, want *ChainError", err)
	}

	if ce.Seq != 2 {
		t.Errorf("divergence reported at seq %d, want 2", ce.Seq)
	}

	if sum.Records != 1 {
		t.Errorf("Summary.Records = %d, want 1 record verified before the divergence", sum.Records)
	}
}

// TestVerifyChainDetectsReorder covers the other half: each record is bound to
// its predecessor, so records cannot be shuffled.
func TestVerifyChainDetectsReorder(t *testing.T) {
	path := installLog(t)

	l, err := Open(path)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}

	appendSamples(t, l, 3)
	l.Close()

	lines := readLines(t, path)
	lines[1], lines[2] = lines[2], lines[1]

	_, err = VerifyChain(strings.NewReader(strings.Join(lines, "\n") + "\n"))

	var ce *ChainError
	if !errors.As(err, &ce) {
		t.Fatalf("VerifyChain error = %v, want *ChainError", err)
	}

	if ce.Line != 2 {
		t.Errorf("divergence reported at line %d, want 2", ce.Line)
	}
}

// TestVerifyChainDetectsMiddleDeletion covers removing a record from the middle,
// which — unlike removing one from the end — breaks the linkage.
func TestVerifyChainDetectsMiddleDeletion(t *testing.T) {
	path := installLog(t)

	l, err := Open(path)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}

	appendSamples(t, l, 3)
	l.Close()

	lines := readLines(t, path)
	lines = append(lines[:1], lines[2])

	if _, err := VerifyChain(strings.NewReader(strings.Join(lines, "\n") + "\n")); err == nil {
		t.Fatal("VerifyChain accepted a chain with a record removed from the middle")
	}
}

// TestVerifyChainCannotDetectTailTruncation DOCUMENTS A LIMITATION. It is not a
// bug report and the behaviour must not be "fixed" here.
//
// Removing records from the END of the file leaves a shorter chain that is
// internally perfect: every remaining hash still covers its predecessor, so
// VerifyChain returns a clean Summary — just with a lower LastSeq. Nothing
// inside the file can reveal this, because an adversary who can truncate the
// file can equally recompute a whole new valid chain over what remains.
//
// The control for tail truncation is the journald anchor: WriteAnchor publishes
// (seq, hash) to a log the broker's own uid cannot rewrite, and the verify
// subcommand compares the newest anchor's seq against the log's LastSeq. A
// truncated log is detected by that comparison and by nothing else.
//
// This test exists so that no future reader credits the hash chain with a
// property it does not have. A control believed to be stronger than it is, is
// worse than no control at all.
func TestVerifyChainCannotDetectTailTruncation(t *testing.T) {
	path := installLog(t)

	l, err := Open(path)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}

	recs := appendSamples(t, l, 3)
	l.Close()

	lines := readLines(t, path)
	truncated := strings.Join(lines[:2], "\n") + "\n"

	sum, err := VerifyChain(strings.NewReader(truncated))
	if err != nil {
		t.Fatalf("VerifyChain on a truncated log returned %v; the limitation this test documents is that it returns NO error", err)
	}

	if sum.Records != 2 || sum.LastSeq != 2 || sum.LastHash != recs[1].Hash {
		t.Errorf("Summary = %+v, want a clean 2-record summary", sum)
	}

	// And Open is equally blind, for the same reason.
	writeLines(t, path, lines[:2])

	l2, err := Open(path)
	if err != nil {
		t.Fatalf("Open on a truncated log returned %v; it cannot detect truncation either", err)
	}
	defer l2.Close()

	if l2.Seq() != 2 {
		t.Errorf("reopened Seq() = %d, want 2", l2.Seq())
	}
}

// TestVerifyChainRejectsUnknownMembers checks that data cannot be hidden in a
// line that still verifies. Unknown members are outside the hash, so they are
// refused rather than ignored.
func TestVerifyChainRejectsUnknownMembers(t *testing.T) {
	path := installLog(t)

	l, err := Open(path)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}

	appendSamples(t, l, 1)
	l.Close()

	lines := readLines(t, path)
	lines[0] = strings.TrimSuffix(lines[0], "}") + `,"smuggled":"payload"}`

	if _, err := VerifyChain(strings.NewReader(lines[0] + "\n")); err == nil {
		t.Fatal("VerifyChain accepted a record with an unknown member")
	}
}

func TestVerifyChainEmptyInput(t *testing.T) {
	sum, err := VerifyChain(strings.NewReader(""))
	if err != nil {
		t.Fatalf("VerifyChain: %v", err)
	}

	if sum != (Summary{}) {
		t.Errorf("Summary = %+v, want the zero Summary", sum)
	}
}

// TestOpenRejectsEditedTail is the check that runs before the broker does
// anything: a tail that does not hash to its stored value means the log has been
// tampered with, and the process must not proceed.
func TestOpenRejectsEditedTail(t *testing.T) {
	path := installLog(t)

	l, err := Open(path)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}

	appendSamples(t, l, 2)
	l.Close()

	lines := readLines(t, path)
	lines[1] = strings.Replace(lines[1], `"result":"ok"`, `"result":"XX"`, 1)
	writeLines(t, path, lines)

	if _, err := Open(path); !errors.Is(err, ErrAuditUnavailable) {
		t.Errorf("Open on an edited tail = %v, want ErrAuditUnavailable", err)
	}
}

// TestOpenMissingFileDoesNotCreateIt pins the O_CREATE decision: a broker that
// can bring its own audit log into existence can also replace the real one.
func TestOpenMissingFileDoesNotCreateIt(t *testing.T) {
	path := filepath.Join(t.TempDir(), "audit.log")

	if _, err := Open(path); !errors.Is(err, ErrAuditUnavailable) {
		t.Errorf("Open on a missing file = %v, want ErrAuditUnavailable", err)
	}

	if _, err := os.Stat(path); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("Open created %s; it must never create the audit log", path)
	}
}

func TestOpenReadOnlyFile(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("running as root: file permissions do not restrict the open")
	}

	path := filepath.Join(t.TempDir(), "audit.log")
	if err := os.WriteFile(path, nil, 0o444); err != nil {
		t.Fatalf("write log: %v", err)
	}

	if _, err := Open(path); !errors.Is(err, ErrAuditUnavailable) {
		t.Errorf("Open on a read-only file = %v, want ErrAuditUnavailable", err)
	}
}

func TestOpenDirectory(t *testing.T) {
	if _, err := Open(t.TempDir()); !errors.Is(err, ErrAuditUnavailable) {
		t.Errorf("Open on a directory = %v, want ErrAuditUnavailable", err)
	}
}

// TestOpenResumesChain checks that reopening picks the chain up where it was
// left, rather than starting over.
func TestOpenResumesChain(t *testing.T) {
	path := installLog(t)

	first, err := Open(path)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}

	recs := appendSamples(t, first, 2)
	first.Close()

	second, err := Open(path)
	if err != nil {
		t.Fatalf("reopen: %v", err)
	}
	defer second.Close()

	if got := second.Seq(); got != 2 {
		t.Errorf("resumed Seq() = %d, want 2", got)
	}

	third, err := second.Append(sampleRecord("pull", 1000))
	if err != nil {
		t.Fatalf("Append after reopen: %v", err)
	}

	if third.Seq != 3 {
		t.Errorf("Seq = %d, want 3", third.Seq)
	}

	if third.Prev != recs[1].Hash {
		t.Errorf("Prev = %q, want %q", third.Prev, recs[1].Hash)
	}

	f, err := os.Open(path)
	if err != nil {
		t.Fatalf("open for verify: %v", err)
	}
	defer f.Close()

	if sum, err := VerifyChain(f); err != nil || sum.LastSeq != 3 {
		t.Errorf("VerifyChain = %+v, %v; want a clean 3-record chain", sum, err)
	}
}

// TestTailRecordEmptyFile pins the fresh-install state: an empty log is a valid
// chain of length zero, so Open must accept it and Append must produce Seq 1.
func TestTailRecordEmptyFile(t *testing.T) {
	path := installLog(t)

	tail, err := TailRecord(path)
	if err != nil {
		t.Fatalf("TailRecord on an empty file: %v", err)
	}

	if tail != (Record{}) {
		t.Errorf("TailRecord = %+v, want the zero Record", tail)
	}

	l, err := Open(path)
	if err != nil {
		t.Fatalf("Open on an empty file: %v", err)
	}
	defer l.Close()

	r, err := l.Append(sampleRecord("push", 1000))
	if err != nil {
		t.Fatalf("Append: %v", err)
	}

	if r.Seq != 1 {
		t.Errorf("first Seq = %d, want 1", r.Seq)
	}
}

// TestTailRecordPartialFinalLine covers the residue of a crash mid-write: a
// truncated final line is an error rather than being quietly skipped, because
// skipping it would silently accept a shorter chain.
func TestTailRecordPartialFinalLine(t *testing.T) {
	path := installLog(t)

	l, err := Open(path)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}

	appendSamples(t, l, 2)
	l.Close()

	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read log: %v", err)
	}

	if err := os.WriteFile(path, b[:len(b)-20], 0o600); err != nil {
		t.Fatalf("write log: %v", err)
	}

	if _, err := TailRecord(path); err == nil {
		t.Fatal("TailRecord accepted a partially written final line")
	}

	if _, err := Open(path); !errors.Is(err, ErrAuditUnavailable) {
		t.Errorf("Open on a partial final line = %v, want ErrAuditUnavailable", err)
	}
}

// TestTailRecordGrowsWindow exercises the backwards read for a record larger
// than the initial tail window.
func TestTailRecordGrowsWindow(t *testing.T) {
	path := installLog(t)

	l, err := Open(path)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}

	appendSamples(t, l, 2)

	big := sampleRecord("push", 1000)
	big.ClientAsserted = strings.Repeat("x", 100<<10)

	want, err := l.Append(big)
	if err != nil {
		t.Fatalf("Append big: %v", err)
	}
	l.Close()

	tail, err := TailRecord(path)
	if err != nil {
		t.Fatalf("TailRecord: %v", err)
	}

	if tail.Hash != want.Hash || tail.ClientAsserted != want.ClientAsserted {
		t.Error("TailRecord did not read back the oversized final record")
	}
}

func TestCloseIsIdempotentAndAppendAfterCloseFails(t *testing.T) {
	l, err := Open(installLog(t))
	if err != nil {
		t.Fatalf("Open: %v", err)
	}

	if err := l.Close(); err != nil {
		t.Fatalf("first Close: %v", err)
	}

	if err := l.Close(); err != nil {
		t.Errorf("second Close: %v", err)
	}

	if _, err := l.Append(sampleRecord("push", 1000)); !errors.Is(err, ErrAuditUnavailable) {
		t.Errorf("Append after Close = %v, want ErrAuditUnavailable", err)
	}
}

// TestAppendConcurrent checks that concurrent callers produce one valid chain
// with no gaps, duplicates or interleaved lines.
func TestAppendConcurrent(t *testing.T) {
	path := installLog(t)

	l, err := Open(path)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}

	const n = 64

	var wg sync.WaitGroup
	for i := range n {
		wg.Go(func() {
			if _, err := l.Append(sampleRecord("push", 1000+i)); err != nil {
				t.Errorf("Append: %v", err)
			}
		})
	}
	wg.Wait()
	l.Close()

	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read log: %v", err)
	}

	sum, err := VerifyChain(bytes.NewReader(b))
	if err != nil {
		t.Fatalf("VerifyChain: %v", err)
	}

	if sum.Records != n || sum.LastSeq != n {
		t.Errorf("Summary = %+v, want %d records", sum, n)
	}
}
