package audit

import (
	"bufio"
	"bytes"
	"errors"
	"fmt"
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

// TestTailRecordMissingFinalNewline covers the single byte that separates a
// healthy tail from a log that poisons every record appended after it.
//
// A final line that is complete, valid JSON but is missing its own trailing
// newline used to be accepted as a healthy tail, hash and all: TailRecord
// trimmed newlines off the window it read and only asked whether what survived
// decoded, never whether the file had actually ended in one. Open therefore
// succeeded, the fail-closed check did not engage, the broker ran normally, and
// the next Append — which writes no leading separator — was concatenated onto
// that line. VerifyChain then failed at that line with "trailing data after
// record", making it and every record after it unreachable, because
// bufio.Scanner splits on '\n' and there was none between them.
//
// So both the positive and the negative case are asserted here: the check has to
// reject a tail that lost its last byte, and it must not reject one that did not.
func TestTailRecordMissingFinalNewline(t *testing.T) {
	path := installLog(t)

	l, err := Open(path)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}

	recs := appendSamples(t, l, 2)

	if err := l.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	// The positive case, on the untouched file, so the fix cannot be "reject
	// every tail".
	tail, err := TailRecord(path)
	if err != nil {
		t.Fatalf("TailRecord on a complete log: %v", err)
	}

	if tail.Hash != recs[1].Hash {
		t.Errorf("TailRecord Hash = %q, want the second record's %q", tail.Hash, recs[1].Hash)
	}

	reopened, err := Open(path)
	if err != nil {
		t.Fatalf("Open on a complete log: %v", err)
	}

	if got := reopened.Seq(); got != 2 {
		t.Errorf("reopened Seq() = %d, want 2", got)
	}

	if err := reopened.Close(); err != nil {
		t.Fatalf("Close reopened: %v", err)
	}

	// Now drop exactly one byte: the newline that terminates record 2.
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read log: %v", err)
	}

	if b[len(b)-1] != '\n' {
		t.Fatalf("test setup: the log does not end in a newline, so there is nothing to drop")
	}

	if err := os.WriteFile(path, b[:len(b)-1], 0o600); err != nil {
		t.Fatalf("write log: %v", err)
	}

	if _, err := TailRecord(path); err == nil {
		t.Error("TailRecord accepted a final line missing its trailing newline; the next Append would be concatenated onto it")
	}

	// And Open must fail closed on it, wrapping ErrAuditUnavailable, which is
	// the error callers match to decide not to proceed.
	if _, err := Open(path); !errors.Is(err, ErrAuditUnavailable) {
		t.Errorf("Open on a log whose final line lost its newline = %v, want ErrAuditUnavailable", err)
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

// TestLogPathNamesTheOpenFile covers Path, which exists so a caller publishing
// an anchor can say which log the anchor describes without having to carry the
// path alongside the *Log separately. A Path that disagreed with what Open was
// actually given would make an anchor's LogPath a guess dressed up as a fact.
func TestLogPathNamesTheOpenFile(t *testing.T) {
	path := installLog(t)

	l, err := Open(path)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer l.Close()

	if got := l.Path(); got != path {
		t.Errorf("Path() = %q, want %q", got, path)
	}
}

// TestChainErrorMessageNamesTheOffendingRecord covers both of Error's shapes: a
// record that decoded far enough to have a sequence number is named by it, and
// one that did not falls back to the line number. Either way the underlying
// cause's own text must still be in there — a message that named only the
// coordinates and not the reason would send an operator straight back to the
// error value to find out what actually happened.
func TestChainErrorMessageNamesTheOffendingRecord(t *testing.T) {
	cause := errors.New("hash mismatch: stored a, recomputed b")

	tests := []struct {
		name string
		ce   *ChainError
		want []string // substrings the message must contain
	}{
		{
			name: "a decoded record is named by sequence number",
			ce:   &ChainError{Line: 7, Seq: 3, Err: cause},
			want: []string{"seq 3", "line 7", cause.Error()},
		},
		{
			name: "an undecodable record falls back to the line number",
			ce:   &ChainError{Line: 4, Seq: 0, Err: cause},
			want: []string{"line 4", cause.Error()},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := tc.ce.Error()

			for _, want := range tc.want {
				if !strings.Contains(got, want) {
					t.Errorf("Error() = %q, want it to contain %q", got, want)
				}
			}

			// The fallback case must not name a sequence number it does not
			// have: "seq 0" would read as a real, decoded record rather than
			// as "this one could not be identified at all".
			if tc.ce.Seq == 0 && strings.Contains(got, "seq") {
				t.Errorf("Error() = %q, names a sequence number for a record that has none", got)
			}
		})
	}
}

// TestChainErrorUnwrapSurvivesErrorsIs is the property that matters most about
// ChainError: an Unwrap that dropped the cause would make errors.Is silently
// false at exactly the moment an operator is using it to diagnose a tampered
// log. VerifyChain's own tests (TestVerifyChainDetectsEdit and friends) extract
// the *ChainError with errors.As but never chase the cause any further, so this
// is the one place that checks the chain does not end there.
func TestChainErrorUnwrapSurvivesErrorsIs(t *testing.T) {
	cause := errors.New("prev does not match the running chain head")
	ce := &ChainError{Line: 2, Seq: 1, Err: cause}

	if !errors.Is(ce, cause) {
		t.Fatal("errors.Is(ChainError, cause) = false, want true: Unwrap must expose the wrapped failure")
	}

	// Wrapped one level further, the way VerifyChain's caller sees it (fmt.Errorf
	// around whatever VerifyChain returned), the cause must still be reachable.
	wrapped := fmt.Errorf("verify: %w", ce)

	if !errors.Is(wrapped, cause) {
		t.Error("errors.Is on a further-wrapped ChainError = false, want true")
	}

	var got *ChainError
	if !errors.As(wrapped, &got) || got != ce {
		t.Error("errors.As did not recover the original *ChainError through the extra wrapping")
	}
}

// TestAppendOutOfRangeTimestampIsAuditUnavailable covers the two Append failure
// modes that used to return a bare error: hashing and encoding, both of which
// fail only when Canonical cannot render TS in its fixed-width form (a year
// outside 0000-9999). The package doc tells callers to fail closed on
// ErrAuditUnavailable; a caller written against that contract would not have
// recognised these two as the audit-unavailable condition, even though the
// operation was just as unrecorded as after a failed write.
func TestAppendOutOfRangeTimestampIsAuditUnavailable(t *testing.T) {
	path := installLog(t)

	l, err := Open(path)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer l.Close()

	r := sampleRecord("push", 1000)
	r.TS = time.Date(10000, 1, 1, 0, 0, 0, 0, time.UTC)

	if _, err := l.Append(r); !errors.Is(err, ErrAuditUnavailable) {
		t.Errorf("Append with an unrepresentable timestamp = %v, want ErrAuditUnavailable", err)
	}

	// Nothing may have been written, and the chain must not have moved.
	if got := l.Seq(); got != 0 {
		t.Errorf("Seq() = %d after a rejected Append, want 0", got)
	}

	if b, err := os.ReadFile(path); err != nil || len(b) != 0 {
		t.Errorf("log holds %d bytes (err %v) after a rejected Append, want it untouched", len(b), err)
	}
}

// TestAppendSyncFailureIsAuditUnavailable is the point of syncing at all: a
// record the kernel has not committed must not be reported to the caller as
// recorded. The write below succeeds and the fsync fails, which is precisely the
// case that would otherwise be indistinguishable from a durable append.
//
// The Log is constructed directly rather than through Open because Open
// deliberately insists on a regular file, and a regular file's fsync cannot be
// made to fail on demand. A pipe's can: Linux fails fsync(2) with EINVAL on a
// descriptor that does not support synchronisation, while the write itself
// succeeds. This is an in-package test, so that seam costs the production API
// nothing — no exported hook and no injectable syncer were added to make it
// testable.
func TestAppendSyncFailureIsAuditUnavailable(t *testing.T) {
	pr, pw, err := os.Pipe()
	if err != nil {
		t.Fatalf("pipe: %v", err)
	}

	t.Cleanup(func() {
		pr.Close()
		pw.Close()
	})

	l := &Log{f: pw, path: "pipe"}

	_, err = l.Append(sampleRecord("push", 1000))
	if !errors.Is(err, ErrAuditUnavailable) {
		t.Fatalf("Append with a failing sync = %v, want ErrAuditUnavailable", err)
	}

	// Naming the sync matters: if the error came from the write, this test would
	// be proving nothing about durability.
	if !strings.Contains(err.Error(), "sync") {
		t.Errorf("Append error = %v, want it to name the failing sync", err)
	}

	// The line really was written — the failure is durability, not the write.
	line, err := bufio.NewReader(pr).ReadBytes('\n')
	if err != nil {
		t.Fatalf("read what Append wrote: %v", err)
	}

	if _, err := decodeLine(line[:len(line)-1]); err != nil {
		t.Errorf("Append wrote %q, which does not decode: %v", line, err)
	}

	// The chain state advances with the write, not with the sync, so a later
	// Append continues the chain instead of reissuing a sequence number that may
	// already be in the file.
	if got := l.Seq(); got != 1 {
		t.Errorf("Seq() = %d after a written-but-unsynced record, want 1", got)
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
