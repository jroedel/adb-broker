package broker

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/jroedel/adb-broker/business/domain/device/devicebus"
	"github.com/jroedel/adb-broker/business/types/errcode"
	"github.com/jroedel/adb-broker/foundation/audit"
)

// First-run creation of the audit log.
//
// Until 2026-08-01 only a root-run installer could bring a log into existence, and a host
// where it had not run failed every invocation with audit_unavailable. The broker creates its
// own log now, which removes that failure and takes on a new obligation in exchange: a chain
// that appears from nothing must be distinguishable from one that was deleted and started
// over. Nothing in the file can tell those apart — both recompute perfectly — so the seq-0
// anchor is the whole of the difference, and these tests are mostly about it.

// runWithFirstRunLog drives Main against a path that may not exist yet, through the same
// open-or-create seam the release build uses.
//
// It is deliberately NOT runWithLog, which opens without creating because its callers hand out
// paths that must fail. Both exist because the distinction between them is the behaviour under
// test here.
func runWithFirstRunLog(t *testing.T, logPath string, store *fakeStore, args ...string) result {
	t.Helper()

	swap(t, &openAuditLog, func() (*audit.Log, bool, error) { return openOrCreateLogAt(logPath) })

	if store != nil {
		swap(t, &newStorer, func(brokerVersion string) devicebus.Storer {
			store.brokerVersion = brokerVersion

			return store
		})
	}

	var stdout, stderr bytes.Buffer

	exit := Main(args, &stdout, &stderr)

	return result{exit: exit, stdout: stdout.String(), stderr: stderr.String()}
}

func TestAFirstRunCreatesTheAuditLogAndAnchorsTheEmptyChain(t *testing.T) {
	// Nested and absent: a host on which nothing has ever set this account up.
	logPath := filepath.Join(t.TempDir(), ".local", "state", "adb-broker", "audit.log")
	published := captureAnchors(t)

	got := runWithFirstRunLog(t, logPath, newFakeStore(), "probe")

	if got.exit != 0 {
		t.Fatalf("exit = %d on a first run, want 0; stderr %q", got.exit, got.stderr)
	}

	if _, err := os.Stat(logPath); err != nil {
		t.Fatalf("the first run did not create the audit log: %v", err)
	}

	// Two anchors: the empty chain at creation, then the probe record. The first is the one
	// that matters — it is published before any device is contacted, so it survives a run
	// that goes on to fail, and it is the only evidence a recreated chain leaves when
	// nothing is ever appended to it.
	if len(*published) != 2 {
		t.Fatalf("published %d anchors, want 2 (the empty chain, then the probe record): %+v", len(*published), *published)
	}

	created := (*published)[0]

	if created.seq != 0 {
		t.Errorf("the creation anchor is at seq %d, want 0", created.seq)
	}

	if created.hash != emptyChainHead {
		t.Errorf("the creation anchor's hash = %s, want the empty-chain head %s", created.hash, emptyChainHead)
	}

	if created.log != logPath {
		t.Errorf("the creation anchor names %s, want %s", created.log, logPath)
	}

	if next := (*published)[1]; next.seq != 1 {
		t.Errorf("the second anchor is at seq %d, want 1", next.seq)
	}
}

func TestAnExistingLogIsNotAnchoredAsIfItWereNew(t *testing.T) {
	// The counterpart to the test above, and the reason the seq-0 anchor means anything: if
	// every run published one, it would say nothing about a chain having been reset.
	logPath := newAuditLog(t)
	published := captureAnchors(t)

	got := runWithFirstRunLog(t, logPath, newFakeStore(), "probe")

	if got.exit != 0 {
		t.Fatalf("exit = %d, want 0; stderr %q", got.exit, got.stderr)
	}

	if len(*published) != 1 {
		t.Fatalf("published %d anchors against an existing log, want 1 for the probe record: %+v", len(*published), *published)
	}

	if seq := (*published)[0].seq; seq != 1 {
		t.Errorf("anchored at seq %d, want 1; an existing log must not be anchored as a new chain", seq)
	}
}

func TestALogThatExistsAndCannotBeOpenedIsNeverReplacedByAnEmptyOne(t *testing.T) {
	// Creation is reached only when the log is ABSENT. Any other failure to open is fatal,
	// because answering "this log will not open" by starting a fresh one would destroy the
	// history it failed to open — silently, and while reporting success.
	dir := t.TempDir()
	logPath := filepath.Join(dir, "audit.log")

	if err := os.Mkdir(logPath, 0o700); err != nil {
		t.Fatalf("plant a directory where the log belongs: %v", err)
	}

	store := newFakeStore()

	got := runWithFirstRunLog(t, logPath, store, "probe")

	if got.exit == 0 {
		t.Error("exit = 0 with an unopenable audit log, want non-zero")
	}

	if store.touched {
		t.Error("reached the transport with no usable audit log")
	}

	if res := decode(t, lines(t, got.stdout)[0]); res["code"] != errcode.CodeAuditUnavailable.String() {
		t.Errorf("code = %v, want audit_unavailable", res["code"])
	}

	fi, err := os.Stat(logPath)
	if err != nil {
		t.Fatalf("stat what was at the log's path: %v", err)
	}

	if !fi.IsDir() {
		t.Error("the broker replaced what it could not open; an existing log must never be overwritten")
	}
}

func TestADeletedLogIsCaughtByAnAnchorThatOutlivedIt(t *testing.T) {
	// The attack the retreat opened up, and the control that answers it. The log is now an
	// ordinary file owned by the account that writes it, so deleting it costs nothing and
	// the recreated chain verifies perfectly on its own. What does not go away is the
	// journal: anchors from the deleted chain still claim sequence numbers the new file
	// cannot account for.
	logPath, seq, head := chainState(t, 4)

	if seq != 4 {
		t.Fatalf("seeded chain is at seq %d, want 4", seq)
	}

	// Anchors that were published while the old chain existed. These are what an adversary
	// cannot retract: journal entries cannot be removed.
	survivingAnchors := anchorLine(t, os.Geteuid(), thisExe(t), logPath, seq, head)

	if err := os.Remove(logPath); err != nil {
		t.Fatalf("delete the audit log: %v", err)
	}

	// The next run recreates it and anchors the empty chain. A fake store, so this test
	// never reaches a real adb server on the host running it.
	published := captureAnchors(t)

	if got := runWithFirstRunLog(t, logPath, newFakeStore(), "probe"); got.exit != 0 {
		t.Fatalf("the run after the deletion exited %d, want 0; stderr %q", got.exit, got.stderr)
	}

	if len(*published) == 0 || (*published)[0].seq != 0 {
		t.Fatalf("the recreated log was not anchored at seq 0: %+v", *published)
	}

	// verify against the anchors that outlived the deletion.
	got := runVerifyWith(t, logPath, survivingAnchors)

	if got.exit == 0 {
		t.Error("verify exited 0 over a deleted chain, want non-zero")
	}

	if !strings.Contains(got.stdout+got.stderr, "truncated") {
		t.Errorf("verify did not report the deletion as a truncated tail:\nstdout %s\nstderr %s", got.stdout, got.stderr)
	}
}

func TestTwoBrokersRacingToCreateOneLogEndUpOnTheSameChain(t *testing.T) {
	// Create uses O_EXCL, so the loser of the race gets os.ErrExist rather than truncating
	// the winner's log. It must join that chain instead of failing: two brokers starting at
	// once on a first run is ordinary, not a fault.
	logPath := filepath.Join(t.TempDir(), "audit.log")

	first, created, err := openOrCreateLogAt(logPath)
	if err != nil {
		t.Fatalf("the first open-or-create failed: %v", err)
	}
	defer func() { _ = first.Close() }()

	if !created {
		t.Error("the first open-or-create reported that it created nothing")
	}

	second, created, err := openOrCreateLogAt(logPath)
	if err != nil {
		t.Fatalf("the second open-or-create failed: %v", err)
	}
	defer func() { _ = second.Close() }()

	if created {
		t.Error("the second open-or-create reported creating a log that already existed")
	}

	if second.Path() != logPath {
		t.Errorf("the second handle is on %s, want %s", second.Path(), logPath)
	}
}

func TestCreationFailingToAnchorDoesNotFailTheRunButIsReported(t *testing.T) {
	// The same rule the audit extension follows: an anchor that cannot be published must
	// not fail an operation that was recorded, and must not be silent either. A permanently
	// broken and quiet anchor path is the defect the first install shipped.
	logPath := filepath.Join(t.TempDir(), "audit.log")

	swap(t, &publishAnchor, func(*audit.Log) error { return errors.New("the journal socket is gone") })

	got := runWithFirstRunLog(t, logPath, newFakeStore(), "probe")

	if got.exit != 0 {
		t.Errorf("exit = %d when the creation anchor could not be published, want 0", got.exit)
	}

	if !strings.Contains(got.stderr, "the journal socket is gone") {
		t.Errorf("the anchor failure was not reported on stderr: %q", got.stderr)
	}

	if strings.Contains(got.stdout, "the journal socket is gone") {
		t.Errorf("the anchor failure reached stdout, which carries the protocol only: %q", got.stdout)
	}
}
