package broker

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"os"
	"strings"
	"testing"

	"github.com/jroedel/adb-broker/foundation/audit"
)

// A denial at the flag boundary never reaches the bus, so the audit extension cannot see
// it. It must still be recorded: a caller repeatedly asking for trees it has no business
// reading is exactly the pattern the log exists to make visible, and it is the one a
// decorator on the bus structurally cannot capture.
func TestDeniedRootIsRecordedEvenThoughItNeverReachesTheBus(t *testing.T) {
	logPath := newAuditLog(t)
	store := newFakeStore()

	got := runWithLog(t, logPath, store, "list", "--root", "/data/data", "--client", "photos")

	if got.exit == 0 {
		t.Fatalf("a denied root exited 0; stdout: %s", got.stdout)
	}
	if !strings.Contains(got.stdout, `"code":"path_denied"`) {
		t.Fatalf("stdout did not report path_denied: %s", got.stdout)
	}

	// The transport must never have been reached.
	if store.touched {
		t.Fatal("a denied root reached the store")
	}

	summary, records := readLog(t, logPath)
	if summary.Records != 1 {
		t.Fatalf("audit log holds %d records, want exactly 1", summary.Records)
	}

	rec := records[0]
	switch {
	case rec.Op != "list":
		t.Errorf("Op = %q, want %q", rec.Op, "list")
	case rec.Decision != "deny":
		t.Errorf("Decision = %q, want %q", rec.Decision, "deny")
	case rec.Result != "path_denied":
		t.Errorf("Result = %q, want %q", rec.Result, "path_denied")
	case rec.CallerUID != os.Getuid():
		t.Errorf("CallerUID = %d, want the real uid %d", rec.CallerUID, os.Getuid())
	case rec.ClientAsserted != "photos":
		t.Errorf("ClientAsserted = %q, want %q", rec.ClientAsserted, "photos")
	}

	// The requested path is recorded as base64 of the raw bytes, so an unparseable or
	// non-UTF-8 request is still recorded faithfully rather than lossily.
	want := base64.StdEncoding.EncodeToString([]byte("/data/data"))
	if rec.PathB64 != want {
		t.Errorf("PathB64 = %q, want %q (base64 of the raw requested bytes)", rec.PathB64, want)
	}
}

// A rejected --client label is also a refusal, and it is recorded with an empty
// ClientAsserted: the label was the thing found invalid, so echoing it into the record
// would put unvalidated caller bytes in the field a reader is told not to trust anyway.
func TestRejectedClientLabelIsRecordedWithoutTheLabel(t *testing.T) {
	logPath := newAuditLog(t)
	store := newFakeStore()

	got := runWithLog(t, logPath, store, "probe", "--client", "not a valid label")

	if got.exit == 0 {
		t.Fatalf("an invalid --client exited 0; stdout: %s", got.stdout)
	}
	if store.touched {
		t.Fatal("an invalid --client reached the store")
	}

	summary, records := readLog(t, logPath)
	if summary.Records != 1 {
		t.Fatalf("audit log holds %d records, want exactly 1", summary.Records)
	}
	if records[0].Decision != "deny" {
		t.Errorf("Decision = %q, want deny", records[0].Decision)
	}
	if records[0].ClientAsserted != "" {
		t.Errorf("ClientAsserted = %q, want empty for a rejected label", records[0].ClientAsserted)
	}
}

// A run that is nothing but a flag-boundary denial must publish an anchor for the chain head
// it just advanced.
//
// This is the defect the first version of denyBeforeBus had. It appended the record — the log
// grew, its head moved — and published nothing, so the invariant deviceaudit.anchor documents
// ("the LAST operation of a process always anchors") held for every record EXCEPT this one.
// The effect was exactly inverted from the intent: a caller repeatedly probing paths it has no
// business reading is the pattern this record type exists to catch, and it was the one record
// type whose tail no anchor covered, so a truncation removing precisely those records could
// not be detected.
func TestADenialOnlyRunAnchorsTheChainHeadItAdvanced(t *testing.T) {
	logPath := newAuditLog(t)
	published := captureAnchors(t)
	store := newFakeStore()

	got := runWithLog(t, logPath, store, "list", "--root", "/data/data")

	if got.exit == 0 {
		t.Fatalf("a denied root exited 0; stdout: %s", got.stdout)
	}

	summary, records := readLog(t, logPath)
	if len(records) != 1 {
		t.Fatalf("audit log holds %d records, want exactly 1", len(records))
	}

	if len(*published) != 1 {
		t.Fatalf("a denial-only run published %d anchors, want exactly 1 for the record it wrote", len(*published))
	}

	anchor := (*published)[0]

	// The anchor has to name the NEW head. An anchor for the previous one would be a claim
	// about a log this run had already changed, and verify would read it as a shortened chain.
	switch {
	case anchor.seq != summary.LastSeq:
		t.Errorf("the anchor claims seq %d, want %d, the sequence number the denial wrote", anchor.seq, summary.LastSeq)
	case anchor.hash != summary.LastHash:
		t.Errorf("the anchor claims head %s, want %s, the chain head after the denial", anchor.hash, summary.LastHash)
	case anchor.log != logPath:
		t.Errorf("the anchor names log %q, want %q: an anchor that does not say which log it describes is evidence about none", anchor.log, logPath)
	}
}

// An anchor that cannot be published changes nothing the caller sees, on the deny path exactly
// as on the recorded-operation path. The refusal happened and was recorded either way, and an
// anchor is a detectability aid for a truncated tail, not a precondition for the record it
// describes. It is reported on stderr, naming the reason, and nowhere else.
func TestADenialWhoseAnchorCannotBePublishedIsReportedUnchanged(t *testing.T) {
	logPath := newAuditLog(t)

	reason := "dial journal socket /run/systemd/journal/socket: permission denied"
	swap(t, &publishAnchor, func(*audit.Log) error { return errors.New(reason) })

	got := runWithLog(t, logPath, newFakeStore(), "list", "--root", "/data/data")

	// Byte for byte what a working anchor path produces: one path_denied error object.
	out := lines(t, got.stdout)
	if len(out) != 1 || !strings.Contains(out[0], `"code":"path_denied"`) {
		t.Fatalf("stdout changed because an anchor failed:\n%s", got.stdout)
	}

	if got.exit != exitError {
		t.Errorf("exit = %d, want %d: an anchor failure must not move the exit status", got.exit, exitError)
	}

	if !strings.Contains(got.stderr, reason) {
		t.Errorf("stderr does not name why the anchor failed, which is the whole diagnostic:\n%s", got.stderr)
	}

	// And the record itself is still there and still verifies.
	if _, records := readLog(t, logPath); len(records) != 1 {
		t.Errorf("audit log holds %d records, want 1: the refusal must be recorded whether or not it could be anchored", len(records))
	}
}

// verify is the one subcommand exempt from the fail-closed check. Gating it would make the
// tool that exists to diagnose a damaged audit log unable to open one — the diagnostic
// refusing exactly when it is needed. verify never appends and never touches a device, so
// there is no unauditable read for the check to prevent.
func TestVerifyRunsEvenWhenTheAuditLogTailDoesNotVerify(t *testing.T) {
	logPath := newAuditLog(t)

	// Write a record, then corrupt it, so audit.Open would refuse this log.
	log, err := audit.Open(logPath)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	if _, err := log.Append(audit.Record{Op: "probe", Decision: "allow", Result: "ok"}); err != nil {
		t.Fatalf("append: %v", err)
	}
	_ = log.Close()

	corruptTail(t, logPath)

	if _, err := audit.Open(logPath); err == nil {
		t.Fatal("audit.Open accepted a corrupted tail; this test no longer proves anything")
	}

	// Every other subcommand must refuse.
	blocked := runWithLog(t, logPath, newFakeStore(), "probe")
	if !strings.Contains(blocked.stdout, `"code":"audit_unavailable"`) {
		t.Fatalf("probe did not fail closed on a corrupt log: %s", blocked.stdout)
	}

	// verify must not.
	out := runVerifyOn(t, logPath)
	if strings.Contains(out, `"code":"audit_unavailable"`) &&
		strings.Contains(out, "cannot be opened") {
		t.Fatalf("verify refused to open the log it exists to diagnose: %s", out)
	}
	if out == "" {
		t.Fatal("verify produced no output at all")
	}
}

// logRecord is one on-disk audit line, keyed the way the file actually spells it.
//
// foundation/audit writes the canonical form with a hand-rolled encoder in snake_case, and
// audit.Record deliberately carries no json tags — the canonical order is a written-down
// rule there, not a struct-tag coincidence. So a test that unmarshalled a line into an
// audit.Record would silently bind only the fields whose Go names happen to match, and
// would report caller_uid as 0 and path_b64 as empty while claiming to have read them.
type logRecord struct {
	Op             string `json:"op"`
	CallerUID      int    `json:"caller_uid"`
	ClientAsserted string `json:"client_asserted"`
	PathB64        string `json:"path_b64"`
	Decision       string `json:"decision"`
	Result         string `json:"result"`
}

// readLog returns the chain summary and every record in the log at path.
func readLog(t *testing.T, path string) (audit.Summary, []logRecord) {
	t.Helper()

	f, err := os.Open(path)
	if err != nil {
		t.Fatalf("open log: %v", err)
	}
	defer f.Close()

	summary, err := audit.VerifyChain(f)
	if err != nil {
		t.Fatalf("the log this test just wrote does not verify: %v", err)
	}

	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read log: %v", err)
	}

	var records []logRecord
	for line := range strings.SplitSeq(strings.TrimRight(string(raw), "\n"), "\n") {
		if line == "" {
			continue
		}

		var rec logRecord
		if err := json.Unmarshal([]byte(line), &rec); err != nil {
			t.Fatalf("decode %q: %v", line, err)
		}
		records = append(records, rec)
	}

	return summary, records
}

// corruptTail flips a byte inside the final record's payload, so the log's tail no longer
// re-hashes and audit.Open must refuse it.
func corruptTail(t *testing.T, path string) {
	t.Helper()

	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read log: %v", err)
	}

	// "allow" -> "allos": inside the hashed payload, and still valid JSON, so the failure
	// is a hash mismatch rather than a parse error.
	corrupted := strings.Replace(string(raw), `"decision":"allow"`, `"decision":"allos"`, 1)
	if corrupted == string(raw) {
		t.Fatal("could not corrupt the record; the on-disk format changed")
	}

	if err := os.WriteFile(path, []byte(corrupted), 0o600); err != nil {
		t.Fatalf("write log: %v", err)
	}
}

// runVerifyOn drives the verify subcommand against a log, with no anchors available.
func runVerifyOn(t *testing.T, logPath string) string {
	t.Helper()

	swap(t, &openAuditLog, func() (*audit.Log, bool, error) {
		t.Fatal("verify opened the audit log for appending; it must not be gated by the fail-closed check")

		return nil, false, nil
	})

	var stdout, stderr strings.Builder
	Main([]string{"verify", "--log", logPath, "--anchors", "-"}, &stdout, &stderr)

	return stdout.String() + stderr.String()
}
