package broker

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/jroedel/adb-broker/business/types/errcode"
	"github.com/jroedel/adb-broker/foundation/audit"
)

// verify is exercised through the --anchors - form, which reads newline-delimited JSON
// entries. That is deliberate rather than a shortcut: it is the path an operator uses on a
// host where the broker's uid cannot read /var/log/journal (root:systemd-journal 0640), and it
// is the only one that can be driven in process, because building a real journal file needs
// foundation/journal's own unexported writer.
//
// The trust rules are the same on both paths, which is the property these tests are here to
// hold: _UID and _EXE are checked on a piped entry exactly as journal.Filter checks them on a
// file, because a second input path that skipped them would be a way around the only rule that
// makes an anchor mean anything.

// anchorLine renders one journalctl -o json entry, with journald's stamped fields as journald
// would have stamped them.
func anchorLine(t *testing.T, uid int, exe, logPath string, seq uint64, hash string) string {
	t.Helper()

	entry := map[string]string{
		"MESSAGE_ID":        audit.MessageID,
		"MESSAGE":           fmt.Sprintf("adb-broker audit anchor seq=%d", seq),
		"PRIORITY":          "5",
		"SYSLOG_IDENTIFIER": "adb-broker",
		"_UID":              fmt.Sprint(uid),
		"_GID":              fmt.Sprint(os.Getgid()),
		"_PID":              fmt.Sprint(os.Getpid()),
		"_COMM":             "adb-broker",
		"_EXE":              exe,
		"ADB_BROKER_SEQ":    fmt.Sprint(seq),
		"ADB_BROKER_HASH":   hash,
		"ADB_BROKER_LOG":    logPath,
	}

	encoded, err := json.Marshal(entry)
	if err != nil {
		t.Fatalf("encode the test anchor: %v", err)
	}

	return string(encoded) + "\n"
}

// chainState appends n records to a fresh audit log and returns the log's path, its last
// sequence number and its chain head.
func chainState(t *testing.T, n int) (string, uint64, string) {
	t.Helper()

	path := newAuditLog(t)

	log, err := audit.Open(path)
	if err != nil {
		t.Fatalf("open the test audit log: %v", err)
	}
	defer func() { _ = log.Close() }()

	for i := range n {
		rec := audit.Record{
			TS:       time.Now(),
			Op:       "probe",
			Decision: "allow",
			Result:   "ok",
			Serial:   fmt.Sprintf("SERIAL%d", i),
		}

		if _, err := log.Append(rec); err != nil {
			t.Fatalf("append record %d: %v", i+1, err)
		}
	}

	head := log.Head()

	return path, log.Seq(), hex.EncodeToString(head[:])
}

// runVerifyWith drives verify with the given anchor stream on stdin.
func runVerifyWith(t *testing.T, logPath, anchors string, args ...string) result {
	t.Helper()

	swap[io.Reader](t, &stdinReader, strings.NewReader(anchors))

	return runWithLog(t, logPath, nil, append([]string{"verify", "--log", logPath, "--anchors", "-"}, args...)...)
}

// thisExe is the path journald would have stamped on an anchor this process published.
func thisExe(t *testing.T) string {
	t.Helper()

	exe, err := os.Executable()
	if err != nil {
		t.Fatalf("determine this binary's path: %v", err)
	}

	return exe
}

func TestVerifyReportsOKWhenTheNewestAnchorMatchesTheChainHead(t *testing.T) {
	logPath, seq, head := chainState(t, 3)

	anchors := anchorLine(t, os.Geteuid(), thisExe(t), logPath, seq-1, strings.Repeat("a", 64)) +
		anchorLine(t, os.Geteuid(), thisExe(t), logPath, seq, head)

	got := runVerifyWith(t, logPath, anchors)

	want := fmt.Sprintf(`{"proto":1,"status":"ok","log":%q,"records":3,"last_seq":%d,"last_hash":%q,"anchors":2,"anchor_seq":%d,"anchor_hash":%q}`+"\n",
		logPath, seq, head, seq, head)

	if got.stdout != want {
		t.Errorf("stdout\n got: %q\nwant: %q", got.stdout, want)
	}

	if got.exit != 0 {
		t.Errorf("exit = %d, want 0; stderr %q", got.exit, got.stderr)
	}
}

func TestVerifyDetectsATruncatedTail(t *testing.T) {
	// The one failure the hash chain cannot detect on its own: an adversary who can write the
	// file can recompute a shorter chain that verifies perfectly. Only the anchor knows which
	// sequence number the file once held.
	logPath, seq, head := chainState(t, 2)

	anchors := anchorLine(t, os.Geteuid(), thisExe(t), logPath, seq+9, head)

	got := runVerifyWith(t, logPath, anchors)

	if got.exit == 0 {
		t.Fatal("exit = 0 with an anchor ahead of the log, want non-zero")
	}

	res := decode(t, lines(t, got.stdout)[0])
	if res["code"] != errcode.CodeAuditUnavailable.String() {
		t.Errorf("code = %v, want audit_unavailable", res["code"])
	}

	if message, _ := res["message"].(string); !strings.Contains(message, "truncated") {
		t.Errorf("message %q does not say the tail was truncated", message)
	}
}

func TestVerifyDetectsAnAlteredTailRecord(t *testing.T) {
	logPath, seq, head := chainState(t, 2)

	anchors := anchorLine(t, os.Geteuid(), thisExe(t), logPath, seq, strings.Repeat("b", 64))

	got := runVerifyWith(t, logPath, anchors)

	if got.exit == 0 {
		t.Fatal("exit = 0 when the anchor's hash disagrees with the chain head, want non-zero")
	}

	res := decode(t, lines(t, got.stdout)[0])
	if res["code"] != errcode.CodeAuditUnavailable.String() {
		t.Errorf("code = %v, want audit_unavailable", res["code"])
	}

	if message, _ := res["message"].(string); !strings.Contains(message, head) {
		t.Errorf("message %q does not name the chain head it compared against", message)
	}
}

func TestVerifyDetectsAnEditedRecordInTheMiddleOfTheChain(t *testing.T) {
	logPath, seq, head := chainState(t, 3)

	recorded, err := os.ReadFile(logPath)
	if err != nil {
		t.Fatalf("read the test audit log: %v", err)
	}

	// An equal-length edit, so nothing but recomputation could notice it.
	edited := strings.Replace(string(recorded), `"serial":"SERIAL1"`, `"serial":"SERIAL9"`, 1)
	if edited == string(recorded) {
		t.Fatal("the seeded chain does not contain the serial this test edits")
	}

	if err := os.WriteFile(logPath, []byte(edited), 0o600); err != nil {
		t.Fatalf("rewrite the test audit log: %v", err)
	}

	// The fail-closed check at startup passes: it validates only the TAIL, which this edit did
	// not touch. Whole-chain verification is verify's job, which is the split the two controls
	// are documented to have.
	got := runVerifyWith(t, logPath, anchorLine(t, os.Geteuid(), thisExe(t), logPath, seq, head))

	if got.exit == 0 {
		t.Fatal("exit = 0 with an edited record mid-chain, want non-zero")
	}

	res := decode(t, lines(t, got.stdout)[0])
	if res["code"] != errcode.CodeAuditUnavailable.String() {
		t.Errorf("code = %v, want audit_unavailable", res["code"])
	}

	if message, _ := res["message"].(string); !strings.Contains(message, "seq 2") {
		t.Errorf("message %q does not name the record at fault", message)
	}
}

func TestVerifyDiscardsAnAnchorItCannotAttributeToThisBinary(t *testing.T) {
	// The journal socket is mode 0666, so any local process can publish a well-formed entry
	// carrying this MESSAGE_ID with a fabricated seq and hash — one such forged anchor is a
	// permanent resident of this host's journal. _UID and _EXE are what distinguish a real one,
	// and an anchor that fails either is discarded rather than weighed.
	logPath, seq, head := chainState(t, 2)

	for _, tc := range []struct {
		name    string
		anchors string
	}{
		{"another uid", anchorLine(t, os.Geteuid()+1, thisExe(t), logPath, seq+9, head)},
		{"another executable", anchorLine(t, os.Geteuid(), "/usr/bin/forge", logPath, seq+9, head)},
		{"another message id", strings.Replace(
			anchorLine(t, os.Geteuid(), thisExe(t), logPath, seq+9, head),
			audit.MessageID, strings.Repeat("f", 32), 1)},
		{"another log", anchorLine(t, os.Geteuid(), thisExe(t), "/tmp/some-other.log", seq+9, head)},
		{"no anchors at all", ""},
	} {
		got := runVerifyWith(t, logPath, tc.anchors)

		// Partial, not ok: the chain verified, but the truncation check could not run, and a
		// verify that claims ok for a check it never performed is the confident pass an
		// adversary is hoping for. Each of these anchors claims a sequence number ahead of the
		// log, so a verify that accepted one would have reported a divergence.
		res := decode(t, lines(t, got.stdout)[0])
		if res["status"] != statusPartial {
			t.Errorf("%s: status = %v, want partial", tc.name, res["status"])
		}

		if res["anchors"] != float64(0) {
			t.Errorf("%s: anchors = %v, want 0", tc.name, res["anchors"])
		}

		if got.exit != 0 {
			t.Errorf("%s: exit = %d, want 0: the chain itself verified", tc.name, got.exit)
		}

		if got.stderr == "" {
			t.Errorf("%s: nothing on stderr said the truncation check could not run", tc.name)
		}
	}
}

func TestVerifyAcceptsALogThatHasGrownSinceTheNewestAnchor(t *testing.T) {
	logPath, seq, _ := chainState(t, 4)

	anchors := anchorLine(t, os.Geteuid(), thisExe(t), logPath, seq-2, strings.Repeat("c", 64))

	got := runVerifyWith(t, logPath, anchors)

	res := decode(t, lines(t, got.stdout)[0])
	if res["status"] != statusOK {
		t.Errorf("status = %v, want ok: no anchor claims a record the log is missing", res["status"])
	}

	if got.exit != 0 {
		t.Errorf("exit = %d, want 0", got.exit)
	}
}

func TestVerifyOnAnEmptyLogWithAnAnchorOfTheEmptyChain(t *testing.T) {
	// A fresh install's log is empty, which is a valid chain of length zero with a head of 32
	// zero bytes. audit.Summary reports that as an empty LastHash, so the two representations
	// have to be reconciled before they are compared.
	logPath := newAuditLog(t)

	got := runVerifyWith(t, logPath, anchorLine(t, os.Geteuid(), thisExe(t), logPath, 0, emptyChainHead))

	res := decode(t, lines(t, got.stdout)[0])
	if res["status"] != statusOK {
		t.Errorf("status = %v, want ok; stderr %q", res["status"], got.stderr)
	}

	if res["last_hash"] != emptyChainHead {
		t.Errorf("last_hash = %v, want the 32 zero bytes an empty chain heads with", res["last_hash"])
	}
}

func TestVerifyRequiresAnAnchorSource(t *testing.T) {
	logPath, _, _ := chainState(t, 1)

	got := runWithLog(t, logPath, nil, "verify", "--log", logPath)

	if got.exit == 0 {
		t.Fatal("exit = 0 with no --anchors, want non-zero")
	}

	res := decode(t, lines(t, got.stdout)[0])
	if res["code"] != errcode.CodeUnsupported.String() {
		t.Errorf("code = %v, want unsupported", res["code"])
	}
}

func TestVerifyReportsAnUnreadableLog(t *testing.T) {
	missing := filepath.Join(t.TempDir(), "not-a-log")

	got := runVerifyWith(t, newAuditLog(t), "", "--log", missing)

	// The last --log wins, which is flag's behaviour; what matters here is the classification.
	if got.exit == 0 {
		t.Fatal("exit = 0 for a log that cannot be read, want non-zero")
	}

	if res := decode(t, lines(t, got.stdout)[0]); res["code"] != errcode.CodeAuditUnavailable.String() {
		t.Errorf("code = %v, want audit_unavailable", res["code"])
	}
}

func TestVerifyReportsAMalformedAnchorFromThisBinarysIdentity(t *testing.T) {
	// An entry that passed the trust filter carries this binary's own uid and path, so a
	// malformed payload in one is not noise to skip past: nothing else publishes under that
	// identity.
	logPath, seq, head := chainState(t, 1)

	for _, tc := range []struct {
		name    string
		anchors string
	}{
		{"a sequence number that is not a number", strings.Replace(
			anchorLine(t, os.Geteuid(), thisExe(t), logPath, seq, head), `"ADB_BROKER_SEQ":"1"`, `"ADB_BROKER_SEQ":"one"`, 1)},
		{"a hash that is not a digest", anchorLine(t, os.Geteuid(), thisExe(t), logPath, seq, "not-a-hash")},
		{"two values for one field", `{"MESSAGE_ID":"` + audit.MessageID + `","_UID":["0","1"],"_EXE":"/x"}` + "\n"},
		{"not JSON at all", "this is not an entry\n"},
	} {
		got := runVerifyWith(t, logPath, tc.anchors)

		if got.exit == 0 {
			t.Errorf("%s: exit = 0, want non-zero", tc.name)
		}

		if res := decode(t, lines(t, got.stdout)[0]); res["code"] != errcode.CodeAuditUnavailable.String() {
			t.Errorf("%s: code = %v, want audit_unavailable", tc.name, res["code"])
		}
	}
}

func TestVerifySkipsBlankLinesAndUnrelatedEntries(t *testing.T) {
	logPath, seq, head := chainState(t, 1)

	anchors := "\n" +
		`{"MESSAGE":"an ordinary log line from something else","_UID":"0","_EXE":"/usr/lib/systemd/systemd"}` + "\n" +
		"\n" +
		anchorLine(t, os.Geteuid(), thisExe(t), logPath, seq, head)

	got := runVerifyWith(t, logPath, anchors)

	res := decode(t, lines(t, got.stdout)[0])
	if res["status"] != statusOK || res["anchors"] != float64(1) {
		t.Errorf("got %s, want status ok with one anchor; stderr %q", lines(t, got.stdout)[0], got.stderr)
	}
}

// The anchor a run actually publishes is one verify accepts, from both of the two paths that
// append to the log.
//
// Every other test in this file hands verify an anchor a test constructed. This one takes what
// the broker itself published, renders it exactly as journalctl would, and feeds it back — so a
// path that anchors the WRONG chain state fails here even though it anchors. Both paths matter
// and for different reasons: the audit extension covers every recorded operation, and
// denyBeforeBus covers the flag-boundary refusal no decorator on the bus can see, which is the
// case that went unanchored until defect E was fixed.
func TestTheAnchorARunPublishesIsOneVerifyAccepts(t *testing.T) {
	for _, tc := range []struct {
		name string
		args []string
	}{
		{"a recorded probe", []string{"probe"}},
		{"a flag-boundary denial", []string{"list", "--root", "/data/data"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			logPath := newAuditLog(t)
			published := captureAnchors(t)

			runWithLog(t, logPath, newFakeStore(), tc.args...)

			if len(*published) != 1 {
				t.Fatalf("the run published %d anchors, want 1", len(*published))
			}

			anchor := (*published)[0]

			got := runVerifyWith(t, logPath, anchorLine(t, os.Geteuid(), thisExe(t), anchor.log, anchor.seq, anchor.hash))

			res := decode(t, lines(t, got.stdout)[0])
			if res["status"] != statusOK || res["anchors"] != float64(1) {
				t.Errorf("verify on the run's own anchor: %s, want status ok with one anchor; stderr %q", lines(t, got.stdout)[0], got.stderr)
			}

			if got.exit != 0 {
				t.Errorf("exit = %d, want 0", got.exit)
			}
		})
	}
}

func TestVerifyContactsNoDevice(t *testing.T) {
	logPath, seq, head := chainState(t, 1)

	store := newFakeStore()

	swap[io.Reader](t, &stdinReader, strings.NewReader(anchorLine(t, os.Geteuid(), thisExe(t), logPath, seq, head)))

	if got := runWithLog(t, logPath, store, "verify", "--log", logPath, "--anchors", "-"); got.exit != 0 {
		t.Fatalf("exit = %d, stderr %q", got.exit, got.stderr)
	}

	if store.touched {
		t.Error("verify reached the transport; it takes no device and no network")
	}
}
