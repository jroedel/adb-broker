package deviceaudit

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/jroedel/adb-broker/business/domain/device/devicebus"
	"github.com/jroedel/adb-broker/business/types/devicepath"
	"github.com/jroedel/adb-broker/business/types/serial"
	"github.com/jroedel/adb-broker/foundation/audit"
)

// ---------------------------------------------------------------------------
// Fixtures
// ---------------------------------------------------------------------------

// installLog creates an empty audit log file the way the installer would.
// audit.Open deliberately cannot create one itself (see its doc comment), so
// every test that needs a *audit.Log must do this first.
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

// newTestLog opens a fresh, empty audit log for the duration of one test.
func newTestLog(t *testing.T) (*audit.Log, string) {
	t.Helper()

	path := installLog(t)

	l, err := audit.Open(path)
	if err != nil {
		t.Fatalf("audit.Open: %v", err)
	}
	t.Cleanup(func() { l.Close() })

	return l, path
}

// newExtension wires this extension the way every test here needs it: with an
// anchor publisher that succeeds and goes nowhere, and no stderr.
//
// Passing nil for the AnchorFunc would default to audit.AnchorTail, which sends a
// real datagram to /run/systemd/journal/socket. That is not hypothetical: 672
// anchors stamped _EXE=…/deviceaudit.test are permanently in this host's journal,
// published by earlier runs of this file and claiming chain heads for logs in
// t.TempDir() directories that no longer exist. Journal entries cannot be removed,
// so each one is noise a real verify has to discard forever. Every test in this
// file goes through here; the two that care about anchoring pass their own.
func newExtension(log *audit.Log, callerUID int, clientAsserted string) devicebus.Extension {
	return NewExtension(log, callerUID, clientAsserted, func(*audit.Log) error { return nil }, io.Discard)
}

func mustSerial(t *testing.T, s string) serial.Serial {
	t.Helper()

	ser, err := serial.ParseSerial(s)
	if err != nil {
		t.Fatalf("mustSerial: %v", err)
	}

	return ser
}

func mustPath(t *testing.T, s string) devicepath.AuthorizedPath {
	t.Helper()

	p, err := devicepath.ParseAuthorizedPath(s)
	if err != nil {
		t.Fatalf("mustPath: %v", err)
	}

	return p
}

// mustVolume pins a devicepath.Volume for test fixtures, via the same
// ResolveVolume constructor the real package uses — there is no other way to
// build a non-zero Volume.
func mustVolume(t *testing.T, dev, ino int64) devicepath.Volume {
	t.Helper()

	vol, err := devicepath.ResolveVolume(func(string) (int64, int64, uint32, error) {
		return dev, ino, 0o040000, nil // S_IFDIR
	})
	if err != nil {
		t.Fatalf("mustVolume: %v", err)
	}

	return vol
}

// diskLine mirrors the on-disk record shape (see foundation/audit's diskRecord)
// closely enough for this test file to assert on individual fields. It is a
// test-only decode: it does not validate the hash chain, which is
// audit.VerifyChain's job and is exercised separately below.
type diskLine struct {
	Seq            uint64 `json:"seq"`
	Op             string `json:"op"`
	CallerUID      int    `json:"caller_uid"`
	ClientAsserted string `json:"client_asserted"`
	Serial         string `json:"serial"`
	PathB64        string `json:"path_b64"`
	Decision       string `json:"decision"`
	Result         string `json:"result"`
	Bytes          int64  `json:"bytes"`
	SHA256         string `json:"sha256"`
	Volume         struct {
		Dev int64 `json:"dev"`
		Ino int64 `json:"ino"`
	} `json:"volume"`
}

// readRecords reads every line of the log at path and decodes it.
func readRecords(t *testing.T, path string) []diskLine {
	t.Helper()

	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read log: %v", err)
	}

	var out []diskLine
	for _, line := range strings.Split(strings.TrimRight(string(raw), "\n"), "\n") {
		if line == "" {
			continue
		}

		var dl diskLine
		if err := json.Unmarshal([]byte(line), &dl); err != nil {
			t.Fatalf("decode line %q: %v", line, err)
		}

		out = append(out, dl)
	}

	return out
}

// fakeExtBusiness is a devicebus.ExtBusiness test double. Each method defers
// to an optional hook, falling back to a zero-value success.
type fakeExtBusiness struct {
	probeFn func(s serial.Serial) (devicebus.Device, error)
	listFn  func(in devicebus.ListInput, fn func(devicebus.FileRecord) error) (devicebus.ListSummary, error)
	fetchFn func(p devicepath.AuthorizedPath, w io.Writer) (devicebus.FetchResult, error)
}

func (f *fakeExtBusiness) Probe(_ context.Context, s serial.Serial) (devicebus.Device, error) {
	if f.probeFn != nil {
		return f.probeFn(s)
	}

	return devicebus.Device{Serial: s}, nil
}

func (f *fakeExtBusiness) List(_ context.Context, in devicebus.ListInput, fn func(devicebus.FileRecord) error) (devicebus.ListSummary, error) {
	if f.listFn != nil {
		return f.listFn(in, fn)
	}

	return devicebus.ListSummary{}, nil
}

func (f *fakeExtBusiness) Fetch(_ context.Context, p devicepath.AuthorizedPath, w io.Writer, _ func(devicebus.FetchInfo) error) (devicebus.FetchResult, error) {
	if f.fetchFn != nil {
		return f.fetchFn(p, w)
	}

	return devicebus.FetchResult{}, nil
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

// 1. A successful Probe appends exactly one record with Op "probe", Decision
// "allow", Result "ok", and the volume from the returned Device.
func TestProbe_Success_AppendsOneAllowRecord(t *testing.T) {
	log, path := newTestLog(t)
	vol := mustVolume(t, 190, 4812)
	ser := mustSerial(t, "emulator-5554")

	fake := &fakeExtBusiness{
		probeFn: func(s serial.Serial) (devicebus.Device, error) {
			return devicebus.Device{Serial: s, Volume: vol}, nil
		},
	}

	ext := newExtension(log, 1000, "user@example.com")(fake)

	if _, err := ext.Probe(t.Context(), ser); err != nil {
		t.Fatalf("Probe: unexpected error: %v", err)
	}

	recs := readRecords(t, path)
	if len(recs) != 1 {
		t.Fatalf("got %d records, want 1", len(recs))
	}

	r := recs[0]
	if r.Op != "probe" {
		t.Errorf("Op = %q, want %q", r.Op, "probe")
	}
	if r.Decision != "allow" {
		t.Errorf("Decision = %q, want %q", r.Decision, "allow")
	}
	if r.Result != "ok" {
		t.Errorf("Result = %q, want %q", r.Result, "ok")
	}
	if r.Volume.Dev != vol.Dev() || r.Volume.Ino != vol.Ino() {
		t.Errorf("Volume = %+v, want dev=%d ino=%d", r.Volume, vol.Dev(), vol.Ino())
	}
}

// 2. A successful Fetch records Bytes and SHA256 from the FetchResult, and
// PathB64 equal to the path's Base64().
func TestFetch_Success_RecordsBytesAndSHA256(t *testing.T) {
	log, path := newTestLog(t)
	vol := mustVolume(t, 190, 42)
	p := mustPath(t, "/sdcard/DCIM/a.jpg")

	fake := &fakeExtBusiness{
		fetchFn: func(_ devicepath.AuthorizedPath, _ io.Writer) (devicebus.FetchResult, error) {
			return devicebus.FetchResult{Bytes: 4096, SHA256: strings.Repeat("a", 64), Volume: vol}, nil
		},
	}

	ext := newExtension(log, 1000, "user@example.com")(fake)

	if _, err := ext.Fetch(t.Context(), p, io.Discard, nil); err != nil {
		t.Fatalf("Fetch: unexpected error: %v", err)
	}

	recs := readRecords(t, path)
	if len(recs) != 1 {
		t.Fatalf("got %d records, want 1", len(recs))
	}

	r := recs[0]
	if r.Op != "fetch" {
		t.Errorf("Op = %q, want %q", r.Op, "fetch")
	}
	if r.Bytes != 4096 {
		t.Errorf("Bytes = %d, want 4096", r.Bytes)
	}
	if r.SHA256 != strings.Repeat("a", 64) {
		t.Errorf("SHA256 = %q, want %q", r.SHA256, strings.Repeat("a", 64))
	}
	if r.PathB64 != p.Base64() {
		t.Errorf("PathB64 = %q, want %q", r.PathB64, p.Base64())
	}
}

// 3. A successful List records the root's PathB64, Bytes 0 and an empty
// SHA256.
func TestList_Success_RecordsRootPathZeroBytesNoSHA(t *testing.T) {
	log, path := newTestLog(t)
	vol := mustVolume(t, 190, 999)
	root := mustPath(t, "/sdcard/DCIM")

	fake := &fakeExtBusiness{
		listFn: func(_ devicebus.ListInput, _ func(devicebus.FileRecord) error) (devicebus.ListSummary, error) {
			return devicebus.ListSummary{Files: 3, Volume: vol}, nil
		},
	}

	ext := newExtension(log, 1000, "user@example.com")(fake)

	in := devicebus.ListInput{Root: root}
	if _, err := ext.List(t.Context(), in, func(devicebus.FileRecord) error { return nil }); err != nil {
		t.Fatalf("List: unexpected error: %v", err)
	}

	recs := readRecords(t, path)
	if len(recs) != 1 {
		t.Fatalf("got %d records, want 1", len(recs))
	}

	r := recs[0]
	if r.Op != "list" {
		t.Errorf("Op = %q, want %q", r.Op, "list")
	}
	if r.PathB64 != root.Base64() {
		t.Errorf("PathB64 = %q, want %q", r.PathB64, root.Base64())
	}
	if r.Bytes != 0 {
		t.Errorf("Bytes = %d, want 0", r.Bytes)
	}
	if r.SHA256 != "" {
		t.Errorf("SHA256 = %q, want empty", r.SHA256)
	}
}

// 4 & 5. A failed operation still appends a record, with Decision "deny", and
// the original error is returned unchanged. A successful operation records
// Decision "allow". Table-driven across all three methods.
func TestFailedOperations_StillAppendAndReturnErrorUnchanged(t *testing.T) {
	sentinel := errors.New("boom: refused")

	t.Run("probe", func(t *testing.T) {
		log, path := newTestLog(t)
		ser := mustSerial(t, "emulator-5554")

		fake := &fakeExtBusiness{
			probeFn: func(serial.Serial) (devicebus.Device, error) {
				return devicebus.Device{}, sentinel
			},
		}

		ext := newExtension(log, 1, "x")(fake)

		_, err := ext.Probe(t.Context(), ser)
		if !errors.Is(err, sentinel) {
			t.Fatalf("Probe: err = %v, want wrapping %v", err, sentinel)
		}

		recs := readRecords(t, path)
		if len(recs) != 1 {
			t.Fatalf("got %d records, want 1", len(recs))
		}
		if recs[0].Decision != "deny" {
			t.Errorf("Decision = %q, want %q", recs[0].Decision, "deny")
		}
	})

	t.Run("list", func(t *testing.T) {
		log, path := newTestLog(t)
		root := mustPath(t, "/sdcard/DCIM")

		fake := &fakeExtBusiness{
			listFn: func(devicebus.ListInput, func(devicebus.FileRecord) error) (devicebus.ListSummary, error) {
				return devicebus.ListSummary{}, sentinel
			},
		}

		ext := newExtension(log, 1, "x")(fake)

		_, err := ext.List(t.Context(), devicebus.ListInput{Root: root}, func(devicebus.FileRecord) error { return nil })
		if !errors.Is(err, sentinel) {
			t.Fatalf("List: err = %v, want wrapping %v", err, sentinel)
		}

		recs := readRecords(t, path)
		if len(recs) != 1 {
			t.Fatalf("got %d records, want 1", len(recs))
		}
		if recs[0].Decision != "deny" {
			t.Errorf("Decision = %q, want %q", recs[0].Decision, "deny")
		}
	})

	t.Run("fetch", func(t *testing.T) {
		log, path := newTestLog(t)
		p := mustPath(t, "/sdcard/DCIM/a.jpg")

		fake := &fakeExtBusiness{
			fetchFn: func(devicepath.AuthorizedPath, io.Writer) (devicebus.FetchResult, error) {
				return devicebus.FetchResult{}, sentinel
			},
		}

		ext := newExtension(log, 1, "x")(fake)

		_, err := ext.Fetch(t.Context(), p, io.Discard, nil)
		if !errors.Is(err, sentinel) {
			t.Fatalf("Fetch: err = %v, want wrapping %v", err, sentinel)
		}

		recs := readRecords(t, path)
		if len(recs) != 1 {
			t.Fatalf("got %d records, want 1", len(recs))
		}
		if recs[0].Decision != "deny" {
			t.Errorf("Decision = %q, want %q", recs[0].Decision, "deny")
		}
	})

	t.Run("success is allow", func(t *testing.T) {
		log, path := newTestLog(t)
		ser := mustSerial(t, "emulator-5554")

		fake := &fakeExtBusiness{}
		ext := newExtension(log, 1, "x")(fake)

		if _, err := ext.Probe(t.Context(), ser); err != nil {
			t.Fatalf("Probe: unexpected error: %v", err)
		}

		recs := readRecords(t, path)
		if len(recs) != 1 {
			t.Fatalf("got %d records, want 1", len(recs))
		}
		if recs[0].Decision != "allow" {
			t.Errorf("Decision = %q, want %q", recs[0].Decision, "allow")
		}
	})
}

// 6. CallerUID and ClientAsserted appear in the record as configured.
func TestRecord_CarriesCallerUIDAndClientAsserted(t *testing.T) {
	log, path := newTestLog(t)
	ser := mustSerial(t, "emulator-5554")

	fake := &fakeExtBusiness{}
	ext := newExtension(log, 4242, "asserted-client-id")(fake)

	if _, err := ext.Probe(t.Context(), ser); err != nil {
		t.Fatalf("Probe: unexpected error: %v", err)
	}

	recs := readRecords(t, path)
	if len(recs) != 1 {
		t.Fatalf("got %d records, want 1", len(recs))
	}
	if recs[0].CallerUID != 4242 {
		t.Errorf("CallerUID = %d, want 4242", recs[0].CallerUID)
	}
	if recs[0].ClientAsserted != "asserted-client-id" {
		t.Errorf("ClientAsserted = %q, want %q", recs[0].ClientAsserted, "asserted-client-id")
	}
}

// 7. The chain is valid after several mixed operations: read the log back
// with audit.VerifyChain and assert a clean summary with the expected record
// count.
func TestChain_ValidAfterMixedOperations(t *testing.T) {
	log, path := newTestLog(t)
	vol := mustVolume(t, 190, 1)
	ser := mustSerial(t, "emulator-5554")
	root := mustPath(t, "/sdcard/DCIM")
	fetchPath := mustPath(t, "/sdcard/DCIM/a.jpg")
	sentinel := errors.New("boom")

	fake := &fakeExtBusiness{
		probeFn: func(s serial.Serial) (devicebus.Device, error) {
			return devicebus.Device{Serial: s, Volume: vol}, nil
		},
		listFn: func(devicebus.ListInput, func(devicebus.FileRecord) error) (devicebus.ListSummary, error) {
			return devicebus.ListSummary{}, sentinel
		},
		fetchFn: func(devicepath.AuthorizedPath, io.Writer) (devicebus.FetchResult, error) {
			return devicebus.FetchResult{Bytes: 10, SHA256: "abc", Volume: vol}, nil
		},
	}

	ext := newExtension(log, 1, "x")(fake)

	if _, err := ext.Probe(t.Context(), ser); err != nil {
		t.Fatalf("Probe: unexpected error: %v", err)
	}
	if _, err := ext.List(t.Context(), devicebus.ListInput{Root: root}, func(devicebus.FileRecord) error { return nil }); !errors.Is(err, sentinel) {
		t.Fatalf("List: err = %v, want wrapping %v", err, sentinel)
	}
	if _, err := ext.Fetch(t.Context(), fetchPath, io.Discard, nil); err != nil {
		t.Fatalf("Fetch: unexpected error: %v", err)
	}

	if err := log.Close(); err != nil {
		t.Fatalf("close log: %v", err)
	}

	f, err := os.Open(path)
	if err != nil {
		t.Fatalf("open log for verification: %v", err)
	}
	defer f.Close()

	summary, err := audit.VerifyChain(f)
	if err != nil {
		t.Fatalf("VerifyChain: %v", err)
	}
	if summary.Records != 3 {
		t.Errorf("Records = %d, want 3", summary.Records)
	}
	if summary.LastSeq != 3 {
		t.Errorf("LastSeq = %d, want 3", summary.LastSeq)
	}
}

// 8. PathB64 round-trips a path containing invalid UTF-8 bytes without loss.
func TestPathB64_RoundTripsInvalidUTF8(t *testing.T) {
	log, path := newTestLog(t)

	raw := append([]byte("/sdcard/DCIM/"), 0xff, 0xfe, 0x80, 'x', 0xc3, '.', 'j', 'p', 'g')

	p, err := devicepath.ParseAuthorizedPath(string(raw))
	if err != nil {
		t.Fatalf("ParseAuthorizedPath: %v", err)
	}

	fake := &fakeExtBusiness{
		fetchFn: func(devicepath.AuthorizedPath, io.Writer) (devicebus.FetchResult, error) {
			return devicebus.FetchResult{}, nil
		},
	}

	ext := newExtension(log, 1, "x")(fake)

	if _, err := ext.Fetch(t.Context(), p, io.Discard, nil); err != nil {
		t.Fatalf("Fetch: unexpected error: %v", err)
	}

	recs := readRecords(t, path)
	if len(recs) != 1 {
		t.Fatalf("got %d records, want 1", len(recs))
	}

	decoded, err := base64.StdEncoding.DecodeString(recs[0].PathB64)
	if err != nil {
		t.Fatalf("PathB64 does not decode: %v", err)
	}
	if string(decoded) != string(raw) {
		t.Fatalf("round-tripped path = %v, want %v", decoded, raw)
	}
}

// 9. The callback passed to List is invoked (not swallowed), and a callback
// error propagates.
func TestList_InvokesCallbackAndPropagatesItsError(t *testing.T) {
	log, _ := newTestLog(t)
	root := mustPath(t, "/sdcard/DCIM")
	callbackErr := errors.New("callback boom")

	fake := &fakeExtBusiness{
		listFn: func(_ devicebus.ListInput, fn func(devicebus.FileRecord) error) (devicebus.ListSummary, error) {
			if err := fn(devicebus.FileRecord{}); err != nil {
				return devicebus.ListSummary{}, err
			}

			return devicebus.ListSummary{Files: 1}, nil
		},
	}

	ext := newExtension(log, 1, "x")(fake)

	invoked := false
	_, err := ext.List(t.Context(), devicebus.ListInput{Root: root}, func(devicebus.FileRecord) error {
		invoked = true

		return callbackErr
	})

	if !invoked {
		t.Fatal("callback was not invoked")
	}
	if !errors.Is(err, callbackErr) {
		t.Fatalf("List: err = %v, want wrapping %v", err, callbackErr)
	}
}

// 10. An anchor failure does not fail the operation, and is reported on the
// writer the extension was constructed with rather than swallowed.
//
// The failing publisher is passed to NewExtension, which is the seam this
// package now offers for it. The package-level writeAnchor variable it replaced
// could only be reached from inside this package, which is why app/broker's
// tests published 2,649 real anchors into this host's journal before the seam
// moved into the constructor.
func TestAnchorFailure_DoesNotFailTheOperationAndIsReported(t *testing.T) {
	log, path := newTestLog(t)
	ser := mustSerial(t, "emulator-5554")

	reason := errors.New("dial journal socket /run/systemd/journal/socket: permission denied")

	var stderr strings.Builder
	fake := &fakeExtBusiness{}
	ext := NewExtension(log, 1, "x", func(*audit.Log) error { return reason }, &stderr)(fake)

	dev, err := ext.Probe(t.Context(), ser)
	if err != nil {
		t.Fatalf("Probe: unexpected error despite anchor failure: %v", err)
	}
	if dev.Serial != ser {
		t.Errorf("Probe returned Serial %v, want the delegate's %v: an anchor failure must not alter the result", dev.Serial, ser)
	}

	recs := readRecords(t, path)
	if len(recs) != 1 {
		t.Fatalf("got %d records, want 1 (the append must still have happened)", len(recs))
	}

	// The line has to name the reason: which of "no socket", "permission denied"
	// and "field rejected" it is decides what an operator does next, and a bare
	// "anchor failed" would send them back to guessing.
	if got := stderr.String(); !strings.Contains(got, reason.Error()) {
		t.Errorf("stderr = %q, want it to name the wrapped reason %q", got, reason.Error())
	}
}

// 11. The report is made once per run, however many operations fail to anchor.
//
// Every operation anchors, so a first-ever run is roughly 20,000 of them, and a
// permanently broken socket would otherwise put 20,000 identical lines on stderr
// and bury the per-operation messages an operator is reading it for. The FIRST
// failure is the diagnostic, so what this asserts is that it gets through and
// that the rest do not repeat it.
func TestAnchorFailure_IsReportedOnceNotPerOperation(t *testing.T) {
	log, _ := newTestLog(t)
	ser := mustSerial(t, "emulator-5554")

	var stderr strings.Builder
	fake := &fakeExtBusiness{}
	ext := NewExtension(log, 1, "x", func(*audit.Log) error { return errors.New("socket unreachable") }, &stderr)(fake)

	for range 5 {
		if _, err := ext.Probe(t.Context(), ser); err != nil {
			t.Fatalf("Probe: unexpected error: %v", err)
		}
	}

	if got := strings.Count(stderr.String(), "socket unreachable"); got != 1 {
		t.Errorf("stderr reported the anchor failure %d times over 5 failing anchors, want exactly 1:\n%s", got, stderr.String())
	}
}

// 12. A successful anchor says nothing at all. stderr is a diagnostic stream,
// and a line per operation on a healthy host would train an operator to ignore
// the one line that matters.
func TestAnchorSuccess_ReportsNothing(t *testing.T) {
	log, _ := newTestLog(t)
	ser := mustSerial(t, "emulator-5554")

	var stderr strings.Builder
	anchored := 0

	fake := &fakeExtBusiness{}
	ext := NewExtension(log, 1, "x", func(l *audit.Log) error {
		anchored++

		if l == nil {
			t.Error("the extension anchored a nil log")
		}

		return nil
	}, &stderr)(fake)

	if _, err := ext.Probe(t.Context(), ser); err != nil {
		t.Fatalf("Probe: unexpected error: %v", err)
	}

	if anchored != 1 {
		t.Errorf("the log was anchored %d times for one operation, want 1", anchored)
	}

	if stderr.String() != "" {
		t.Errorf("stderr = %q, want nothing for a successful anchor", stderr.String())
	}
}

// 13. Nothing an anchor failure produces may reach a writer other than the one
// stderr the extension was given — and a nil one is discarded rather than fatal.
func TestAnchorFailure_WithNoWriterIsStillHarmless(t *testing.T) {
	log, path := newTestLog(t)
	ser := mustSerial(t, "emulator-5554")

	fake := &fakeExtBusiness{}
	ext := NewExtension(log, 1, "x", func(*audit.Log) error { return errors.New("nowhere to report this") }, nil)(fake)

	if _, err := ext.Probe(t.Context(), ser); err != nil {
		t.Fatalf("Probe: unexpected error with a nil report writer: %v", err)
	}

	if recs := readRecords(t, path); len(recs) != 1 {
		t.Fatalf("got %d records, want 1", len(recs))
	}
}

// 14. Extension ordering: wrap a fake with this extension via
// devicebus.NewBusiness and assert records are still written when it is one
// of several extensions.
type passThroughExt struct {
	bus   devicebus.ExtBusiness
	calls *[]string
	name  string
}

func (e *passThroughExt) Probe(ctx context.Context, s serial.Serial) (devicebus.Device, error) {
	*e.calls = append(*e.calls, e.name)

	return e.bus.Probe(ctx, s)
}

func (e *passThroughExt) List(ctx context.Context, in devicebus.ListInput, fn func(devicebus.FileRecord) error) (devicebus.ListSummary, error) {
	*e.calls = append(*e.calls, e.name)

	return e.bus.List(ctx, in, fn)
}

func (e *passThroughExt) Fetch(ctx context.Context, p devicepath.AuthorizedPath, w io.Writer, before func(devicebus.FetchInfo) error) (devicebus.FetchResult, error) {
	*e.calls = append(*e.calls, e.name)

	return e.bus.Fetch(ctx, p, w, before)
}

func newPassThroughExt(name string, calls *[]string) devicebus.Extension {
	return func(bus devicebus.ExtBusiness) devicebus.ExtBusiness {
		return &passThroughExt{bus: bus, calls: calls, name: name}
	}
}

// fakeStorer is a minimal devicebus.Storer test double, used only to exercise
// devicebus.NewBusiness's own wiring in TestExtension_WorksAmongSeveralExtensions.
type fakeStorer struct {
	vol devicepath.Volume
}

func (f *fakeStorer) Probe(_ context.Context, s serial.Serial) (devicebus.Device, error) {
	return devicebus.Device{Serial: s}, nil
}

func (f *fakeStorer) ResolveVolume(context.Context) (devicepath.Volume, error) {
	return f.vol, nil
}

func (f *fakeStorer) List(_ context.Context, _ devicebus.ListInput, _ devicepath.Volume, _ func(devicebus.FileRecord) error) (devicebus.ListSummary, error) {
	return devicebus.ListSummary{}, nil
}

func (f *fakeStorer) Fetch(_ context.Context, _ devicepath.AuthorizedPath, _ devicepath.Volume, _ io.Writer, _ func(devicebus.FetchInfo) error) (devicebus.FetchResult, error) {
	return devicebus.FetchResult{}, nil
}

func TestExtension_WorksAmongSeveralExtensions(t *testing.T) {
	log, path := newTestLog(t)
	vol := mustVolume(t, 190, 1)
	ser := mustSerial(t, "emulator-5554")

	store := &fakeStorer{vol: vol}

	var calls []string
	before := newPassThroughExt("before", &calls)
	auditExt := newExtension(log, 7, "asserted")
	after := newPassThroughExt("after", &calls)

	biz := devicebus.NewBusiness(store, before, auditExt, after)

	if _, err := biz.Probe(t.Context(), ser); err != nil {
		t.Fatalf("Probe: unexpected error: %v", err)
	}

	if want := []string{"before", "after"}; !slices.Equal(calls, want) {
		t.Errorf("call order = %v, want %v", calls, want)
	}

	recs := readRecords(t, path)
	if len(recs) != 1 {
		t.Fatalf("got %d records, want 1", len(recs))
	}
	if recs[0].Op != "probe" || recs[0].CallerUID != 7 || recs[0].ClientAsserted != "asserted" {
		t.Errorf("record = %+v, want op=probe caller_uid=7 client_asserted=asserted", recs[0])
	}
}

// Bonus: unit-test the Result-code mapping directly, since it is the one
// piece of logic in this package with no equivalent test elsewhere.
func TestResultCode_MapsKnownSentinelsAndDefaultsToInternal(t *testing.T) {
	tests := []struct {
		name string
		err  error
		want string
	}{
		{"nil", nil, "ok"},
		{"path denied", devicepath.ErrPathDenied, "path_denied"},
		{"volume unresolved", devicepath.ErrVolumeUnresolved, "volume_unresolved"},
		{"unrecognised", errors.New("something else"), "internal"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := resultCode(tt.err); got != tt.want {
				t.Errorf("resultCode(%v) = %q, want %q", tt.err, got, tt.want)
			}
		})
	}
}
