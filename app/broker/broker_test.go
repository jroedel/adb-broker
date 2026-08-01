package broker

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"io"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/jroedel/adb-broker/business/domain/device/devicebus"
	"github.com/jroedel/adb-broker/business/types/devicepath"
	"github.com/jroedel/adb-broker/business/types/errcode"
	"github.com/jroedel/adb-broker/business/types/filekind"
	"github.com/jroedel/adb-broker/business/types/mtime"
	"github.com/jroedel/adb-broker/business/types/serial"
	"github.com/jroedel/adb-broker/foundation/audit"
)

// Every test here drives the real Main with a fake devicebus.Storer, so what is asserted is
// the bytes a consumer would actually read. No test needs a phone, an adb server or root, and
// no test touches /var/log/adb-broker: the audit log lives in t.TempDir() for the duration of
// one invocation.
//
// These tests deliberately do not run in parallel. They swap unexported package seams
// (openAuditLog, newStorer, stdinReader), and a parallel test that swapped one of them back
// would be testing a different binary than the one it asserted on.

// The example values from the interface specification, used so the assertions below are
// comparisons against the document rather than against this implementation's own output.
const (
	exampleSerial  = "EXAMPLESERIAL1"
	exampleServer  = "1.0.41"
	examplePath    = "/sdcard/DCIM/Camera/IMG_0182.JPG"
	examplePathB64 = "L3NkY2FyZC9EQ0lNL0NhbWVyYS9JTUdfMDE4Mi5KUEc="
	exampleSize    = 103159
	exampleMtime   = 1709828653

	// emptyInputSHA256 is SHA-256 of no bytes at all. A zero-byte file transfers successfully
	// with this digest, and there is one on the target device.
	emptyInputSHA256 = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
)

// codedError is an error carrying a taxonomy classification, as every error from the layers
// below this one does. Tests use it to prove the App layer reports the code the failing layer
// decided on rather than one of its own.
type codedError struct {
	code errcode.Code
	msg  string
}

func (e codedError) Error() string      { return e.msg }
func (e codedError) Code() errcode.Code { return e.code }
func newCodedError(c errcode.Code) error {
	return codedError{code: c, msg: string(c) + " from the fake"}
}

// fakeStore is a devicebus.Storer that answers from values a test set, and records that it was
// reached at all.
type fakeStore struct {
	// brokerVersion is whatever the package passed to newStorer, echoed back on Device so a
	// probe response can be asserted against the binary's own version.
	brokerVersion string

	// touched records that some method of this store ran. Every method sets it FIRST, before
	// any early return, because the tests that matter most are the ones asserting a phone was
	// never contacted.
	touched bool

	state         string
	serverVersion string
	probeErr      error
	volumeErr     error

	// attachedDevices is what this store reports as the number of attached devices, which a
	// real Storer counts from its transport's device list. It is settable so a probe test
	// can prove the App layer reports the STORE's number rather than deriving one of its own
	// — deriving it is not possible here, and a response that quietly said 1 because one
	// device was probed would be wrong on exactly the machine the member exists for.
	attachedDevices int

	records    []devicebus.FileRecord
	pathErrors []devicebus.PathError
	refused    int
	listErr    error
	listRoot   string

	payload   []byte
	fetchErr  error
	fetchPath string
}

func (f *fakeStore) Probe(_ context.Context, s serial.Serial) (devicebus.Device, error) {
	f.touched = true

	if f.probeErr != nil {
		return devicebus.Device{}, f.probeErr
	}

	named := exampleSerial
	if !s.IsZero() {
		named = s.String()
	}

	return devicebus.Device{
		Serial:          serial.MustParseSerial(named),
		State:           f.state,
		BrokerVersion:   f.brokerVersion,
		ServerVersion:   f.serverVersion,
		AttachedDevices: f.attachedDevices,
	}, nil
}

func (f *fakeStore) ResolveVolume(_ context.Context) (devicepath.Volume, error) {
	f.touched = true

	if f.volumeErr != nil {
		return devicepath.Volume{}, f.volumeErr
	}

	// The measured shape of the real device's shared storage: dev=190, a directory.
	return devicepath.ResolveVolume(func(string) (int64, int64, uint32, error) {
		return 190, 4812, 0o040755, nil
	})
}

func (f *fakeStore) List(_ context.Context, in devicebus.ListInput, _ devicepath.Volume, fn func(devicebus.FileRecord) error) (devicebus.ListSummary, error) {
	f.touched = true
	f.listRoot = in.Root.String()

	summary := devicebus.ListSummary{RefusedEntries: f.refused, Errors: f.pathErrors}

	for _, rec := range f.records {
		if err := fn(rec); err != nil {
			return summary, err
		}

		summary.Files++
	}

	return summary, f.listErr
}

func (f *fakeStore) Fetch(_ context.Context, p devicepath.AuthorizedPath, _ devicepath.Volume, w io.Writer, before func(devicebus.FetchInfo) error) (devicebus.FetchResult, error) {
	f.touched = true
	f.fetchPath = p.String()

	if f.fetchErr != nil {
		return devicebus.FetchResult{}, f.fetchErr
	}

	digest := sha256.Sum256(f.payload)

	// A real Storer stats the file and hands the size over before reading a byte, which
	// is how the caller frames the stream without buffering it. A fake that skipped this
	// would let a regression in the framing pass unnoticed, so it mirrors the real order:
	// size first, then bytes, and a refusal here transfers nothing.
	if before != nil {
		if err := before(devicebus.FetchInfo{Size: int64(len(f.payload))}); err != nil {
			return devicebus.FetchResult{}, err
		}
	}

	n, err := w.Write(f.payload)
	if err != nil {
		return devicebus.FetchResult{}, err
	}

	return devicebus.FetchResult{
		Bytes:  int64(n),
		SHA256: hex.EncodeToString(digest[:]),
		Serial: serial.MustParseSerial(exampleSerial),
	}, nil
}

// newFakeStore returns a store that answers as the measured device does, with one example
// file and nothing wrong.
func newFakeStore() *fakeStore {
	return &fakeStore{
		state:         "device",
		serverVersion: exampleServer,
		// One phone, which is what the measured device session looked like and the case a
		// consumer may omit --serial in.
		attachedDevices: 1,
		records:         []devicebus.FileRecord{fileRecord(examplePath, exampleSize, exampleMtime)},
		payload:         bytes.Repeat([]byte{'x'}, exampleSize),
	}
}

// fileRecord builds one Business FileRecord for a path the allowlist permits.
func fileRecord(path string, size, sec int64) devicebus.FileRecord {
	return devicebus.FileRecord{
		Path:  devicepath.MustParseAuthorizedPath(path),
		Size:  size,
		Mtime: mtime.ParseMtime(sec),
		Kind:  filekind.KindRegular,
	}
}

// result is one in-process invocation's observable output.
type result struct {
	exit   int
	stdout string
	stderr string
}

// swap replaces one package seam for the duration of a test.
func swap[T any](t *testing.T, seam *T, value T) {
	t.Helper()

	old := *seam
	*seam = value

	t.Cleanup(func() { *seam = old })
}

// TestMain keeps this package's tests off the host's real journal.
//
// Every recorded operation anchors, and until the anchor became a seam that meant every
// invocation these tests drive published a live datagram to /run/systemd/journal/socket:
// 2,649 entries stamped _EXE=…/broker.test are permanently in this host's journal, each
// claiming a sequence number and chain head for an audit log in a t.TempDir() that no longer
// exists. Journal entries cannot be removed, so all of them are noise a real verify has to
// discard forever — and the volume was what made the case for closing the hole.
//
// It is done here, once, rather than in each test's setup, so a test added later cannot
// forget: publishing to the host is not something a test opts out of, it is something a test
// must deliberately opt into by replacing this again. captureAnchors is how to opt into
// OBSERVING one without publishing it.
func TestMain(m *testing.M) {
	publishAnchor = func(*audit.Log) error { return nil }

	os.Exit(m.Run())
}

// capturedAnchor is what one anchor would have published: the three values audit.AnchorTail
// reads off the live log.
type capturedAnchor struct {
	seq  uint64
	hash string
	log  string
}

// captureAnchors records every anchor an invocation publishes instead of sending it.
//
// It reassembles the anchor from the log the same way audit.AnchorTail does, which is
// deliberate and limited: what these tests assert is WHETHER a code path anchors and at which
// chain state, not the wire form. The wire form is asserted byte for byte against a real
// datagram in foundation/audit's own tests, which is the only place that can.
func captureAnchors(t *testing.T) *[]capturedAnchor {
	t.Helper()

	var published []capturedAnchor

	swap(t, &publishAnchor, func(l *audit.Log) error {
		head := l.Head()
		published = append(published, capturedAnchor{seq: l.Seq(), hash: hex.EncodeToString(head[:]), log: l.Path()})

		return nil
	})

	return &published
}

// newAuditLog creates an empty audit log in a temporary directory and returns its path.
//
// It is created here rather than by the broker on purpose, and the purpose changed on
// 2026-08-01. It used to be the only way to get one, since audit.Open does not pass O_CREATE
// and only the installer could create a log. The broker creates its own now, so what this
// helper provides is the EXISTING-log case specifically — see firstrun_test.go for the other
// one. An empty file is a valid chain of length zero.
func newAuditLog(t *testing.T) string {
	t.Helper()

	path := filepath.Join(t.TempDir(), "audit.log")
	if err := os.WriteFile(path, nil, 0o600); err != nil {
		t.Fatalf("create the test audit log: %v", err)
	}

	return path
}

// run drives Main with a fresh temporary audit log and the given store.
func run(t *testing.T, store *fakeStore, args ...string) result {
	t.Helper()

	return runWithLog(t, newAuditLog(t), store, args...)
}

// runWithLog drives Main against a named audit log, so a test can inspect what was recorded or
// point the fail-closed check at a path that cannot be opened.
func runWithLog(t *testing.T, logPath string, store *fakeStore, args ...string) result {
	t.Helper()

	swap(t, &openAuditLog, func() (*audit.Log, bool, error) {
		// audit.Open, NOT the open-or-create Main uses: these helpers hand out paths that
		// must FAIL to open, and a creating seam would answer them by making a fresh log.
		log, err := audit.Open(logPath)

		return log, false, err
	})

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

// lines splits stdout into its protocol lines, asserting that it ends with exactly one
// newline and contains no blank line — a stray newline is a protocol violation, not
// whitespace.
func lines(t *testing.T, stdout string) []string {
	t.Helper()

	if stdout == "" {
		t.Fatal("stdout is empty; every subcommand writes at least one object")
	}

	if !strings.HasSuffix(stdout, "\n") {
		t.Fatalf("stdout does not end with a newline: %q", stdout)
	}

	out := strings.Split(strings.TrimSuffix(stdout, "\n"), "\n")
	for i, line := range out {
		if strings.TrimSpace(line) == "" {
			t.Fatalf("stdout line %d is blank; stdout carries the protocol and nothing else", i+1)
		}
	}

	return out
}

// decode parses one protocol line into a map, so a test can assert that a member is ABSENT,
// which a typed struct cannot express.
func decode(t *testing.T, line string) map[string]any {
	t.Helper()

	var got map[string]any
	if err := json.Unmarshal([]byte(line), &got); err != nil {
		t.Fatalf("decode %q: %v", line, err)
	}

	return got
}

// 1. probe emits exactly one object, with proto 1 and the transport's state token verbatim.

// exampleAllowlist is the allowlist member as a consumer reads it: the six compiled roots,
// sorted, as a JSON array.
//
// It is written out literally rather than built from devicepath.Roots so that a change to the
// compiled allowlist fails here. The list is part of the stdout contract now, so it should not
// be possible to alter what a consumer is told this binary can reach without editing a test
// that says so.
const exampleAllowlist = `["/sdcard/DCIM","/sdcard/Download","/sdcard/Movies","/sdcard/Music","/sdcard/Pictures","/sdcard/Recordings"]`

func TestProbeEmitsOneObjectMatchingTheSpecifiedShape(t *testing.T) {
	store := newFakeStore()

	got := run(t, store, "probe")

	want := fmt.Sprintf(`{"proto":1,"status":"ok","serial":%q,"state":"device","broker":%q,"adb":%q,"attached_devices":1,"allowlist":%s}`+"\n",
		exampleSerial, version, exampleServer, exampleAllowlist)

	if got.stdout != want {
		t.Errorf("stdout\n got: %q\nwant: %q", got.stdout, want)
	}

	if got.exit != 0 {
		t.Errorf("exit = %d, want 0", got.exit)
	}
}

// A consumer cannot change the allowlist — it is compiled in — so the only thing reporting it
// can do is turn a per-source runtime refusal into a startup check. That only works if EVERY
// root is reported: a consumer that validated its sources against five of six would reject a
// source this binary would have served.
func TestProbeReportsEveryCompiledAllowlistRootInSortedOrder(t *testing.T) {
	got := run(t, newFakeStore(), "probe")

	var res struct {
		Allowlist []string `json:"allowlist"`
	}
	if err := json.Unmarshal([]byte(lines(t, got.stdout)[0]), &res); err != nil {
		t.Fatalf("decode the probe response: %v", err)
	}

	// devicepath.Roots is the allowlist in force and returns it sorted. Comparing against it
	// rather than against a list retyped here is the point: the response must be the same
	// allowlist the path parser enforces, not a second copy of it that could drift.
	want := devicepath.Roots()

	if !slices.Equal(res.Allowlist, want) {
		t.Fatalf("allowlist = %v, want %v", res.Allowlist, want)
	}

	if !slices.IsSorted(res.Allowlist) {
		t.Errorf("allowlist = %v, want it sorted", res.Allowlist)
	}

	// Every root reported must be one this binary would actually accept a path under. A root
	// on the wire that ParseAuthorizedPath refuses would be a consumer's instruction to
	// configure a source that then fails with path_denied.
	for _, root := range res.Allowlist {
		if _, err := devicepath.ParseAuthorizedPath(root); err != nil {
			t.Errorf("reported root %q is not one this binary accepts: %v", root, err)
		}
	}
}

// The count is the store's, reported unchanged. The two failure modes it exists to prevent are
// both "1 when it should not be": a consumer that sees 1 omits --serial on every fetch, and on
// a machine with two phones that means archiving from whichever one answered.
func TestProbeReportsTheAttachedDeviceCountTheStoreReported(t *testing.T) {
	for _, tc := range []struct {
		name  string
		args  []string
		count int
	}{
		{name: "one phone", args: []string{"probe"}, count: 1},
		{name: "three phones", args: []string{"probe"}, count: 3},

		// Naming a serial selects one device; it does not change how many are attached. A
		// response saying 1 here would tell a consumer that omitting --serial is safe, which
		// is precisely what it is not.
		{name: "a named serial does not narrow the count", args: []string{"probe", "--serial", exampleSerial}, count: 2},
	} {
		store := newFakeStore()
		store.attachedDevices = tc.count

		got := run(t, store, tc.args...)

		res := decode(t, lines(t, got.stdout)[0])

		// JSON numbers decode as float64; compare as a number rather than reformatting.
		if n, ok := res["attached_devices"].(float64); !ok || int(n) != tc.count {
			t.Errorf("%s: attached_devices = %v, want %d", tc.name, res["attached_devices"], tc.count)
		}
	}
}

func TestProbeReportsTheStateTokenVerbatim(t *testing.T) {
	// A state other than "device" is fatal to the consumer, which needs the RAW token to say
	// why. Nothing in the App layer maps it, so a token this binary has never heard of still
	// reaches the consumer intact.
	for _, state := range []string{"device", "unauthorized", "offline", "bootloader", "sideload", "recovery"} {
		store := newFakeStore()
		store.state = state

		got := run(t, store, "probe")

		if want := fmt.Sprintf(`"state":%q`, state); !strings.Contains(got.stdout, want) {
			t.Errorf("state %q: stdout %q does not contain %s", state, got.stdout, want)
		}
	}
}

func TestProbeResponseNeverCarriesTheVolume(t *testing.T) {
	// The pinned volume goes to the audit log and nowhere else. There is no App-side
	// representation of it, and this asserts the negative on the bytes.
	got := run(t, newFakeStore(), "probe")

	for _, forbidden := range []string{"volume", "dev", "ino"} {
		if _, ok := decode(t, lines(t, got.stdout)[0])[forbidden]; ok {
			t.Errorf("probe response carries a %q member", forbidden)
		}
	}
}

// 2. list emits NDJSON then exactly one summary line, and the summary has no path key.

func TestListEmitsRecordsThenExactlyOneSummaryWithoutAPathMember(t *testing.T) {
	store := newFakeStore()
	store.records = []devicebus.FileRecord{
		fileRecord(examplePath, exampleSize, exampleMtime),
		fileRecord("/sdcard/DCIM/Camera/IMG_0183.JPG", 42, 1709828654),
	}

	got := run(t, store, "list", "--root", "/sdcard/DCIM/Camera")

	out := lines(t, got.stdout)
	if len(out) != 3 {
		t.Fatalf("got %d stdout lines, want 2 records and 1 summary:\n%s", len(out), got.stdout)
	}

	for i, line := range out[:2] {
		rec := decode(t, line)
		if _, ok := rec["path"]; !ok {
			t.Errorf("record %d has no path member: %s", i+1, line)
		}

		if _, ok := rec["proto"]; ok {
			t.Errorf("record %d carries a proto member, which belongs on the summary: %s", i+1, line)
		}
	}

	summary := decode(t, out[2])
	if _, ok := summary["path"]; ok {
		t.Errorf("the summary carries a path member, which is the one thing that distinguishes it from a record: %s", out[2])
	}

	if summary["status"] != statusOK || summary["files"] != float64(2) || summary["proto"] != float64(1) {
		t.Errorf("summary = %s, want proto 1, status ok and files 2", out[2])
	}

	// files is contract rather than incidental: it is exactly the number of records that
	// preceded the summary on this stream, which is what makes it usable as an integrity check
	// by a consumer that counted them itself. It was unspecified until the first consumer
	// checked it anyway and had to treat a disagreement as unactionable.
	if want := float64(len(out) - 1); summary["files"] != want {
		t.Errorf("files = %v, want %v, the number of records that preceded the summary", summary["files"], want)
	}

	if got.exit != 0 {
		t.Errorf("exit = %d, want 0", got.exit)
	}
}

func TestListRecordIsByteExact(t *testing.T) {
	got := run(t, newFakeStore(), "list", "--root", "/sdcard/DCIM/Camera")

	want := fmt.Sprintf(`{"path":%q,"path_b64":%q,"size":%d,"mtime":%d}`+"\n",
		examplePath, examplePathB64, exampleSize, exampleMtime)

	if first := lines(t, got.stdout)[0] + "\n"; first != want {
		t.Errorf("record\n got: %q\nwant: %q", first, want)
	}
}

// 3. list with per-path errors is partial and still exits 0.

func TestListWithPerPathErrorsIsPartialAndExitsZero(t *testing.T) {
	store := newFakeStore()
	store.pathErrors = []devicebus.PathError{{
		Path: devicepath.MustParseAuthorizedPath("/sdcard/DCIM/Camera/locked"),
		Code: errcode.CodePermissionDenied,
	}}

	got := run(t, store, "list", "--root", "/sdcard/DCIM/Camera")

	out := lines(t, got.stdout)
	want := `{"proto":1,"status":"partial","files":1,"errors":[{"code":"permission_denied","path":"/sdcard/DCIM/Camera/locked","path_b64":"L3NkY2FyZC9EQ0lNL0NhbWVyYS9sb2NrZWQ="}]}`

	if out[len(out)-1] != want {
		t.Errorf("summary\n got: %s\nwant: %s", out[len(out)-1], want)
	}

	if got.exit != 0 {
		t.Errorf("exit = %d, want 0: a partial listing produced usable output", got.exit)
	}
}

func TestListRefusedEntriesDoNotMakeAListingPartial(t *testing.T) {
	// Symlinks, sockets and off-volume entries are confinement decisions about entries that
	// were never going to be served. Reporting them as failures would have a consumer warning
	// about a phone behaving exactly as designed.
	store := newFakeStore()
	store.refused = 7

	got := run(t, store, "list", "--root", "/sdcard/DCIM/Camera")

	out := lines(t, got.stdout)
	if summary := decode(t, out[len(out)-1]); summary["status"] != statusOK {
		t.Errorf("status = %v with %d refused entries and no errors, want ok", summary["status"], store.refused)
	}
}

// 4. path_b64 is authoritative: a name that is not valid UTF-8 round-trips through it while
// path is the lossy rendering.

func TestPathB64RoundTripsAPathThatIsNotValidUTF8(t *testing.T) {
	// A real Android filename is a byte string. This one is not valid UTF-8 anywhere.
	rawPath := "/sdcard/DCIM/Camera/IMG_\xff\xfe.JPG"

	store := newFakeStore()
	store.records = []devicebus.FileRecord{fileRecord(rawPath, 1, 2)}

	got := run(t, store, "list", "--root", "/sdcard/DCIM/Camera")

	rec := decode(t, lines(t, got.stdout)[0])

	encoded, ok := rec["path_b64"].(string)
	if !ok {
		t.Fatalf("record has no path_b64: %v", rec)
	}

	decoded, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil {
		t.Fatalf("decode path_b64 %q: %v", encoded, err)
	}

	if string(decoded) != rawPath {
		t.Errorf("path_b64 decodes to %q, want the raw device bytes %q", decoded, rawPath)
	}

	lossy, ok := rec["path"].(string)
	if !ok {
		t.Fatalf("record has no path: %v", rec)
	}

	if lossy == rawPath {
		t.Error("path returned the raw bytes; a JSON string cannot carry them, so it must be the lossy rendering")
	}

	if !strings.Contains(lossy, "\uFFFD") {
		t.Errorf("path = %q, want the invalid bytes replaced with U+FFFD", lossy)
	}

	// And the coercion happened exactly once: what reached stdout is already valid UTF-8, so
	// nothing downstream had to repair it.
	if !strings.HasPrefix(lossy, "/sdcard/DCIM/Camera/IMG_") || !strings.HasSuffix(lossy, ".JPG") {
		t.Errorf("path = %q, want the readable parts of the name preserved", lossy)
	}
}

// 5. No record ever carries mtime_nsec.

func TestNoObjectCarriesMtimeNsec(t *testing.T) {
	// The transport carries whole seconds only, so the member can never be populated. Asserted
	// on the raw bytes of every subcommand's output, because a member that appears once as
	// null is a member a consumer will try to read.
	for _, args := range [][]string{{"probe"}, {"list", "--root", "/sdcard/DCIM/Camera"}, {"fetch", "--path", examplePath}} {
		store := newFakeStore()
		store.records = []devicebus.FileRecord{
			fileRecord(examplePath, exampleSize, exampleMtime),
			fileRecord("/sdcard/DCIM/Camera/IMG_0183.JPG", 0, 0),
		}

		got := run(t, store, args...)

		if strings.Contains(got.stdout, "mtime_nsec") {
			t.Errorf("%v: stdout carries mtime_nsec:\n%s", args, got.stdout)
		}
	}
}

func TestTheRequestedPathReachesTheStoreUnchanged(t *testing.T) {
	// The path the store is asked for is the path the caller named, byte for byte. A
	// coerced-then-fetched path would be a file that does not exist, and the audit record
	// would name one that was never read.
	raw := "/sdcard/DCIM/Camera/IMG_\xff.JPG"

	store := newFakeStore()
	store.records = []devicebus.FileRecord{fileRecord(raw, 1, 1)}

	if got := run(t, store, "list", "--root", "/sdcard/DCIM"); got.exit != 0 {
		t.Fatalf("list: exit = %d, stderr %q", got.exit, got.stderr)
	}

	if store.listRoot != "/sdcard/DCIM" {
		t.Errorf("the store was asked to list %q, want /sdcard/DCIM", store.listRoot)
	}

	fetch := newFakeStore()
	if got := run(t, fetch, "fetch", "--path", raw); got.exit != 0 {
		t.Fatalf("fetch: exit = %d, stderr %q", got.exit, got.stderr)
	}

	if fetch.fetchPath != raw {
		t.Errorf("the store was asked to fetch %q, want the raw bytes %q", fetch.fetchPath, raw)
	}
}

// 6. fetch emits a header, exactly size bytes, then a trailer, in that order.

func TestFetchEmitsHeaderPayloadTrailerInThatOrder(t *testing.T) {
	store := newFakeStore()

	got := run(t, store, "fetch", "--path", examplePath)

	digest := sha256.Sum256(store.payload)
	want := fmt.Sprintf(`{"proto":1,"op":"fetch","size":%d}`+"\n", exampleSize) +
		string(store.payload) +
		fmt.Sprintf(`{"status":"ok","bytes":%d,"sha256":%q}`+"\n", exampleSize, hex.EncodeToString(digest[:]))

	if got.stdout != want {
		t.Errorf("stdout differs from the specified framing\n got %d bytes\nwant %d bytes", len(got.stdout), len(want))
	}

	// Read it the way a consumer does: parse the header, take exactly size bytes, then REQUIRE
	// a trailer.
	header, rest, ok := strings.Cut(got.stdout, "\n")
	if !ok {
		t.Fatal("no header line")
	}

	var h FetchHeader
	if err := json.Unmarshal([]byte(header), &h); err != nil {
		t.Fatalf("decode the header %q: %v", header, err)
	}

	if int64(len(rest)) < h.Size {
		t.Fatalf("header claims %d bytes and only %d follow", h.Size, len(rest))
	}

	payload, trailer := rest[:h.Size], rest[h.Size:]
	if payload != string(store.payload) {
		t.Error("the bytes between the two lines are not the file's bytes verbatim")
	}

	var tr FetchTrailer
	if err := json.Unmarshal([]byte(strings.TrimSuffix(trailer, "\n")), &tr); err != nil {
		t.Fatalf("decode the trailer %q: %v", trailer, err)
	}

	if tr.Status != statusOK || tr.Bytes != h.Size {
		t.Errorf("trailer = %+v, want status ok and %d bytes", tr, h.Size)
	}

	if got.exit != 0 {
		t.Errorf("exit = %d, want 0", got.exit)
	}
}

func TestFetchWritesNothingToTheLocalFilesystem(t *testing.T) {
	// The consumer creates its own staging file, with O_EXCL, which is where the
	// refuse-to-overwrite guarantee lives. The audit log is the sole exception.
	dir := t.TempDir()
	logPath := filepath.Join(dir, "audit.log")

	if err := os.WriteFile(logPath, nil, 0o600); err != nil {
		t.Fatalf("create the test audit log: %v", err)
	}

	before := entries(t, dir)

	if got := runWithLog(t, logPath, newFakeStore(), "fetch", "--path", examplePath); got.exit != 0 {
		t.Fatalf("exit = %d, stderr %q", got.exit, got.stderr)
	}

	if after := entries(t, dir); len(after) != len(before) {
		t.Errorf("the transfer created %d file(s) beside the audit log: %v", len(after)-len(before), after)
	}
}

// entries lists the names in a directory.
func entries(t *testing.T, dir string) []string {
	t.Helper()

	found, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("read %s: %v", dir, err)
	}

	names := make([]string, len(found))
	for i, e := range found {
		names[i] = e.Name()
	}

	return names
}

// 7. A zero-byte file: header with size 0, no bytes, and the empty-input digest.

func TestFetchOfAZeroByteFile(t *testing.T) {
	store := newFakeStore()
	store.payload = nil

	got := run(t, store, "fetch", "--path", examplePath)

	want := `{"proto":1,"op":"fetch","size":0}` + "\n" +
		`{"status":"ok","bytes":0,"sha256":"` + emptyInputSHA256 + `"}` + "\n"

	if got.stdout != want {
		t.Errorf("stdout\n got: %q\nwant: %q", got.stdout, want)
	}

	if got.exit != 0 {
		t.Errorf("exit = %d, want 0: an empty file is a successful transfer", got.exit)
	}
}

// 8. A denied --root fails with path_denied before any transport connection is attempted.

func TestADeniedRootIsRefusedBeforeTheDeviceIsTouched(t *testing.T) {
	denied := []string{
		"/data/data/com.android.providers.media", // outside the allowlist entirely
		"/sdcard",                                // a parent of a root, never widened to its children
		"/",                                      // likewise
		"/sdcard/Download-private",               // a string prefix of a root, not a segment prefix
		"/storage/emulated/0/DCIM",               // the same directory, an unaccepted spelling
		"/sdcard/DCIM/..",                        // resolves upward on the device
		"sdcard/DCIM",                            // relative; the device resolves it
		"/sdcard/DCIM/",                          // trailing slash: two spellings of one path
		"/sdcard/DCIM\x00/Camera",                // the device truncates at the NUL
	}

	for _, root := range denied {
		store := newFakeStore()

		got := run(t, store, "list", "--root", root)

		if store.touched {
			t.Errorf("--root %q reached the transport; the allowlist must be enforced before a phone is contacted", root)
		}

		res := decode(t, lines(t, got.stdout)[0])
		if res["code"] != errcode.CodePathDenied.String() {
			t.Errorf("--root %q: code = %v, want path_denied", root, res["code"])
		}

		if res["status"] != statusError {
			t.Errorf("--root %q: status = %v, want error", root, res["status"])
		}

		if got.exit == 0 {
			t.Errorf("--root %q: exit = 0, want non-zero", root)
		}
	}
}

func TestADeniedFetchPathIsRefusedBeforeTheDeviceIsTouched(t *testing.T) {
	store := newFakeStore()

	got := run(t, store, "fetch", "--path", "/data/misc/keystore/user_0/1000_USRPKEY_x")

	if store.touched {
		t.Error("a denied --path reached the transport")
	}

	res := decode(t, lines(t, got.stdout)[0])
	if res["code"] != errcode.CodePathDenied.String() {
		t.Errorf("code = %v, want path_denied", res["code"])
	}

	if res["path"] == nil {
		t.Error("the error object does not name the path that was refused")
	}
}

// 9. An unparseable --root produces a FieldErrors-derived error object, not a panic.

func TestUnparseableFlagsProduceAnErrorObjectRatherThanAPanic(t *testing.T) {
	for _, tc := range []struct {
		name string
		args []string
		code errcode.Code
	}{
		{"a path rule fired", []string{"list", "--root", "/sdcard/DCIM/./Camera"}, errcode.CodePathDenied},
		{"an empty root", []string{"list", "--root", ""}, errcode.CodeUnsupported},
		{"a missing root", []string{"list"}, errcode.CodeUnsupported},
		{"a bad serial", []string{"list", "--root", "/sdcard/DCIM", "--serial", "no spaces allowed"}, errcode.CodeUnsupported},
		{"a negative depth", []string{"list", "--root", "/sdcard/DCIM", "--max-depth", "-1"}, errcode.CodeUnsupported},
		{"an unknown flag", []string{"list", "--root", "/sdcard/DCIM", "--recurse"}, errcode.CodeUnsupported},
		{"a positional argument", []string{"list", "/sdcard/DCIM"}, errcode.CodeUnsupported},
		{"a missing path", []string{"fetch"}, errcode.CodeUnsupported},
	} {
		store := newFakeStore()

		got := run(t, store, tc.args...)

		if store.touched {
			t.Errorf("%s: reached the transport", tc.name)
		}

		out := lines(t, got.stdout)
		if len(out) != 1 {
			t.Errorf("%s: got %d stdout lines, want exactly one error object:\n%s", tc.name, len(out), got.stdout)

			continue
		}

		res := decode(t, out[0])
		if res["code"] != tc.code.String() {
			t.Errorf("%s: code = %v, want %s", tc.name, res["code"], tc.code)
		}

		if res["message"] == "" {
			t.Errorf("%s: the error object carries no message", tc.name)
		}

		if got.exit == 0 {
			t.Errorf("%s: exit = 0, want non-zero", tc.name)
		}
	}
}

func TestEveryInvalidFlagIsReportedInOneRun(t *testing.T) {
	// A caller that passed three bad flags should learn about three bad flags in one run,
	// rather than discovering them one invocation at a time.
	got := run(t, newFakeStore(), "list", "--root", "/etc/shadow", "--serial", "bad serial", "--client", "bad client")

	res := decode(t, lines(t, got.stdout)[0])

	message, _ := res["message"].(string)
	for _, field := range []string{"root:", "serial:", "client:"} {
		if !strings.Contains(message, field) {
			t.Errorf("message %q does not mention %s", message, field)
		}
	}
}

// 10. --client accepts a valid label and rejects the rest outright.

func TestClientLabelIsBoundedRatherThanSanitized(t *testing.T) {
	for _, tc := range []struct {
		name    string
		label   string
		accepts bool
	}{
		{"a plain name", "photos", true},
		{"every accepted class", "Photos_2026.v1-beta", true},
		{"exactly the limit", strings.Repeat("a", maxClientBytes), true},
		{"one byte over the limit", strings.Repeat("a", maxClientBytes+1), false},
		{"a space", "photos archiver", false},
		{"a slash", "photos/archiver", false},
		{"a newline", "photos\narchiver", false},
		{"a NUL", "photos\x00", false},
		{"shell metacharacters", "photos;rm -rf /", false},
		{"non-ASCII", "phötos", false},
	} {
		store := newFakeStore()

		got := run(t, store, "probe", "--client", tc.label)

		switch {
		case tc.accepts && got.exit != 0:
			t.Errorf("%s: exit = %d, want 0; stderr %q", tc.name, got.exit, got.stderr)

		case tc.accepts:
			continue

		case got.exit == 0:
			t.Errorf("%s: exit = 0, want the label rejected outright", tc.name)

		default:
			res := decode(t, lines(t, got.stdout)[0])
			if res["code"] != errcode.CodeUnsupported.String() {
				t.Errorf("%s: code = %v, want unsupported", tc.name, res["code"])
			}

			if store.touched {
				t.Errorf("%s: reached the transport with an unrecordable label", tc.name)
			}
		}
	}
}

func TestTheClientLabelReachesTheAuditRecordVerbatim(t *testing.T) {
	logPath := newAuditLog(t)

	if got := runWithLog(t, logPath, newFakeStore(), "probe", "--client", "photos"); got.exit != 0 {
		t.Fatalf("exit = %d, stderr %q", got.exit, got.stderr)
	}

	recorded, err := os.ReadFile(logPath)
	if err != nil {
		t.Fatalf("read the audit log: %v", err)
	}

	// client_asserted is caller-controlled and evidence of nothing, which is exactly why it is
	// recorded under a name nobody can mistake for a verified identity — alongside caller_uid,
	// which the kernel supplies.
	for _, want := range []string{`"client_asserted":"photos"`, fmt.Sprintf(`"caller_uid":%d`, os.Getuid()), `"op":"probe"`} {
		if !strings.Contains(string(recorded), want) {
			t.Errorf("the audit record does not contain %s:\n%s", want, recorded)
		}
	}
}

// 11. Fail closed: an unopenable audit log ends every subcommand, before any device contact.

func TestAnUnopenableAuditLogEndsEverySubcommand(t *testing.T) {
	missing := filepath.Join(t.TempDir(), "there-is-no-log-here", "audit.log")

	for _, args := range [][]string{
		{"probe"},
		{"list", "--root", "/sdcard/DCIM/Camera"},
		{"fetch", "--path", examplePath},

		// verify needs --log naming the missing path EXPLICITLY, and the other three
		// must not have it. verify is the one subcommand exempt from the fail-closed
		// check, so it never calls openAuditLog and the seam runWithLog swaps is invisible
		// to it: left to itself it resolves auditLogPath() and reads the log of whoever is
		// running the suite.
		//
		// Without the flag this case asserted nothing about this binary. It passed on any
		// machine where ~/.local/state/adb-broker/audit.log happened not to exist — which
		// is every machine that has never run a release build, including CI — and failed
		// the moment one did, reporting "partial" and exit 0 over the host's real log.
		// Found exactly that way on 2026-08-01, after running a downloaded v0.1.0-rc1
		// binary on the development host created one.
		{"verify", "--log", missing, "--anchors", "-"},
	} {
		store := newFakeStore()

		got := runWithLog(t, missing, store, args...)

		if got.exit == 0 {
			t.Errorf("%v: exit = 0, want non-zero when the operation could not have been recorded", args)
		}

		if store.touched {
			t.Errorf("%v: reached the transport with no audit log", args)
		}

		out := lines(t, got.stdout)
		if len(out) != 1 {
			t.Errorf("%v: got %d stdout lines, want exactly one error object:\n%s", args, len(out), got.stdout)

			continue
		}

		res := decode(t, out[0])
		if res["code"] != errcode.CodeAuditUnavailable.String() {
			t.Errorf("%v: code = %v, want audit_unavailable", args, res["code"])
		}

		if res["proto"] != float64(1) {
			t.Errorf("%v: the error object is not a well-formed protocol object: %s", args, out[0])
		}
	}
}

func TestAnAuditLogWhoseTailDoesNotVerifyEndsTheInvocation(t *testing.T) {
	logPath := newAuditLog(t)

	// One good record, then one byte of it changed. The chain covers the record's values, so
	// this is caught by recomputation at open time rather than by noticing an edit.
	if got := runWithLog(t, logPath, newFakeStore(), "probe"); got.exit != 0 {
		t.Fatalf("seed the log: exit = %d, stderr %q", got.exit, got.stderr)
	}

	recorded, err := os.ReadFile(logPath)
	if err != nil {
		t.Fatalf("read the audit log: %v", err)
	}

	tampered := strings.Replace(string(recorded), `"op":"probe"`, `"op":"prube"`, 1)
	if tampered == string(recorded) {
		t.Fatal("the seeded record does not contain the op member this test edits")
	}

	if err := os.WriteFile(logPath, []byte(tampered), 0o600); err != nil {
		t.Fatalf("rewrite the audit log: %v", err)
	}

	store := newFakeStore()

	got := runWithLog(t, logPath, store, "probe")

	if got.exit == 0 {
		t.Error("exit = 0 with an edited tail, want non-zero")
	}

	if store.touched {
		t.Error("reached the transport with an unverifiable audit log")
	}

	if res := decode(t, lines(t, got.stdout)[0]); res["code"] != errcode.CodeAuditUnavailable.String() {
		t.Errorf("code = %v, want audit_unavailable", res["code"])
	}
}

// 12. stdout carries protocol bytes and nothing else, for every subcommand, byte for byte.

func TestStdoutCarriesOnlyProtocolBytes(t *testing.T) {
	logPath := seededLog(t)

	for _, tc := range []struct {
		name string
		args []string
		want string
	}{
		{
			name: "probe",
			args: []string{"probe"},
			want: fmt.Sprintf(`{"proto":1,"status":"ok","serial":%q,"state":"device","broker":%q,"adb":%q,"attached_devices":1,"allowlist":%s}`+"\n",
				exampleSerial, version, exampleServer, exampleAllowlist),
		},
		{
			name: "list",
			args: []string{"list", "--root", "/sdcard/DCIM/Camera"},
			want: fmt.Sprintf(`{"path":%q,"path_b64":%q,"size":%d,"mtime":%d}`+"\n", examplePath, examplePathB64, exampleSize, exampleMtime) +
				`{"proto":1,"status":"ok","files":1,"errors":[]}` + "\n",
		},
		{
			name: "fetch",
			args: []string{"fetch", "--path", examplePath},
			want: `{"proto":1,"op":"fetch","size":3}` + "\n" + "abc" +
				`{"status":"ok","bytes":3,"sha256":"ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"}` + "\n",
		},
		{
			name: "an error",
			args: []string{"probe", "--serial", "not a serial"},
			want: `{"proto":1,"status":"error","code":"unsupported","message":"serial: serial: invalid device serial"}` + "\n",
		},
	} {
		store := newFakeStore()
		store.payload = []byte("abc")

		got := runWithLog(t, logPath, store, tc.args...)

		if got.stdout != tc.want {
			t.Errorf("%s: stdout\n got: %q\nwant: %q", tc.name, got.stdout, tc.want)
		}
	}
}

func TestNothingIsWrittenToStdoutForHelp(t *testing.T) {
	for _, args := range [][]string{{"--help"}, {"-h"}, {"help"}, {"probe", "--help"}, {"list", "-h"}} {
		got := run(t, newFakeStore(), args...)

		if got.stdout != "" {
			t.Errorf("%v: stdout = %q, want nothing: usage is for humans and goes to stderr", args, got.stdout)
		}

		if got.stderr == "" {
			t.Errorf("%v: stderr is empty, so nothing explained the subcommand", args)
		}

		if got.exit != 0 {
			t.Errorf("%v: exit = %d, want 0 for an answered help request", args, got.exit)
		}
	}
}

// 13. An unknown subcommand exits non-zero without emitting a malformed protocol object.

func TestAnUnknownSubcommandIsRefusedWithAWellFormedObject(t *testing.T) {
	for _, args := range [][]string{{}, {"pull"}, {"shell"}, {"--json"}, {"PROBE"}} {
		store := newFakeStore()

		got := run(t, store, args...)

		if got.exit == 0 {
			t.Errorf("%v: exit = 0, want non-zero", args)
		}

		if store.touched {
			t.Errorf("%v: reached the transport", args)
		}

		out := lines(t, got.stdout)
		if len(out) != 1 {
			t.Errorf("%v: got %d stdout lines, want exactly one error object:\n%s", args, len(out), got.stdout)

			continue
		}

		res := decode(t, out[0])
		if res["proto"] != float64(1) || res["status"] != statusError || res["code"] != errcode.CodeUnsupported.String() {
			t.Errorf("%v: %s is not a well-formed unsupported error object", args, out[0])
		}
	}
}

// 14. This package reads no environment variable, for any purpose.

func TestPackageSourceReadsNoEnvironment(t *testing.T) {
	// A setuid binary inherits the caller's environment and Go's runtime does not sanitize it,
	// so the rule is absolute rather than a matter of which variables look dangerous: no
	// ADB_*, no proxy variable, no path override, nothing.
	//
	// The check is over the parsed syntax tree rather than the file's text, so that the
	// comments explaining the rule cannot trip it — and so that an aliased import of os cannot
	// hide a call the way a substring search for "os.Getenv" would allow.
	forbidden := map[string]bool{"Getenv": true, "LookupEnv": true, "Environ": true, "Setenv": true, "Unsetenv": true}

	for _, dir := range []string{".", filepath.Join("..", "..", "cmd", "adb-broker")} {
		for _, path := range goSourceFiles(t, dir) {
			file, err := parser.ParseFile(token.NewFileSet(), path, nil, parser.SkipObjectResolution)
			if err != nil {
				t.Fatalf("parse %s: %v", path, err)
			}

			ast.Inspect(file, func(n ast.Node) bool {
				sel, ok := n.(*ast.SelectorExpr)
				if ok && forbidden[sel.Sel.Name] {
					t.Errorf("%s calls %s at %v; this binary must ignore its environment entirely",
						path, sel.Sel.Name, file.Name)
				}

				return true
			})
		}
	}
}

func TestPackageSourceNeverResolvesTheHomeDirectoryFromTheEnvironment(t *testing.T) {
	// The sibling above cannot catch either of these, and that is the reason this test is
	// separate rather than another entry in its map: the environment read happens inside the
	// standard library, not in this package's source, so a grep or an AST walk looking for
	// os.Getenv finds nothing to report.
	//
	// os.UserHomeDir reads $HOME outright. os/user is the subtle one, and this guard used to
	// forbid only user.Current while recommending user.LookupId as the safe alternative. That
	// recommendation was wrong, the code took it, and the guard then passed over a derivation
	// with the original defect still in it for as long as it stood.
	//
	// Under CGO_ENABLED=0 — the configuration a portable release artifact is built in — os/user
	// compiles lookup_stubs.go, whose current() attempts the passwd lookup and, when it fails,
	// builds a User from os.UserHomeDir() and $USER and returns it with a NIL error. LookupId is
	// no escape from that, because it short-circuits:
	//
	//	if u, err := Current(); err == nil && u.Uid == uid { return u, err }
	//
	// and this derivation asks for the current uid by construction, so the fast path always
	// fires. Reproduced against the published v0.1.0-rc1 artifact on 2026-08-01: an audit log
	// created under $HOME on a host whose uid the passwd file did not contain.
	//
	// So the guard is now on the IMPORT, not on a list of function names. Naming the safe
	// members of an unsafe package is what failed: it required this test to stay ahead of every
	// path through os/user, and it did not. The package is simply not used here — passwd.go
	// reads the database directly — and a guard on the import cannot be defeated by a member
	// nobody thought of.
	//
	// TestTheAuditLogPathIsThisUsersOwnAndIsNotTakenFromTheEnvironment asserts the produced
	// value, and TestAuditLogPathRefusesAUidWithNoPasswdEntry now asserts the failing case
	// directly, which became possible only once the lookup had a seam. This check does not
	// depend on where it runs.
	forbiddenImports := map[string]string{
		`"os/user"`: "os/user answers an unresolvable uid from $HOME under CGO_ENABLED=0, through Current AND through LookupId; passwd.go reads the database directly",
	}

	// os.UserHomeDir stays matched by selector name, exactly as the environment test above
	// matches, so that an aliased import of os cannot hide the call.
	forbiddenCalls := map[string]string{
		"UserHomeDir": "os.UserHomeDir reads $HOME, which must never decide where the audit log lives",
	}

	for _, dir := range []string{".", filepath.Join("..", "..", "cmd", "adb-broker")} {
		for _, path := range goSourceFiles(t, dir) {
			file, err := parser.ParseFile(token.NewFileSet(), path, nil, parser.SkipObjectResolution)
			if err != nil {
				t.Fatalf("parse %s: %v", path, err)
			}

			for _, imp := range file.Imports {
				if why, bad := forbiddenImports[imp.Path.Value]; bad {
					t.Errorf("%s imports %s: %s", path, imp.Path.Value, why)
				}
			}

			ast.Inspect(file, func(n ast.Node) bool {
				sel, ok := n.(*ast.SelectorExpr)
				if ok {
					if why, bad := forbiddenCalls[sel.Sel.Name]; bad {
						t.Errorf("%s calls %s: %s", path, sel.Sel.Name, why)
					}
				}

				return true
			})
		}
	}
}

// TestAuditLogPathRefusesAUidWithNoPasswdEntry is the test that could not be written before.
//
// The whole finding — twice over — was that the derivation answered an unresolvable account out
// of $HOME instead of failing. No behavioural test could see it, because the fallback is
// unreachable on any host whose uid resolves, and every host that runs this suite is such a
// host. So the rule was enforced statically, by a guard that named the wrong functions, and the
// defect survived a correction that was supposed to remove it.
//
// passwdFile is a seam for exactly this. Pointed at a database that does not contain the running
// uid, the derivation must return an error — with $HOME set to somewhere obvious, so that a
// regression produces a path under it rather than a subtle wrong answer.
func TestAuditLogPathRefusesAUidWithNoPasswdEntry(t *testing.T) {
	decoy := t.TempDir()
	t.Setenv("HOME", decoy)

	// Every line but this uid's, so the file is a realistic database rather than an empty one:
	// a parser that gave up on the first non-matching line would otherwise pass by accident.
	passwd := filepath.Join(t.TempDir(), "passwd")
	contents := "root:x:0:0:root:/root:/bin/bash\n" +
		"daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin\n" +
		"# a comment\n" +
		"+::::::\n" +
		"nobody:x:65534:65534:nobody:/nonexistent:/usr/sbin/nologin\n"

	if err := os.WriteFile(passwd, []byte(contents), 0o600); err != nil {
		t.Fatalf("write the fixture passwd: %v", err)
	}

	swap(t, &passwdFile, passwd)

	got, err := auditLogPath()

	switch {
	case err == nil:
		t.Fatalf("auditLogPath() = %q with no error; an unresolvable uid must be refused", got)

	case got != "":
		t.Errorf("auditLogPath() returned %q alongside its error; it must return no path at all", got)

	case strings.Contains(err.Error(), decoy):
		t.Errorf("the error names $HOME (%s), so the derivation reached the environment: %v", decoy, err)
	}
}

// TestAuditLogPathReadsTheHomeDirectoryOutOfThePasswdDatabase is the other half: the value must
// come from the database and from nothing else, including when $HOME disagrees with it.
func TestAuditLogPathReadsTheHomeDirectoryOutOfThePasswdDatabase(t *testing.T) {
	t.Setenv("HOME", filepath.Join(t.TempDir(), "not-the-real-home"))

	home := t.TempDir()
	passwd := filepath.Join(t.TempDir(), "passwd")
	contents := fmt.Sprintf("root:x:0:0:root:/root:/bin/bash\nsomebody:x:%d:%d::%s:/bin/sh\n",
		os.Getuid(), os.Getgid(), home)

	if err := os.WriteFile(passwd, []byte(contents), 0o600); err != nil {
		t.Fatalf("write the fixture passwd: %v", err)
	}

	swap(t, &passwdFile, passwd)

	got, err := auditLogPath()
	if err != nil {
		t.Fatalf("auditLogPath: %v", err)
	}

	want := filepath.Join(home, ".local", "state", "adb-broker", "audit.log")
	if got != want {
		t.Errorf("auditLogPath() = %q, want %q", got, want)
	}
}

// goSourceFiles lists the non-test Go files in dir.
func goSourceFiles(t *testing.T, dir string) []string {
	t.Helper()

	found, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("read %s: %v", dir, err)
	}

	var paths []string
	for _, e := range found {
		name := e.Name()
		if e.IsDir() || !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") {
			continue
		}

		paths = append(paths, filepath.Join(dir, name))
	}

	if len(paths) == 0 {
		t.Fatalf("no non-test Go files found in %s", dir)
	}

	return paths
}

// 15. The exit status follows the status member: 0 for ok and partial, non-zero otherwise.

func TestExitStatusFollowsTheStatusMember(t *testing.T) {
	for _, tc := range []struct {
		name string
		set  func(*fakeStore)
		args []string
		exit int
	}{
		{"a successful probe", func(*fakeStore) {}, []string{"probe"}, exitOK},
		{"a complete listing", func(*fakeStore) {}, []string{"list", "--root", "/sdcard/DCIM/Camera"}, exitOK},
		{
			name: "a partial listing",
			set: func(f *fakeStore) {
				f.pathErrors = []devicebus.PathError{{
					Path: devicepath.MustParseAuthorizedPath("/sdcard/DCIM/Camera/locked"),
					Code: errcode.CodePermissionDenied,
				}}
			},
			args: []string{"list", "--root", "/sdcard/DCIM/Camera"},
			exit: exitOK,
		},
		{"no device", func(f *fakeStore) { f.probeErr = newCodedError(errcode.CodeNoDevice) }, []string{"probe"}, exitError},
		{"an unauthorized device", func(f *fakeStore) { f.probeErr = newCodedError(errcode.CodeUnauthorized) }, []string{"probe"}, exitError},
		{"a root that could not be read", func(f *fakeStore) { f.listErr = newCodedError(errcode.CodeRootNotFound) }, []string{"list", "--root", "/sdcard/DCIM/Camera"}, exitError},
		{"a failed transfer", func(f *fakeStore) { f.fetchErr = newCodedError(errcode.CodeTransferFailed) }, []string{"fetch", "--path", examplePath}, exitError},
		{"a usage mistake", func(*fakeStore) {}, []string{"fetch", "--nope"}, exitUsage},
	} {
		store := newFakeStore()
		tc.set(store)

		got := run(t, store, tc.args...)

		if got.exit != tc.exit {
			t.Errorf("%s: exit = %d, want %d; stdout %q", tc.name, got.exit, tc.exit, got.stdout)
		}
	}
}

func TestTheCodeOnTheWireIsTheCodeTheFailingLayerDecided(t *testing.T) {
	// Every code in the taxonomy reaches the wire unchanged, through errcode.Coder. Nothing in
	// the App layer maps, guesses or re-derives one, so a code added to the taxonomy later
	// needs no change here.
	for _, code := range []errcode.Code{
		errcode.CodeNoDevice, errcode.CodeUnauthorized, errcode.CodeOffline, errcode.CodeMultipleDevices,
		errcode.CodeNoADBServer, errcode.CodePathDenied, errcode.CodeVolumeUnresolved, errcode.CodeRootNotFound,
		errcode.CodeNotADirectory, errcode.CodePermissionDenied, errcode.CodePathNotFound,
		errcode.CodeTransferFailed, errcode.CodeDeviceDisconnected, errcode.CodeUnsupported, errcode.CodeInternal,
	} {
		store := newFakeStore()
		store.probeErr = newCodedError(code)

		got := run(t, store, "probe")

		if res := decode(t, lines(t, got.stdout)[0]); res["code"] != code.String() {
			t.Errorf("code = %v, want %s", res["code"], code)
		}
	}
}

func TestAnUnclassifiedFailureIsReportedAsInternal(t *testing.T) {
	// internal is fatal in the taxonomy, so an unclassified failure aborts a consumer's run
	// rather than being quietly skipped.
	store := newFakeStore()
	store.probeErr = fmt.Errorf("something nobody classified")

	got := run(t, store, "probe")

	if res := decode(t, lines(t, got.stdout)[0]); res["code"] != errcode.CodeInternal.String() {
		t.Errorf("code = %v, want internal", res["code"])
	}
}

func TestAFailedOperationIsStillRecorded(t *testing.T) {
	// A denial is recorded with the same weight as a success. The records that matter most are
	// the ones a design where "interesting events go unwritten" would omit.
	logPath := newAuditLog(t)

	store := newFakeStore()
	store.probeErr = newCodedError(errcode.CodeUnauthorized)

	if got := runWithLog(t, logPath, store, "probe"); got.exit == 0 {
		t.Fatal("exit = 0 for a refused probe")
	}

	recorded, err := os.ReadFile(logPath)
	if err != nil {
		t.Fatalf("read the audit log: %v", err)
	}

	for _, want := range []string{`"decision":"deny"`, `"result":"unauthorized"`} {
		if !strings.Contains(string(recorded), want) {
			t.Errorf("the audit record does not contain %s:\n%s", want, recorded)
		}
	}
}

func TestAnAnchorFailureIsVisibleOnStderrAndNowhereElse(t *testing.T) {
	// The failure this makes observable was invisible for a whole install: the broker ran, wrote
	// its audit record, published no anchor, and the only trace was verify honestly reporting
	// that a truncated tail "could not be ruled out". The anchor is the ONLY control against
	// truncation, so a permanently broken anchor path that says nothing is the guarantee going
	// unenforced while still appearing to be in force.
	//
	// It is reported on stderr and asserted to be nowhere else. Not on stdout, which carries the
	// protocol and nothing else — a consumer capturing it expecting JSON must not find prose.
	// Not in the exit status. Not in the error the operation returns, which is the delegate's.
	// The comparison is against the same invocation with a working anchor rather than against a
	// written-down response, so what is asserted is "nothing a consumer can observe changed" and
	// not "the probe response still looks like this", which is a different test and already
	// exists.
	healthy := runWithLog(t, newAuditLog(t), newFakeStore(), "probe")

	logPath := newAuditLog(t)

	reason := "dial journal socket /run/systemd/journal/socket: connect: permission denied"
	swap(t, &publishAnchor, func(l *audit.Log) error {
		return fmt.Errorf("audit: publish an anchor for %s at seq %d, the only control against a truncated tail: %s", l.Path(), l.Seq(), reason)
	})

	got := runWithLog(t, logPath, newFakeStore(), "probe")

	if got.stdout != healthy.stdout {
		t.Errorf("stdout changed because an anchor failed\n got: %q\nwant: %q", got.stdout, healthy.stdout)
	}

	if got.exit != exitOK || healthy.exit != exitOK {
		t.Errorf("exit = %d (healthy %d), want %d: an anchor failure must not fail an operation already recorded", got.exit, healthy.exit, exitOK)
	}

	if healthy.stderr != "" {
		t.Errorf("a successful anchor put %q on stderr; only a failure may say anything", healthy.stderr)
	}

	// What an operator reading stderr must be able to learn: which log, how far the chain had
	// got, and which of the candidate causes this is.
	for _, fragment := range []string{"adb-broker:", logPath, "seq 1", reason} {
		if !strings.Contains(got.stderr, fragment) {
			t.Errorf("stderr does not mention %q, so it does not diagnose anything:\n%s", fragment, got.stderr)
		}
	}

	if _, err := os.Stat(logPath); err != nil {
		t.Fatalf("stat the audit log: %v", err)
	}

	recorded, err := os.ReadFile(logPath)
	if err != nil {
		t.Fatalf("read the audit log: %v", err)
	}

	if !strings.Contains(string(recorded), `"op":"probe"`) {
		t.Errorf("the operation was not recorded:\n%s", recorded)
	}
}

func TestListStreamsRatherThanBuffering(t *testing.T) {
	// The record for a file is on stdout before the next file is even discovered. A
	// twenty-thousand-file listing has to be parseable incrementally, and this is the property
	// that makes it so.
	store := newFakeStore()
	store.records = []devicebus.FileRecord{
		fileRecord("/sdcard/DCIM/Camera/one.JPG", 1, 1),
		fileRecord("/sdcard/DCIM/Camera/two.JPG", 2, 2),
	}

	logPath := newAuditLog(t)
	swap(t, &openAuditLog, func() (*audit.Log, bool, error) {
		// audit.Open, NOT the open-or-create Main uses: these helpers hand out paths that
		// must FAIL to open, and a creating seam would answer them by making a fresh log.
		log, err := audit.Open(logPath)

		return log, false, err
	})
	swap(t, &newStorer, func(v string) devicebus.Storer { store.brokerVersion = v; return store })

	// Each record must be flushed BEFORE the next one is asked for, which is what "streamed as
	// discovered" means. The counters are read inside the writer, on the same goroutine, so an
	// implementation that collected the records and wrote them at the end fails here.
	var flushesWhenWritten []int

	watcher := &watchingWriter{}
	watcher.onWrite = func(int) { flushesWhenWritten = append(flushesWhenWritten, watcher.flushes) }

	var stderr bytes.Buffer
	if exit := Main([]string{"list", "--root", "/sdcard/DCIM/Camera"}, watcher, &stderr); exit != 0 {
		t.Fatalf("exit = %d, stderr %q", exit, stderr.String())
	}

	// One write per record plus one for the summary.
	if writes := len(flushesWhenWritten); writes != len(store.records)+1 {
		t.Errorf("stdout saw %d writes for %d records and a summary; the listing was buffered", writes, len(store.records))
	}

	// The second record was written only after the first had been flushed.
	for i, flushes := range flushesWhenWritten {
		if flushes != i {
			t.Errorf("write %d happened after %d flushes, want %d: records are not being pushed out as they arrive", i+1, flushes, i)
		}
	}

	if watcher.flushes < len(store.records) {
		t.Errorf("stdout was flushed %d times for %d records; a buffered consumer would not see them arrive", watcher.flushes, len(store.records))
	}
}

// watchingWriter counts the writes and flushes a listing performs, and implements Flush so the
// streaming guarantee is observable.
type watchingWriter struct {
	buf     bytes.Buffer
	flushes int
	onWrite func(int)
}

func (w *watchingWriter) Write(p []byte) (int, error) {
	if w.onWrite != nil {
		w.onWrite(len(p))
	}

	return w.buf.Write(p)
}

func (w *watchingWriter) Flush() error {
	w.flushes++

	return nil
}

// seededLog returns the path of an audit log holding one valid record, for tests that need the
// fail-closed check to pass against a chain that is not empty.
func seededLog(t *testing.T) string {
	t.Helper()

	path := newAuditLog(t)

	log, err := audit.Open(path)
	if err != nil {
		t.Fatalf("open the test audit log: %v", err)
	}
	defer func() { _ = log.Close() }()

	if _, err := log.Append(audit.Record{TS: time.Now(), Op: "probe", Decision: "allow", Result: "ok"}); err != nil {
		t.Fatalf("seed the test audit log: %v", err)
	}

	return path
}
