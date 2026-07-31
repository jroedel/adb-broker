package broker

import (
	"context"
	"errors"
	"io"
	"strings"
	"testing"

	"github.com/jroedel/adb-broker/business/domain/device/devicebus"
	"github.com/jroedel/adb-broker/business/types/devicepath"
	"github.com/jroedel/adb-broker/business/types/errcode"
	"github.com/jroedel/adb-broker/business/types/serial"
	"github.com/jroedel/adb-broker/foundation/audit"
)

// streamingStore reports a size far larger than anything that could be held in memory,
// then writes the bytes lazily. It records the order in which the framing happened.
type streamingStore struct {
	size   int64
	events []string
}

func (s *streamingStore) Probe(context.Context, serial.Serial) (devicebus.Device, error) {
	return devicebus.Device{State: "device", Serial: serial.MustParseSerial("EXAMPLESERIAL1")}, nil
}

func (s *streamingStore) ResolveVolume(context.Context) (devicepath.Volume, error) {
	return devicepath.ResolveVolume(func(string) (int64, int64, uint32, error) {
		return 190, 3252, 0o042770, nil
	})
}

func (s *streamingStore) List(context.Context, devicebus.ListInput, devicepath.Volume, func(devicebus.FileRecord) error) (devicebus.ListSummary, error) {
	return devicebus.ListSummary{}, nil
}

func (s *streamingStore) Fetch(_ context.Context, _ devicepath.AuthorizedPath, _ devicepath.Volume, w io.Writer, before func(devicebus.FetchInfo) error) (devicebus.FetchResult, error) {
	s.events = append(s.events, "stat")

	if before != nil {
		if err := before(devicebus.FetchInfo{Size: s.size}); err != nil {
			return devicebus.FetchResult{}, err
		}
	}
	s.events = append(s.events, "size-handed-over")

	// Write in chunks, recording that bytes moved only after the header was framed. If the
	// caller were buffering, it could not have written the header before this point.
	var written int64
	chunk := strings.Repeat("x", 64*1024)
	for written < s.size {
		n := int64(len(chunk))
		if remaining := s.size - written; remaining < n {
			n = remaining
		}
		if _, err := io.WriteString(w, chunk[:n]); err != nil {
			return devicebus.FetchResult{}, err
		}
		written += n
	}
	s.events = append(s.events, "bytes-written")

	return devicebus.FetchResult{
		Bytes:  written,
		SHA256: "unused-in-this-test",
		Serial: serial.MustParseSerial("EXAMPLESERIAL1"),
	}, nil
}

// A fetch must not hold the payload in memory. The size is stated ahead of the first byte
// via the seam's callback, so a file far larger than any sane buffer streams through with
// peak memory bounded by the chunk size rather than the file size.
//
// This guards the defect the first implementation had: it buffered the whole payload to
// learn the size for the header, which on this device's >4 GiB videos — the very files
// STAT_V2 is mandatory for — would have meant a multi-gigabyte allocation per fetch.
func TestFetchStreamsWithoutBufferingThePayload(t *testing.T) {
	const size = int64(512) << 20 // 512 MiB: far past any acceptable buffer

	store := &streamingStore{size: size}

	var out countingWriter
	code := runWithStore(t, store, &out, "fetch", "--path", "/sdcard/DCIM/Camera/big.mp4")

	if code != 0 {
		t.Fatalf("exit code = %d, want 0", code)
	}

	// The order is what proves it: the size crossed the seam, and therefore the header was
	// written, before any payload byte did.
	want := []string{"stat", "size-handed-over", "bytes-written"}
	if len(store.events) != len(want) {
		t.Fatalf("events = %v, want %v", store.events, want)
	}
	for i := range want {
		if store.events[i] != want[i] {
			t.Fatalf("events = %v, want %v", store.events, want)
		}
	}

	// Everything the store produced reached stdout, plus the two framing lines.
	if out.n < size {
		t.Fatalf("stdout received %d bytes, want at least the %d-byte payload", out.n, size)
	}

	if !out.sawHeaderBeforePayload {
		t.Fatal("the header did not precede the payload on stdout")
	}
}

// runWithStore drives Main against an arbitrary Storer and an arbitrary stdout writer.
//
// The package's usual harness collects stdout into a bytes.Buffer, which would have this
// test allocate half a gigabyte to prove the code under test does not. So this one streams
// stdout into whatever the caller passes.
func runWithStore(t *testing.T, store devicebus.Storer, stdout io.Writer, args ...string) int {
	t.Helper()

	logPath := newAuditLog(t)
	swap(t, &openAuditLog, func() (*audit.Log, error) { return audit.Open(logPath) })
	swap(t, &newStorer, func(string) devicebus.Storer { return store })

	return Main(args, stdout, io.Discard)
}

// countingWriter counts bytes without retaining them, so the test itself does not buffer
// half a gigabyte to assert that the code under test does not.
type countingWriter struct {
	n                      int64
	sawHeaderBeforePayload bool
	first                  []byte
}

func (c *countingWriter) Write(p []byte) (int, error) {
	if len(c.first) < 256 {
		c.first = append(c.first, p[:min(len(p), 256-len(c.first))]...)
		if idx := strings.IndexByte(string(c.first), '\n'); idx > 0 {
			line := string(c.first[:idx])
			c.sawHeaderBeforePayload = strings.Contains(line, `"op":"fetch"`) &&
				strings.Contains(line, `"size":536870912`)
		}
	}

	c.n += int64(len(p))

	return len(p), nil
}

// truncatingStore promises a size, writes fewer bytes, then fails — the shape a real device
// produces when storage goes away mid-transfer.
type truncatingStore struct {
	streamingStore
	writeBytes int64
	failWith   error
}

func (s *truncatingStore) Fetch(_ context.Context, _ devicepath.AuthorizedPath, _ devicepath.Volume, w io.Writer, before func(devicebus.FetchInfo) error) (devicebus.FetchResult, error) {
	if before != nil {
		if err := before(devicebus.FetchInfo{Size: s.size}); err != nil {
			return devicebus.FetchResult{}, err
		}
	}

	if _, err := io.WriteString(w, strings.Repeat("x", int(s.writeBytes))); err != nil {
		return devicebus.FetchResult{}, err
	}

	if s.failWith != nil {
		return devicebus.FetchResult{}, s.failWith
	}

	return devicebus.FetchResult{}, errTruncated
}

// errTruncated carries a classification, as every error a real Storer returns does — the
// errcode.Coder contract. A fake that returned a bare error would be testing the broker's
// fallback rather than its behaviour.
var errTruncated error = codedTestErr{code: errcode.CodeTransferFailed}

type codedTestErr struct{ code errcode.Code }

func (c codedTestErr) Error() string      { return "storage went away mid-transfer" }
func (c codedTestErr) Code() errcode.Code { return c.code }

// After the header is on stdout, no further object may be written there. The header commits
// to a byte count, so a consumer reads exactly that many bytes — and an error object appended
// to a short payload is read as CONTENT, not as an error. Measured before this was fixed: a
// consumer would have written 37 bytes of `{"proto":1,"status":"error",…` into its staging
// file after a 5-byte payload.
//
// The stream simply ends instead. A missing trailer is already the contract's signal for a
// failed transfer, and it is the only signal that cannot be mistaken for content.
func TestFetchThatFailsMidStreamWritesNoJSONIntoThePayload(t *testing.T) {
	store := &truncatingStore{
		streamingStore: streamingStore{size: 42},
		writeBytes:     5,
	}

	var out strings.Builder
	var errBuf strings.Builder

	logPath := newAuditLog(t)
	swap(t, &openAuditLog, func() (*audit.Log, error) { return audit.Open(logPath) })
	swap(t, &newStorer, func(string) devicebus.Storer { return store })

	code := Main([]string{"fetch", "--path", "/sdcard/DCIM/Camera/big.mp4"}, &out, &errBuf)

	if code == 0 {
		t.Fatal("a truncated transfer exited 0")
	}

	got := out.String()

	// Exactly the header line plus the five payload bytes, and nothing else.
	const wantHeader = `{"proto":1,"op":"fetch","size":42}` + "\n"
	if got != wantHeader+"xxxxx" {
		t.Fatalf("stdout = %q, want the header plus exactly 5 payload bytes and nothing more", got)
	}

	// The failure must not be describable as JSON anywhere after the header.
	if strings.Contains(got[len(wantHeader):], "{") {
		t.Fatalf("a JSON object was written into the payload region: %q", got[len(wantHeader):])
	}

	// The classification is on stderr, greppable, since it cannot go into a stream whose
	// length is already committed.
	if !strings.Contains(errBuf.String(), "code=transfer_failed") {
		t.Fatalf("stderr does not carry a machine-readable code: %q", errBuf.String())
	}
}

// A fetch that fails BEFORE the header writes one ordinary error object and nothing else, and
// the object is discriminated from a header exactly as a list terminator is: by carrying a
// status member, which a header never does.
//
// This is the contract's most dangerous shape if a consumer gets it wrong, which is why it is
// asserted rather than left implied. A consumer that assumes the first line of a fetch is always
// a header decodes this object into its header struct, finds no size member, and reads zero —
// and a zero-size header is exactly what a legitimate empty file produces, one of which exists
// on the target device. What separates them is the trailer, which a real empty file still has
// and this failure does not, so the two assertions below are the two halves a consumer needs:
// the status member is present, and no framing member is.
func TestFetchThatFailsBeforeTheHeaderWritesAnErrorObject(t *testing.T) {
	store := newFakeStore()
	store.fetchErr = newCodedError(errcode.CodeNotARegularFile)

	got := run(t, store, "fetch", "--path", "/sdcard/DCIM/Camera")

	if got.exit == 0 {
		t.Fatal("a fetch that failed before the header exited 0")
	}

	out := lines(t, got.stdout)
	if len(out) != 1 {
		t.Fatalf("got %d stdout lines, want exactly one error object:\n%s", len(out), got.stdout)
	}

	obj := decode(t, out[0])

	switch {
	case obj["status"] != statusError:
		t.Errorf("status = %v, want %q; presence of status is the only discriminator a consumer has here", obj["status"], statusError)

	case obj["code"] != errcode.CodeNotARegularFile.String():
		t.Errorf("code = %v, want %s", obj["code"], errcode.CodeNotARegularFile)
	}

	// Not a header wearing an error's clothes: neither framing member may appear, or a consumer
	// that checked for them instead of for status would find one and read a size of zero.
	for _, member := range []string{"op", "size"} {
		if _, ok := obj[member]; ok {
			t.Errorf("the error object carries the header's %q member: %s", member, out[0])
		}
	}
}

// An unclassified mid-stream failure must degrade to internal, which is Fatal, rather than to
// transfer_failed, which is per-file. A consumer told "one file failed" when the real state is
// unknown would carry on through a broken run; the safe direction is to abort.
func TestUnclassifiedMidStreamFailureIsFatalNotPerFile(t *testing.T) {
	store := &truncatingStore{
		streamingStore: streamingStore{size: 42},
		writeBytes:     5,
	}
	store.failWith = errors.New("something nobody classified")

	var out, errBuf strings.Builder

	logPath := newAuditLog(t)
	swap(t, &openAuditLog, func() (*audit.Log, error) { return audit.Open(logPath) })
	swap(t, &newStorer, func(string) devicebus.Storer { return store })

	if code := Main([]string{"fetch", "--path", "/sdcard/DCIM/Camera/big.mp4"}, &out, &errBuf); code == 0 {
		t.Fatal("an unclassified truncated transfer exited 0")
	}

	if !strings.Contains(errBuf.String(), "code=internal") {
		t.Fatalf("an unclassified failure was not reported as internal: %q", errBuf.String())
	}
	if !errcode.Code("internal").Fatal() {
		t.Fatal("internal is no longer Fatal; the safe direction has changed")
	}
}
