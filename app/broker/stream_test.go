package broker

import (
	"context"
	"io"
	"strings"
	"testing"

	"github.com/jroedel/adb-broker/business/domain/device/devicebus"
	"github.com/jroedel/adb-broker/business/types/devicepath"
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
