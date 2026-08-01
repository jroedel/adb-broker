package adbwire

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

// The unit tests in this package drive the real implementation against a
// recorded-bytes fake server: a listener on 127.0.0.1:0 that replays byte
// sequences taken verbatim from the protocol captures in docs/adb_experiment.md.
// Nothing is stubbed above the socket, so the framing, the deadlines and the
// prose table are all exercised as shipped.

// step is one leg of a recorded conversation: bytes the client is expected to
// send, and bytes the server sends back.
type step struct {
	want []byte // exact bytes expected from the client; empty means read nothing
	send []byte // bytes to reply with; empty means reply with nothing
	hang bool   // never read, never reply — the measured "server blocks forever"
}

// fakeServer replays one script per accepted connection, in order. A script per
// connection matters because the adb server is measured to close the socket after
// answering a value query, so a Conn redials for its second request.
type fakeServer struct {
	ln net.Listener
	// stop releases a hanging step when the test finishes.
	stop chan struct{}
	wg   sync.WaitGroup
}

// startFakeServer starts the fake and points Dial at it for the duration of the
// test. Tests using it must not call t.Parallel: the address is a package
// variable.
func startFakeServer(t *testing.T, conns ...[]step) *fakeServer {
	t.Helper()

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}

	f := &fakeServer{ln: ln, stop: make(chan struct{})}

	setServerAddr(t, ln.Addr().String())

	f.wg.Go(func() {
		for _, script := range conns {
			nc, err := ln.Accept()
			if err != nil {
				return
			}

			f.serve(t, nc, script)
		}
	})

	t.Cleanup(func() {
		close(f.stop)
		_ = ln.Close()
		f.wg.Wait()
	})

	return f
}

// serve replays one script on one connection.
func (f *fakeServer) serve(t *testing.T, nc net.Conn, script []step) {
	t.Helper()

	defer nc.Close()

	// A stuck read must fail the test rather than deadlock its cleanup.
	_ = nc.SetDeadline(time.Now().Add(10 * time.Second))

	for i, st := range script {
		if st.hang {
			<-f.stop

			return
		}

		if len(st.want) > 0 {
			got := make([]byte, len(st.want))
			if _, err := io.ReadFull(nc, got); err != nil {
				t.Errorf("fake server step %d: reading %d bytes: %v", i, len(st.want), err)

				return
			}

			if !bytes.Equal(got, st.want) {
				t.Errorf("fake server step %d: client sent %q, want %q", i, got, st.want)

				return
			}
		}

		if len(st.send) > 0 {
			if _, err := nc.Write(st.send); err != nil {
				t.Errorf("fake server step %d: write: %v", i, err)

				return
			}
		}
	}
}

// dial opens a raw connection to the fake, for tests that need a socket without
// going through the host handshake.
func (f *fakeServer) dial(t *testing.T) net.Conn {
	t.Helper()

	nc, err := net.Dial("tcp", f.ln.Addr().String())
	if err != nil {
		t.Fatalf("dial fake server: %v", err)
	}

	t.Cleanup(func() { _ = nc.Close() })

	return nc
}

// setServerAddr redirects Dial for the duration of one test.
func setServerAddr(t *testing.T, addr string) {
	t.Helper()

	prev := serverAddr
	serverAddr = addr

	t.Cleanup(func() { serverAddr = prev })
}

// Recorded byte builders. These mirror encodeHostRequest deliberately rather
// than calling it, so a bug in the encoder cannot cancel out in the fixtures.

func hostReq(service string) []byte {
	return fmt.Appendf(nil, "%04x%s", len(service), service)
}

func okayValue(payload string) []byte {
	return fmt.Appendf(nil, "OKAY%04x%s", len(payload), payload)
}

func okaySwitch() []byte {
	return []byte("OKAY")
}

func failReply(msg string) []byte {
	return fmt.Appendf(nil, "FAIL%04x%s", len(msg), msg)
}

// dialConn opens a Conn against whatever startFakeServer set up.
func dialConn(t *testing.T, ctx context.Context) *Conn {
	t.Helper()

	c, err := Dial(ctx)
	if err != nil {
		t.Fatalf("Dial: %v", err)
	}

	t.Cleanup(func() { _ = c.Close() })

	return c
}

// TestServerVersionDoubleEncoded covers the double-encoded payload: length 0004
// wrapping the four characters 0029, meaning 41 and not 4.
func TestServerVersionDoubleEncoded(t *testing.T) {
	tests := []struct {
		name    string
		payload string
		want    string
	}{
		{"measured 0029 is 41", "0029", "1.0.41"},
		{"lower values still parse", "0028", "1.0.40"},
		{"lower-case hex digits", "002a", "1.0.42"},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			startFakeServer(t, []step{{want: hostReq(svcVersion), send: okayValue(tc.payload)}})

			ctx := t.Context()

			got, err := dialConn(t, ctx).ServerVersion(ctx)
			if err != nil {
				t.Fatalf("ServerVersion: %v", err)
			}

			if got != tc.want {
				t.Errorf("ServerVersion = %q, want %q", got, tc.want)
			}
		})
	}
}

// TestServerVersionNonHexPayload proves the length field is never mistaken for
// the value: a payload that is not ASCII hex is a protocol error, not a version.
func TestServerVersionNonHexPayload(t *testing.T) {
	startFakeServer(t, []step{{want: hostReq(svcVersion), send: okayValue("v41!")}})

	ctx := t.Context()

	_, err := dialConn(t, ctx).ServerVersion(ctx)
	if !errors.Is(err, ErrProtocol) {
		t.Fatalf("ServerVersion error = %v, want ErrProtocol", err)
	}
}

// TestDevicesEmptyList is the measured no-phone case: OKAY with a zero-length
// payload. It must be an empty slice and a nil error, never ErrNoDevices.
func TestDevicesEmptyList(t *testing.T) {
	startFakeServer(t, []step{{want: hostReq(svcDevices), send: okayValue("")}})

	ctx := t.Context()

	got, err := dialConn(t, ctx).Devices(ctx)
	if err != nil {
		t.Fatalf("Devices: %v", err)
	}

	if got == nil {
		t.Error("Devices returned a nil slice; want an empty, non-nil one")
	}

	if len(got) != 0 {
		t.Errorf("Devices = %v, want empty", got)
	}

	if errors.Is(err, ErrNoDevices) {
		t.Error("an empty list must not be reported as ErrNoDevices")
	}
}

// TestDevicesParse covers the tab-separated short form, including the
// unauthorized state token.
func TestDevicesParse(t *testing.T) {
	tests := []struct {
		name    string
		payload string
		want    []DeviceEntry
	}{
		{
			name:    "one device",
			payload: "EXAMPLESERIAL1\tdevice\n",
			want:    []DeviceEntry{{Serial: "EXAMPLESERIAL1", State: "device"}},
		},
		{
			name:    "unauthorized state token",
			payload: "EXAMPLESERIAL1\tunauthorized\n",
			want:    []DeviceEntry{{Serial: "EXAMPLESERIAL1", State: "unauthorized"}},
		},
		{
			name:    "several devices and states",
			payload: "EXAMPLESERIAL1\tdevice\nEXAMPLESERIAL2\tunauthorized\nEXAMPLESERIAL3\toffline\nemulator-5554\tbootloader\n",
			want: []DeviceEntry{
				{Serial: "EXAMPLESERIAL1", State: "device"},
				{Serial: "EXAMPLESERIAL2", State: "unauthorized"},
				{Serial: "EXAMPLESERIAL3", State: "offline"},
				{Serial: "emulator-5554", State: "bootloader"},
			},
		},
		{
			name:    "no trailing newline",
			payload: "EXAMPLESERIAL1\tdevice",
			want:    []DeviceEntry{{Serial: "EXAMPLESERIAL1", State: "device"}},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			startFakeServer(t, []step{{want: hostReq(svcDevices), send: okayValue(tc.payload)}})

			ctx := t.Context()

			got, err := dialConn(t, ctx).Devices(ctx)
			if err != nil {
				t.Fatalf("Devices: %v", err)
			}

			if len(got) != len(tc.want) {
				t.Fatalf("Devices = %v, want %v", got, tc.want)
			}

			for i := range got {
				if got[i] != tc.want[i] {
					t.Errorf("entry %d = %+v, want %+v", i, got[i], tc.want[i])
				}
			}
		})
	}
}

// TestDevicesMalformedLine keeps a line with no tab from being read as a serial
// with an empty state.
func TestDevicesMalformedLine(t *testing.T) {
	startFakeServer(t, []step{{want: hostReq(svcDevices), send: okayValue("EXAMPLESERIAL1 device\n")}})

	ctx := t.Context()

	_, err := dialConn(t, ctx).Devices(ctx)
	if !errors.Is(err, ErrProtocol) {
		t.Fatalf("Devices error = %v, want ErrProtocol", err)
	}
}

// The five FAIL messages below are the complete observed set, quoted in full.
// The mapping table matches short substrings of them; these constants are what
// the substrings were derived from, so a rewording upstream fails here first.
const (
	failNoDevices    = "no devices/emulators found"
	failNotFound     = "device 'EXAMPLESERIAL1' not found"
	failUnauthorized = "device unauthorized.\nThis adb server's $ADB_VENDOR_KEYS is not set\nTry 'adb kill-server' if that seems wrong.\nOtherwise check for a confirmation dialog on your device."
	failOffline      = "device offline (no transport)"
	failUnknownSvc   = "unknown host service"
)

// TestFailProseMapping is the prose table's test, one case per observed string.
func TestFailProseMapping(t *testing.T) {
	tests := []struct {
		name string
		msg  string
		want error
	}{
		{"no device attached", failNoDevices, ErrNoDevices},
		{"named serial absent", failNotFound, ErrDeviceNotFound},
		{"present but not trusted", failUnauthorized, ErrUnauthorized},
		{"no transport selected", failOffline, ErrOffline},
		{"bad service name", failUnknownSvc, ErrUnknownService},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			startFakeServer(t, []step{{want: hostReq(svcVersion), send: failReply(tc.msg)}})

			ctx := t.Context()

			_, err := dialConn(t, ctx).ServerVersion(ctx)
			if !errors.Is(err, tc.want) {
				t.Fatalf("error = %v, want it to wrap %v", err, tc.want)
			}

			fe, ok := errors.AsType[FailError](err)
			if !ok {
				t.Fatalf("error %v does not carry a FailError", err)
			}

			if fe.Message != tc.msg {
				t.Errorf("FailError.Message = %q, want the prose verbatim %q", fe.Message, tc.msg)
			}

			if fe.Service != svcVersion {
				t.Errorf("FailError.Service = %q, want %q", fe.Service, svcVersion)
			}
		})
	}
}

// TestUnrecognizedFailProse proves an unknown message is never a silent success,
// and that its text survives for a human to read.
func TestUnrecognizedFailProse(t *testing.T) {
	const msg = "something adb has not said before"

	startFakeServer(t, []step{{want: hostReq(svcVersion), send: failReply(msg)}})

	ctx := t.Context()

	_, err := dialConn(t, ctx).ServerVersion(ctx)
	if !errors.Is(err, ErrProtocol) {
		t.Fatalf("error = %v, want ErrProtocol", err)
	}

	if !strings.Contains(err.Error(), msg) {
		t.Errorf("error %q does not preserve the message %q", err, msg)
	}
}

// TestServerClosesWithZeroBytes covers the measured silent close, which several
// malformed requests provoke. It must not be reported as a protocol error with an
// empty message.
func TestServerClosesWithZeroBytes(t *testing.T) {
	startFakeServer(t, []step{{want: hostReq(svcVersion)}})

	ctx := t.Context()

	_, err := dialConn(t, ctx).ServerVersion(ctx)
	if !errors.Is(err, ErrProtocol) {
		t.Fatalf("error = %v, want ErrProtocol", err)
	}

	if !strings.Contains(err.Error(), "closed the connection") {
		t.Errorf("error %q does not say the server closed the connection", err)
	}
}

// TestServerNeverReplies covers the measured hang: a request whose length prefix
// is too long gets no reply at all, ever. Our own deadline is the only thing that
// ends the exchange.
func TestServerNeverReplies(t *testing.T) {
	startFakeServer(t, []step{{want: hostReq(svcVersion), hang: true}})

	ctx, cancel := context.WithTimeout(t.Context(), 150*time.Millisecond)
	defer cancel()

	c := dialConn(t, ctx)

	start := time.Now()

	_, err := c.ServerVersion(ctx)
	if err == nil {
		t.Fatal("ServerVersion returned no error against a server that never replies")
	}

	if elapsed := time.Since(start); elapsed > 5*time.Second {
		t.Fatalf("ServerVersion took %v; it hung instead of hitting its deadline", elapsed)
	}

	if !errors.Is(err, context.DeadlineExceeded) {
		t.Errorf("error = %v, want it to wrap context.DeadlineExceeded", err)
	}

	if !errors.Is(err, ErrProtocol) {
		t.Errorf("error = %v, want it to wrap ErrProtocol", err)
	}
}

// TestDialNothingListening covers an absent adb server. It must be ErrNoServer,
// and nothing may be started.
func TestDialNothingListening(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}

	addr := ln.Addr().String()

	if err := ln.Close(); err != nil {
		t.Fatalf("close listener: %v", err)
	}

	setServerAddr(t, addr)

	if _, err := Dial(t.Context()); !errors.Is(err, ErrNoServer) {
		t.Fatalf("Dial error = %v, want ErrNoServer", err)
	}
}

// TestConnRedialsAfterValueQuery covers the measured lifecycle: the adb server
// closes the socket once it has answered, so a second query needs a new one.
func TestConnRedialsAfterValueQuery(t *testing.T) {
	startFakeServer(t,
		[]step{{want: hostReq(svcVersion), send: okayValue("0029")}},
		[]step{{want: hostReq(svcDevices), send: okayValue("")}},
	)

	ctx := t.Context()
	c := dialConn(t, ctx)

	if _, err := c.ServerVersion(ctx); err != nil {
		t.Fatalf("ServerVersion: %v", err)
	}

	if _, err := c.Devices(ctx); err != nil {
		t.Fatalf("Devices after ServerVersion: %v", err)
	}
}

// TestDeviceFeatures covers the only features service this package will send.
func TestDeviceFeatures(t *testing.T) {
	const serial = "EXAMPLESERIAL1"

	startFakeServer(t, []step{{
		want: hostReq(fmt.Sprintf(svcFeaturesTmpl, serial)),
		send: okayValue("stat_v2,ls_v2,sendrecv_v2"),
	}})

	ctx := t.Context()

	got, err := dialConn(t, ctx).DeviceFeatures(ctx, serial)
	if err != nil {
		t.Fatalf("DeviceFeatures: %v", err)
	}

	want := []string{"stat_v2", "ls_v2", "sendrecv_v2"}
	if len(got) != len(want) {
		t.Fatalf("DeviceFeatures = %v, want %v", got, want)
	}

	for i := range got {
		if got[i] != want[i] {
			t.Errorf("feature %d = %q, want %q", i, got[i], want[i])
		}
	}
}

// TestDeviceFeaturesNotFound uses the full observed FAIL for an absent serial.
func TestDeviceFeaturesNotFound(t *testing.T) {
	const serial = "NOSUCHSERIAL"

	startFakeServer(t, []step{{
		want: hostReq(fmt.Sprintf(svcFeaturesTmpl, serial)),
		send: failReply("device 'NOSUCHSERIAL' not found"),
	}})

	ctx := t.Context()

	if _, err := dialConn(t, ctx).DeviceFeatures(ctx, serial); !errors.Is(err, ErrDeviceNotFound) {
		t.Fatalf("error = %v, want ErrDeviceNotFound", err)
	}
}

// TestDeviceFeaturesRejectsUnusableSerial keeps a serial that would corrupt the
// service string off the wire. The fake is given no script, so any write fails
// the test.
func TestDeviceFeaturesRejectsUnusableSerial(t *testing.T) {
	tests := map[string]string{
		"empty":   "",
		"NUL":     "EXAMPLE\x00SERIAL",
		"newline": "EXAMPLE\nSERIAL",
		"tab":     "EXAMPLE\tSERIAL",
	}

	for name, serial := range tests {
		t.Run(name, func(t *testing.T) {
			ctx := t.Context()

			// The serial is refused before any socket is touched, so a Conn with
			// no connection is enough — and a Conn with no connection means a
			// regression here panics instead of reaching the wire.
			c := &Conn{}

			if _, err := c.DeviceFeatures(ctx, serial); !errors.Is(err, ErrProtocol) {
				t.Fatalf("error = %v, want ErrProtocol", err)
			}
		})
	}
}

// TestTransportOkayCarriesNoPayload is the shape distinction that a single
// exchange helper would get wrong: a transport switch answers with a bare OKAY
// and the next bytes belong to the stream, so reading a payload here would block
// until the deadline expired.
func TestTransportOkayCarriesNoPayload(t *testing.T) {
	startFakeServer(t, []step{
		{want: hostReq(svcTransportAny), send: okaySwitch()},
		{want: hostReq(svcSync), send: okaySwitch()},
	})

	ctx, cancel := context.WithTimeout(t.Context(), 2*time.Second)
	defer cancel()

	c := dialConn(t, ctx)

	if err := c.TransportAny(ctx); err != nil {
		t.Fatalf("TransportAny: %v", err)
	}

	sc, err := c.Sync(ctx)
	if err != nil {
		t.Fatalf("Sync: %v", err)
	}

	t.Cleanup(func() { _ = sc.Close() })
}

// TestTransportSerialFailUnauthorized uses the full observed prose, which is
// measured to be identical for all three transport-gated services.
func TestTransportSerialFailUnauthorized(t *testing.T) {
	const serial = "EXAMPLESERIAL1"

	startFakeServer(t, []step{{
		want: hostReq(fmt.Sprintf(svcTransportTmpl, serial)),
		send: failReply(failUnauthorized),
	}})

	ctx := t.Context()

	if err := dialConn(t, ctx).TransportSerial(ctx, serial); !errors.Is(err, ErrUnauthorized) {
		t.Fatalf("error = %v, want ErrUnauthorized", err)
	}
}

// TestSyncWithoutTransport covers the measured transport gate on sync:.
func TestSyncWithoutTransport(t *testing.T) {
	startFakeServer(t, []step{{want: hostReq(svcSync), send: failReply(failOffline)}})

	ctx := t.Context()

	if _, err := dialConn(t, ctx).Sync(ctx); !errors.Is(err, ErrOffline) {
		t.Fatalf("error = %v, want ErrOffline", err)
	}
}

// TestHostServiceAfterTransportRefused keeps a host service from being written
// into a selected transport.
func TestHostServiceAfterTransportRefused(t *testing.T) {
	startFakeServer(t, []step{{want: hostReq(svcTransportAny), send: okaySwitch()}})

	ctx := t.Context()
	c := dialConn(t, ctx)

	if err := c.TransportAny(ctx); err != nil {
		t.Fatalf("TransportAny: %v", err)
	}

	if _, err := c.ServerVersion(ctx); err == nil {
		t.Fatal("ServerVersion succeeded on a connection with a transport selected")
	}
}

// TestConnCloseIsIdempotent because callers defer it and error paths call it too.
func TestConnCloseIsIdempotent(t *testing.T) {
	// No script: the connection is accepted and nothing is exchanged on it.
	startFakeServer(t)

	ctx := t.Context()

	c, err := Dial(ctx)
	if err != nil {
		t.Fatalf("Dial: %v", err)
	}

	if err := c.Close(); err != nil {
		t.Fatalf("first Close: %v", err)
	}

	if err := c.Close(); err != nil {
		t.Fatalf("second Close: %v", err)
	}

	if _, err := c.ServerVersion(ctx); err == nil {
		t.Fatal("ServerVersion succeeded on a closed connection")
	}
}

// forbiddenServices are the service strings this package must never be able to
// send. host:host-features and host:features are on the list for a measured
// reason: host:host-features answers "stat_v2,ls_v2,sendrecv_v2" with no device
// attached, so a capability check wired to it can never fail.
var forbiddenServices = []string{
	"shell:",
	"exec:",
	"SEND",
	"reverse:",
	"root:",
	"tcpip:",
	"host:host-features",
	"host:features",
	"host:devices-l",
	"QUIT",
}

// TestVocabularyHasNoForbiddenService greps the compiled vocabulary.
func TestVocabularyHasNoForbiddenService(t *testing.T) {
	if len(vocabulary) == 0 {
		t.Fatal("the vocabulary is empty; this test would pass vacuously")
	}

	for _, service := range vocabulary {
		for _, bad := range forbiddenServices {
			if strings.Contains(service, bad) {
				t.Errorf("vocabulary entry %q contains the forbidden service %q", service, bad)
			}
		}
	}
}

// TestVocabularyIsComplete pins the vocabulary to the ten strings the package is
// allowed to send, so growing it is a deliberate, reviewed change.
func TestVocabularyIsComplete(t *testing.T) {
	want := []string{
		"host:version",
		"host:devices",
		"host:transport-any",
		"sync:",
		"host-serial:%s:features",
		"host:transport:%s",
		"LST2",
		"STA2",
		"LIS2",
		"RECV",
	}

	if len(vocabulary) != len(want) {
		t.Fatalf("vocabulary = %q, want %q", vocabulary, want)
	}

	for i := range want {
		if vocabulary[i] != want[i] {
			t.Errorf("vocabulary[%d] = %q, want %q", i, vocabulary[i], want[i])
		}
	}
}

// TestSourceSendsNoForbiddenService is the belt to the vocabulary test's braces:
// it greps the package's own non-test source for the forbidden strings, so a
// service string spelled inline instead of added to the vocabulary is caught too.
func TestSourceSendsNoForbiddenService(t *testing.T) {
	// SEND and QUIT are excluded here: this package's comments explain why it
	// sends neither, and a comment is not a code path. The vocabulary test above
	// covers what can actually be written to a socket.
	greps := []string{"shell:", "exec:", "reverse:", "root:", "tcpip:", "host:host-features", "host:features", "host:devices-l"}

	for _, name := range packageSources(t) {
		src, err := os.ReadFile(name)
		if err != nil {
			t.Fatalf("read %s: %v", name, err)
		}

		for _, bad := range greps {
			if bytes.Contains(src, []byte(`"`+bad)) {
				t.Errorf("%s contains a string literal beginning %q", name, bad)
			}
		}
	}
}

// TestNoExecPath proves the claim in the package comment: nothing here can start
// a process, so nothing here can start an adb server.
func TestNoExecPath(t *testing.T) {
	for _, name := range packageSources(t) {
		src, err := os.ReadFile(name)
		if err != nil {
			t.Fatalf("read %s: %v", name, err)
		}

		for _, bad := range []string{`"os/exec"`, `"syscall"`, "exec.Command"} {
			if bytes.Contains(src, []byte(bad)) {
				t.Errorf("%s references %s; this package must have no exec path", name, bad)
			}
		}
	}
}

// packageSources lists the package's non-test Go files.
func packageSources(t *testing.T) []string {
	t.Helper()

	all, err := filepath.Glob("*.go")
	if err != nil {
		t.Fatalf("glob: %v", err)
	}

	sources := make([]string, 0, len(all))

	for _, name := range all {
		if strings.HasSuffix(name, "_test.go") {
			continue
		}

		sources = append(sources, name)
	}

	if len(sources) == 0 {
		t.Fatal("found no package sources; this test would pass vacuously")
	}

	return sources
}
