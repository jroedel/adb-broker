//go:build integration

package adbwire

// These tests talk to the real adb server on ServerAddr, with NO device
// attached. That is deliberate: the no-device state is where the interesting
// failures live, and it is the state a build machine is in. Every test skips
// rather than fails when no server is listening, so a tagged run stays green on
// a machine without adb installed.
//
// Nothing here plugs in, unplugs, or authorises anything, and nothing starts a
// server.

import (
	"context"
	"errors"
	"strconv"
	"strings"
	"testing"
	"time"
)

// dialReal returns a Conn to the real server, or skips.
func dialReal(t *testing.T, ctx context.Context) *Conn {
	t.Helper()

	c, err := Dial(ctx)
	if errors.Is(err, ErrNoServer) {
		t.Skipf("no adb server on %s: %v", ServerAddr, err)
	}

	if err != nil {
		t.Fatalf("Dial: %v", err)
	}

	t.Cleanup(func() { _ = c.Close() })

	return c
}

// realCtx bounds every integration exchange, so a hung server fails the test
// instead of the run.
func realCtx(t *testing.T) context.Context {
	t.Helper()

	ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
	t.Cleanup(cancel)

	return ctx
}

// TestIntegrationServerVersion reads the real double-encoded version payload.
func TestIntegrationServerVersion(t *testing.T) {
	ctx := realCtx(t)

	got, err := dialReal(t, ctx).ServerVersion(ctx)
	if err != nil {
		t.Fatalf("ServerVersion: %v", err)
	}

	rest, ok := strings.CutPrefix(got, "1.0.")
	if !ok {
		t.Fatalf("ServerVersion = %q, want the 1.0.<n> form adb prints", got)
	}

	n, err := strconv.Atoi(rest)
	if err != nil {
		t.Fatalf("ServerVersion = %q, whose last component is not a number: %v", got, err)
	}

	// 41 (0x29) is what this host reported. Anything plausible passes; a value of
	// 4 would mean the length prefix had been read as the value.
	if n < 20 {
		t.Errorf("ServerVersion = %q; %d looks like a length field rather than a version", got, n)
	}

	t.Logf("adb server version %s", got)
}

// TestIntegrationDevicesEmpty exercises the measured no-device reply: OKAY with a
// zero-length payload. With a device attached this test reports what it saw and
// stops rather than failing, since the state of the host is not its to control.
func TestIntegrationDevicesEmpty(t *testing.T) {
	ctx := realCtx(t)

	got, err := dialReal(t, ctx).Devices(ctx)
	if err != nil {
		t.Fatalf("Devices: %v", err)
	}

	if got == nil {
		t.Error("Devices returned a nil slice; want an empty, non-nil one")
	}

	if len(got) != 0 {
		t.Skipf("a device is attached (%d entries); this test covers the empty-list reply", len(got))
	}
}

// TestIntegrationFeaturesUnknownSerial exercises the real FAIL path and the prose
// table against a serial that cannot exist.
func TestIntegrationFeaturesUnknownSerial(t *testing.T) {
	ctx := realCtx(t)

	_, err := dialReal(t, ctx).DeviceFeatures(ctx, "NOSUCHSERIAL")
	if !errors.Is(err, ErrDeviceNotFound) {
		t.Fatalf("DeviceFeatures error = %v, want ErrDeviceNotFound", err)
	}

	fe, ok := errors.AsType[FailError](err)
	if !ok {
		t.Fatalf("error %v does not carry a FailError", err)
	}

	t.Logf("real FAIL prose: %q", fe.Message)
}

// TestIntegrationUnknownHostService exercises the "unknown host service" row of
// the prose table.
//
// It reaches the unexported query directly, because no exported method can send
// an unknown service — the vocabulary is closed, and that is the point. This is
// test-only code and is not compiled into the binary.
func TestIntegrationUnknownHostService(t *testing.T) {
	ctx := realCtx(t)

	_, err := dialReal(t, ctx).query(ctx, "host:bogus")
	if !errors.Is(err, ErrUnknownService) {
		t.Fatalf("error = %v, want ErrUnknownService", err)
	}
}

// TestIntegrationTransportAnyNoDevice covers the real transport failure with
// nothing attached.
func TestIntegrationTransportAnyNoDevice(t *testing.T) {
	ctx := realCtx(t)

	err := dialReal(t, ctx).TransportAny(ctx)
	if errors.Is(err, ErrUnauthorized) {
		t.Skip("a device is attached but untrusted; this test covers the no-device reply")
	}

	if err == nil {
		t.Skip("a device is attached; this test covers the no-device reply")
	}

	if !errors.Is(err, ErrNoDevices) {
		t.Fatalf("TransportAny error = %v, want ErrNoDevices", err)
	}
}

// TestIntegrationSyncWithoutTransport covers the measured transport gate: sync:
// on a fresh connection fails with "device offline (no transport)" rather than
// hanging.
func TestIntegrationSyncWithoutTransport(t *testing.T) {
	ctx := realCtx(t)

	sc, err := dialReal(t, ctx).Sync(ctx)
	if err == nil {
		_ = sc.Close()

		t.Fatal("Sync succeeded with no transport selected")
	}

	if !errors.Is(err, ErrOffline) {
		t.Fatalf("Sync error = %v, want ErrOffline", err)
	}
}

// TestIntegrationServerSurvivesOurMistakes checks the lifecycle claim the redial
// logic rests on: the server closes the socket after answering, and a second
// query on the same Conn still works because the Conn redials.
func TestIntegrationServerRedial(t *testing.T) {
	ctx := realCtx(t)
	c := dialReal(t, ctx)

	if _, err := c.ServerVersion(ctx); err != nil {
		t.Fatalf("first ServerVersion: %v", err)
	}

	if _, err := c.Devices(ctx); err != nil {
		t.Fatalf("Devices after ServerVersion on the same Conn: %v", err)
	}

	if _, err := c.ServerVersion(ctx); err != nil {
		t.Fatalf("third exchange on the same Conn: %v", err)
	}
}
