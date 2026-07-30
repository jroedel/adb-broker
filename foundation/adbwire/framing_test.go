package adbwire

import (
	"context"
	"errors"
	"net"
	"strings"
	"testing"
	"time"
)

// TestEncodeHostRequest pins the %04x framing. This is the one place the length
// prefix is produced, and a one-nibble error here is measured to come back as
// FAIL "device offline (no transport)" — a device error for an encoder bug.
func TestEncodeHostRequest(t *testing.T) {
	tests := []struct {
		name    string
		service string
		want    string
	}{
		{"the measured host:version request", svcVersion, "000chost:version"},
		{"host:devices", svcDevices, "000chost:devices"},
		{"host:transport-any", svcTransportAny, "0012host:transport-any"},
		{"sync:", svcSync, "0005sync:"},
		{"features for a serial", "host-serial:EXAMPLESERIAL1:features", "0023host-serial:EXAMPLESERIAL1:features"},
		{"empty service", "", "0000"},
		{"15 bytes stays one digit", strings.Repeat("a", 15), "000f" + strings.Repeat("a", 15)},
		{"16 bytes carries", strings.Repeat("a", 16), "0010" + strings.Repeat("a", 16)},
		{"lower-case hex above 9", strings.Repeat("a", 0xab), "00ab" + strings.Repeat("a", 0xab)},
		{"four digits", strings.Repeat("a", 0x1234), "1234" + strings.Repeat("a", 0x1234)},
		{"the largest expressible request", strings.Repeat("a", hostRequestMax), "ffff" + strings.Repeat("a", hostRequestMax)},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, err := encodeHostRequest(tc.service)
			if err != nil {
				t.Fatalf("encodeHostRequest: %v", err)
			}

			if string(got) != tc.want {
				t.Errorf("encodeHostRequest(%q) = %q, want %q", tc.service, got, tc.want)
			}
		})
	}
}

// TestEncodeHostRequestTooLong refuses what the prefix cannot describe rather
// than truncating it, because a truncated prefix is the measured landmine.
func TestEncodeHostRequestTooLong(t *testing.T) {
	if _, err := encodeHostRequest(strings.Repeat("a", hostRequestMax+1)); !errors.Is(err, ErrProtocol) {
		t.Fatalf("error = %v, want ErrProtocol", err)
	}
}

// TestDeadlineFor covers both halves of the rule that no socket is ever left
// without a deadline: the caller's deadline wins, and a context without one gets
// the compiled default.
func TestDeadlineFor(t *testing.T) {
	t.Run("the caller's deadline is used", func(t *testing.T) {
		want := time.Now().Add(3 * time.Second)

		ctx, cancel := context.WithDeadline(t.Context(), want)
		defer cancel()

		if got := deadlineFor(ctx, defaultHostDeadline); !got.Equal(want) {
			t.Errorf("deadlineFor = %v, want the context's %v", got, want)
		}
	})

	t.Run("a context with no deadline gets the default", func(t *testing.T) {
		before := time.Now()

		got := deadlineFor(context.Background(), defaultHostDeadline)

		if got.Before(before.Add(defaultHostDeadline)) || got.After(time.Now().Add(defaultHostDeadline)) {
			t.Errorf("deadlineFor = %v, want roughly now plus %v", got, defaultHostDeadline)
		}
	})

	t.Run("the defaults are the measured ones", func(t *testing.T) {
		if defaultHostDeadline != 30*time.Second {
			t.Errorf("defaultHostDeadline = %v, want 30s", defaultHostDeadline)
		}

		if defaultDataDeadline != 60*time.Second {
			t.Errorf("defaultDataDeadline = %v, want 60s", defaultDataDeadline)
		}
	})
}

// pipeWith returns a connection whose peer has already sent b and then closed.
func pipeWith(t *testing.T, b []byte) net.Conn {
	t.Helper()

	client, server := net.Pipe()

	t.Cleanup(func() {
		_ = client.Close()
		_ = server.Close()
	})

	go func() {
		if len(b) > 0 {
			_, _ = server.Write(b)
		}

		_ = server.Close()
	}()

	return client
}

// TestReadHostStatusRejectsUnknownToken keeps a reply that is neither OKAY nor
// FAIL from being read as either.
func TestReadHostStatusRejectsUnknownToken(t *testing.T) {
	nc := pipeWith(t, []byte("WHAT0000"))

	_, err := readHostStatus(t.Context(), nc, svcVersion)
	if !errors.Is(err, ErrProtocol) {
		t.Fatalf("error = %v, want ErrProtocol", err)
	}

	if !strings.Contains(err.Error(), `"WHAT"`) {
		t.Errorf("error %q does not report the token it saw", err)
	}
}

// TestReadHostStatusSilentClose is the measured empty reply: zero bytes read is
// not a FAIL, and the error must say so rather than carrying an empty message.
func TestReadHostStatusSilentClose(t *testing.T) {
	nc := pipeWith(t, nil)

	_, err := readHostStatus(t.Context(), nc, svcVersion)
	if !errors.Is(err, ErrProtocol) {
		t.Fatalf("error = %v, want ErrProtocol", err)
	}

	if !strings.Contains(err.Error(), "closed the connection without replying") {
		t.Errorf("error %q does not describe a silent close", err)
	}
}

// TestReadHostPayloadNonHexLength covers a length prefix that is not hex.
func TestReadHostPayloadNonHexLength(t *testing.T) {
	nc := pipeWith(t, []byte("zzzz"))

	_, err := readHostPayload(t.Context(), nc, svcVersion)
	if !errors.Is(err, ErrProtocol) {
		t.Fatalf("error = %v, want ErrProtocol", err)
	}

	if !strings.Contains(err.Error(), "zzzz") {
		t.Errorf("error %q does not report the prefix it saw", err)
	}
}

// TestReadHostPayloadZeroLength is the empty-device-list shape: a zero length is
// a real, successful reply.
func TestReadHostPayloadZeroLength(t *testing.T) {
	nc := pipeWith(t, []byte("0000"))

	got, err := readHostPayload(t.Context(), nc, svcDevices)
	if err != nil {
		t.Fatalf("readHostPayload: %v", err)
	}

	if len(got) != 0 {
		t.Errorf("payload = %q, want empty", got)
	}
}

// TestReadHostPayloadTruncated covers a server that closes part-way through its
// reply, which is a different failure from closing before it.
func TestReadHostPayloadTruncated(t *testing.T) {
	nc := pipeWith(t, []byte("0010short"))

	_, err := readHostPayload(t.Context(), nc, svcDevices)
	if !errors.Is(err, ErrProtocol) {
		t.Fatalf("error = %v, want ErrProtocol", err)
	}

	if !strings.Contains(err.Error(), "part-way") {
		t.Errorf("error %q does not distinguish a truncated reply from a silent close", err)
	}
}

// TestParseHexPayload covers the double encoding on its own, away from any
// socket: "0029" is 41.
func TestParseHexPayload(t *testing.T) {
	tests := map[string]struct {
		payload string
		want    uint64
		wantErr bool
	}{
		"the measured version": {payload: "0029", want: 41},
		"zero":                 {payload: "0000", want: 0},
		"upper-case hex":       {payload: "002A", want: 42},
		"empty":                {payload: "", wantErr: true},
		"not hex":              {payload: "1.0.41", wantErr: true},
	}

	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			got, err := parseHexPayload([]byte(tc.payload))

			switch {
			case tc.wantErr && err == nil:
				t.Fatalf("parseHexPayload(%q) = %d, want an error", tc.payload, got)

			case !tc.wantErr && err != nil:
				t.Fatalf("parseHexPayload(%q): %v", tc.payload, err)

			case !tc.wantErr && got != tc.want:
				t.Errorf("parseHexPayload(%q) = %d, want %d", tc.payload, got, tc.want)
			}
		})
	}
}

// TestWireErrDeadline covers the classification of an expired deadline, which is
// the only thing that ends the measured never-replies exchange.
func TestWireErrDeadline(t *testing.T) {
	client, server := net.Pipe()

	t.Cleanup(func() {
		_ = client.Close()
		_ = server.Close()
	})

	ctx, cancel := context.WithTimeout(t.Context(), 50*time.Millisecond)
	defer cancel()

	buf := make([]byte, 4)

	err := readFull(ctx, client, svcVersion, buf, defaultHostDeadline)
	if !errors.Is(err, ErrProtocol) {
		t.Fatalf("error = %v, want ErrProtocol", err)
	}

	if !errors.Is(err, context.DeadlineExceeded) {
		t.Errorf("error = %v, want it to wrap context.DeadlineExceeded", err)
	}
}
