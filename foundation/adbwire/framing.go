package adbwire

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"strconv"
	"time"
)

// Host framing constants. A host request is a %04x lower-case hex length prefix
// followed by the ASCII service string, e.g. "000chost:version". A reply is the
// four bytes OKAY or FAIL; a FAIL always carries a %04x-prefixed message, and an
// OKAY carries one only for the services that return a value.
const (
	statusOKAY = "OKAY"
	statusFAIL = "FAIL"

	statusLen = 4
	lengthLen = 4

	// hostRequestMax is the longest service string a %04x prefix can describe.
	hostRequestMax = 0xffff
)

// Deadline defaults. Measured behaviour forces these to exist: a request whose
// %04x prefix is longer than the request body makes the adb server block
// forever and never reply. Our own deadline is the only thing that ends that
// exchange, so a context without a deadline must never mean "block forever".
// Do not remove these in the name of simplification.
const (
	// defaultHostDeadline bounds one host exchange, one sync command and the
	// dial itself.
	defaultHostDeadline = 30 * time.Second

	// defaultDataDeadline bounds one RECV packet read. It is per read rather
	// than per transfer, because a large file is many 64 KiB packets and a
	// whole-transfer bound would be a throughput guess.
	defaultDataDeadline = 60 * time.Second
)

// encodeHostRequest renders a service string in the host framing.
//
// This is the single chokepoint for the length prefix, and it is a chokepoint on
// purpose: measured, "0004host:version" (a prefix one nibble short) makes the
// server read the request as "host" and reply FAIL "device offline (no
// transport)". An off-by-one here would send whoever debugs it to the phone
// instead of to this function.
func encodeHostRequest(service string) ([]byte, error) {
	if len(service) > hostRequestMax {
		return nil, fmt.Errorf("adbwire: service string is %d bytes, over the %d the length prefix can express: %w", len(service), hostRequestMax, ErrProtocol)
	}

	return fmt.Appendf(make([]byte, 0, lengthLen+len(service)), "%04x%s", len(service), service), nil
}

// deadlineFor returns the absolute deadline to arm a socket with: the caller's,
// when the context has one, otherwise now plus def. There is no code path that
// leaves a socket without a deadline.
func deadlineFor(ctx context.Context, def time.Duration) time.Time {
	if dl, ok := ctx.Deadline(); ok {
		return dl
	}

	return time.Now().Add(def)
}

// armDeadline puts a deadline on the next read or write of nc.
func armDeadline(ctx context.Context, nc net.Conn, def time.Duration) error {
	if err := ctx.Err(); err != nil {
		return err
	}

	return nc.SetDeadline(deadlineFor(ctx, def))
}

// writeAll writes p under a deadline derived from ctx.
func writeAll(ctx context.Context, nc net.Conn, op string, p []byte, def time.Duration) error {
	if err := armDeadline(ctx, nc, def); err != nil {
		return wireErr(ctx, op, err)
	}

	if _, err := nc.Write(p); err != nil {
		return wireErr(ctx, op, err)
	}

	return nil
}

// readFull fills buf under a deadline derived from ctx.
func readFull(ctx context.Context, nc net.Conn, op string, buf []byte, def time.Duration) error {
	if err := armDeadline(ctx, nc, def); err != nil {
		return wireErr(ctx, op, err)
	}

	if _, err := io.ReadFull(nc, buf); err != nil {
		return wireErr(ctx, op, err)
	}

	return nil
}

// wireErr classifies a transport failure. Every outcome wraps ErrProtocol, and
// the distinct cases exist because they were measured as distinct:
//
//   - A silent close with zero bytes read is not a FAIL. Several malformed
//     requests ("zzzzhost:version", "0000", an unprefixed request) get the socket
//     closed with an empty reply, and reporting that as a protocol error with an
//     empty message loses the only information there is.
//   - A deadline that expires means the server never replied at all, which a
//     too-long length prefix provokes.
func wireErr(ctx context.Context, op string, err error) error {
	switch {
	case ctx.Err() != nil:
		return fmt.Errorf("adbwire: %s: the exchange deadline passed with no reply from the adb server: %w: %w", op, ErrProtocol, ctx.Err())

	case errors.Is(err, os.ErrDeadlineExceeded):
		// The socket deadline came either from the caller's context or from the
		// default above. Both spellings of "deadline exceeded" are attached, so
		// a caller can match either one: net reports os.ErrDeadlineExceeded,
		// while the context whose deadline it was may not have noticed yet —
		// the two timers do not fire in a guaranteed order.
		return fmt.Errorf("adbwire: %s: the exchange deadline passed with no reply from the adb server: %w: %w: %w", op, ErrProtocol, err, context.DeadlineExceeded)

	case errors.Is(err, io.EOF):
		return fmt.Errorf("adbwire: %s: the adb server closed the connection without replying: %w", op, ErrProtocol)

	case errors.Is(err, io.ErrUnexpectedEOF):
		return fmt.Errorf("adbwire: %s: the adb server closed the connection part-way through its reply: %w", op, ErrProtocol)

	default:
		return fmt.Errorf("adbwire: %s: %w: %w", op, ErrProtocol, err)
	}
}

// parseHexPayload reads an ASCII-hex payload as a number. host:version's payload
// is double-encoded this way: the four characters "0029" mean 41.
func parseHexPayload(payload []byte) (uint64, error) {
	return strconv.ParseUint(string(payload), 16, 32)
}

// readHostStatus reads the four-byte OKAY/FAIL token.
func readHostStatus(ctx context.Context, nc net.Conn, op string) (string, error) {
	var buf [statusLen]byte
	if err := readFull(ctx, nc, op+" status", buf[:], defaultHostDeadline); err != nil {
		return "", err
	}

	status := string(buf[:])

	switch status {
	case statusOKAY, statusFAIL:
		return status, nil

	default:
		return "", fmt.Errorf("adbwire: %s: reply began with %q, which is neither OKAY nor FAIL: %w", op, status, ErrProtocol)
	}
}

// readHostPayload reads a %04x-length-prefixed payload. A zero length is a
// legitimate, meaningful reply: an empty device list is OKAY with a zero-length
// payload, so this returns an empty slice and no error for it.
func readHostPayload(ctx context.Context, nc net.Conn, op string) ([]byte, error) {
	var lenBuf [lengthLen]byte
	if err := readFull(ctx, nc, op+" payload length", lenBuf[:], defaultHostDeadline); err != nil {
		return nil, err
	}

	n, err := strconv.ParseUint(string(lenBuf[:]), 16, 32)
	if err != nil {
		return nil, fmt.Errorf("adbwire: %s: payload length %q is not a %%04x hex prefix: %w", op, lenBuf[:], ErrProtocol)
	}

	payload := make([]byte, n)
	if err := readFull(ctx, nc, op+" payload", payload, defaultHostDeadline); err != nil {
		return nil, err
	}

	return payload, nil
}
