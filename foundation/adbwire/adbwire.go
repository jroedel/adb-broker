// Package adbwire speaks the adb host protocol and the adb sync service
// directly, over a TCP connection to the adb server on the loopback interface.
//
// It never execs the adb binary and never starts a server: there is no exec
// path in this package, deliberately. If nothing is listening on ServerAddr the
// answer is ErrNoServer, not a spawned process.
//
// The outbound vocabulary is a compiled, closed set — see vocabulary. There is
// no method that sends shell:, exec:, SEND, reverse:, root: or tcpip:, and no
// method that sends host:host-features or host:features. That last exclusion is
// measured rather than stylistic: host:host-features reports the *server's*
// capabilities and answers "stat_v2,ls_v2,sendrecv_v2" with no device attached
// at all, so a capability check wired to it can never fail. Only
// host-serial:<serial>:features is evidence about the phone.
//
// Every read and write carries a deadline derived from the caller's context, and
// there is no way to construct a Conn or a SyncConn without one. See the
// deadline constants in framing.go for the measured hang this prevents.
//
// All prose matching lives in errors.go, in one table with a test per observed
// string. Nothing else in the broker reads adb's English.
package adbwire

import (
	"context"
	"errors"
	"fmt"
	"net"
	"strings"
	"sync"
)

// ServerAddr is the adb server address this package talks to. It is compiled in
// and not configurable: a broker that can be pointed at another adb server is a
// broker whose audit log cannot say which server it used.
const ServerAddr = "127.0.0.1:5037"

// serverAddr is the address Dial actually connects to. It is ServerAddr in every
// build; the unit tests point it at a recorded-bytes fake server on loopback.
// Nothing outside this package can change it.
var serverAddr = ServerAddr

// The host services this package sends. Two are templates because they name a
// device serial.
const (
	svcVersion       = "host:version"
	svcDevices       = "host:devices"
	svcTransportAny  = "host:transport-any"
	svcSync          = "sync:"
	svcFeaturesTmpl  = "host-serial:%s:features"
	svcTransportTmpl = "host:transport:%s"
)

// vocabulary is the complete set of service strings and sync command IDs this
// package can put on the wire, templates included. It is the whole outbound
// surface of the broker's device transport: if a string is not in here, no code
// path in this package can send it.
//
// host:devices is the short, tab-separated form. host:devices-l is deliberately
// absent — its space-padded columns are a worse parse for no extra information
// the broker uses.
//
// A test greps this set for the forbidden services, so adding one here is not a
// quiet change.
var vocabulary = []string{
	svcVersion,
	svcDevices,
	svcTransportAny,
	svcSync,
	svcFeaturesTmpl,
	svcTransportTmpl,
	syncLstat,
	syncStat,
	syncList,
	syncRecv,
}

// DeviceEntry is one line of host:devices.
type DeviceEntry struct {
	Serial string

	// State is the state token verbatim: device, unauthorized, offline,
	// bootloader and whatever else adb decides to emit. It is the only
	// structured signal about device state the protocol offers — read it in
	// preference to any FAIL prose, which is measured to be identical for
	// several different failures.
	State string
}

// connState tracks what may be sent next on a Conn's socket.
type connState int

const (
	// stateFresh: a host service may be sent.
	stateFresh connState = iota

	// stateSpent: the adb server closed the socket after answering. Measured:
	// after a value query such as host:version the server closes, so a second
	// query on the same socket reads zero bytes. The next request redials.
	stateSpent

	// stateTransport: a transport is selected on this socket. Only Sync may
	// follow; a host service here would be sent into a device transport.
	stateTransport

	// stateHandedOff: the socket now belongs to a SyncConn.
	stateHandedOff

	// stateClosed: Close was called.
	stateClosed
)

// Conn is a connection to the adb server. It is safe for sequential use from
// multiple goroutines; a Conn is a protocol channel, not a pool, and concurrent
// exchanges on one channel would interleave.
type Conn struct {
	mu    sync.Mutex
	nc    net.Conn
	state connState
}

// Dial connects to the adb server. It never starts one: a refused or unanswered
// connection is ErrNoServer.
//
// The dial and every later exchange are bounded by the caller's context
// deadline, or by defaultHostDeadline when the context has none.
func Dial(ctx context.Context) (*Conn, error) {
	nc, err := dialServer(ctx)
	if err != nil {
		return nil, err
	}

	return &Conn{nc: nc}, nil
}

// dialServer opens one socket to the adb server.
func dialServer(ctx context.Context) (net.Conn, error) {
	dialCtx, cancel := context.WithDeadline(ctx, deadlineFor(ctx, defaultHostDeadline))
	defer cancel()

	var d net.Dialer

	nc, err := d.DialContext(dialCtx, "tcp", serverAddr)

	switch {
	case err == nil:
		return nc, nil

	case ctx.Err() != nil:
		return nil, fmt.Errorf("adbwire: dial %s: %w", serverAddr, ctx.Err())

	default:
		return nil, fmt.Errorf("adbwire: dial %s: no adb server is listening and this package never starts one: %w: %w", serverAddr, ErrNoServer, err)
	}
}

// Close releases the connection. It is safe to call more than once.
//
// Closing a Conn that produced a SyncConn does not close the sync session: Sync
// hands the socket over, and the SyncConn owns it from then on.
func (c *Conn) Close() error {
	c.mu.Lock()
	defer c.mu.Unlock()

	nc := c.nc
	c.nc, c.state = nil, stateClosed

	if nc == nil {
		return nil
	}

	return nc.Close()
}

// prepare makes sure c holds a socket a request may be written to, redialling
// when the adb server closed the previous one.
//
// allowTransport is true only for sync:, which is the one service that is meant
// to follow a transport selection on the same socket.
func (c *Conn) prepare(ctx context.Context, allowTransport bool) error {
	switch {
	case c.state == stateClosed:
		return errors.New("adbwire: connection is closed")

	case c.state == stateHandedOff:
		return errors.New("adbwire: connection was handed off to a sync session; dial a new one")

	case c.state == stateFresh && c.nc == nil:
		// A zero-value Conn has no socket and therefore no deadlines behind it.
		// Dial is the only way in; this refuses rather than panicking.
		return errors.New("adbwire: Conn was not created by Dial")

	case c.state == stateTransport && !allowTransport:
		return errors.New("adbwire: a transport is selected on this connection; only Sync may follow it")

	case c.state == stateSpent:
		nc, err := dialServer(ctx)
		if err != nil {
			return err
		}

		c.nc, c.state = nc, stateFresh
	}

	return nil
}

// spend closes the socket and marks the Conn as needing a redial. It is called
// after every host exchange that the adb server answers and then closes, which
// measured is every OKAY-with-a-payload and every FAIL.
func (c *Conn) spend() {
	if c.nc != nil {
		_ = c.nc.Close()
		c.nc = nil
	}

	c.state = stateSpent
}

// query sends a host service that answers with a value and returns its payload.
// It takes c.mu itself; the switch-style services take it in their own methods.
// The payload may legitimately be empty: an empty device list is OKAY with a
// zero-length payload, not a FAIL.
func (c *Conn) query(ctx context.Context, service string) ([]byte, error) {
	c.mu.Lock()
	defer c.mu.Unlock()

	if err := c.prepare(ctx, false); err != nil {
		return nil, err
	}

	req, err := encodeHostRequest(service)
	if err != nil {
		return nil, err
	}

	if err := writeAll(ctx, c.nc, service, req, defaultHostDeadline); err != nil {
		c.spend()

		return nil, err
	}

	status, err := readHostStatus(ctx, c.nc, service)
	if err != nil {
		c.spend()

		return nil, err
	}

	payload, err := readHostPayload(ctx, c.nc, service)

	// The server closes the socket after answering either way, so this Conn
	// needs a fresh one before the next request whatever happened here.
	c.spend()

	if err != nil {
		return nil, err
	}

	if status == statusFAIL {
		return nil, fmt.Errorf("adbwire: %s: %w", service, newHostFailError(service, string(payload)))
	}

	return payload, nil
}

// switchServiceLocked sends a service that turns the socket into a stream rather
// than answering with a value: host:transport*, and sync:. The caller holds c.mu.
//
// An OKAY here carries NO payload — the next bytes on the socket belong to the
// stream. A FAIL still carries a %04x-prefixed message. Reading a payload after
// OKAY would block until the deadline expired, so the two shapes cannot share
// one code path.
func (c *Conn) switchServiceLocked(ctx context.Context, service string) error {
	if err := c.prepare(ctx, service == svcSync); err != nil {
		return err
	}

	req, err := encodeHostRequest(service)
	if err != nil {
		return err
	}

	if err := writeAll(ctx, c.nc, service, req, defaultHostDeadline); err != nil {
		c.spend()

		return err
	}

	status, err := readHostStatus(ctx, c.nc, service)
	if err != nil {
		c.spend()

		return err
	}

	if status == statusFAIL {
		payload, perr := readHostPayload(ctx, c.nc, service)
		c.spend()

		if perr != nil {
			return perr
		}

		return fmt.Errorf("adbwire: %s: %w", service, newHostFailError(service, string(payload)))
	}

	return nil
}

// ServerVersion returns the adb server's protocol version, formatted the way adb
// itself prints it, e.g. "1.0.41".
//
// The payload is double-encoded and this is the easy bug in the whole package:
// measured, host:version replies OKAY, length "0004", payload "0029" — four ASCII
// hex characters meaning 41, not a length of four. Reading the length as the
// value gives 4 and looks plausible.
func (c *Conn) ServerVersion(ctx context.Context) (string, error) {
	payload, err := c.query(ctx, svcVersion)
	if err != nil {
		return "", err
	}

	n, err := parseHexPayload(payload)
	if err != nil {
		return "", fmt.Errorf("adbwire: %s: payload %q is not the ASCII hex version the server is measured to send: %w", svcVersion, payload, ErrProtocol)
	}

	// adb reports its protocol version as 1.0.<n>; the wire carries only n.
	return fmt.Sprintf("1.0.%d", n), nil
}

// Devices lists the attached devices using host:devices, the short
// tab-separated form.
//
// An empty list is not an error. Measured: with no phone attached the server
// replies OKAY with a zero-length payload, so this returns an empty slice and a
// nil error and the caller decides that no device is attached. Code that keys
// off FAIL alone never notices. ErrNoDevices is returned only when the server
// says so itself, in a FAIL payload.
func (c *Conn) Devices(ctx context.Context) ([]DeviceEntry, error) {
	payload, err := c.query(ctx, svcDevices)
	if err != nil {
		return nil, err
	}

	entries := make([]DeviceEntry, 0, 4)

	for line := range strings.SplitSeq(string(payload), "\n") {
		if line == "" {
			continue
		}

		serial, state, ok := strings.Cut(line, "\t")
		if !ok || serial == "" || state == "" {
			return nil, fmt.Errorf("adbwire: %s: line %q is not serial<TAB>state: %w", svcDevices, line, ErrProtocol)
		}

		entries = append(entries, DeviceEntry{Serial: serial, State: state})
	}

	return entries, nil
}

// DeviceFeatures returns the feature list the named device reports.
//
// This is host-serial:<serial>:features, and it is the only features service
// this package will send. host:host-features is a trap: measured, it answers
// "stat_v2,ls_v2,sendrecv_v2" with no device attached, because it describes the
// server. A V2-capability gate wired to it passes unconditionally.
func (c *Conn) DeviceFeatures(ctx context.Context, serial string) ([]string, error) {
	if err := checkSerial(serial); err != nil {
		return nil, err
	}

	payload, err := c.query(ctx, fmt.Sprintf(svcFeaturesTmpl, serial))
	if err != nil {
		return nil, err
	}

	features := make([]string, 0, 8)

	for f := range strings.SplitSeq(string(payload), ",") {
		if f == "" {
			continue
		}

		features = append(features, f)
	}

	return features, nil
}

// TransportSerial selects the named device as this connection's transport. On
// success the connection carries a transport and Sync is the only thing that may
// follow on it.
func (c *Conn) TransportSerial(ctx context.Context, serial string) error {
	if err := checkSerial(serial); err != nil {
		return err
	}

	c.mu.Lock()
	defer c.mu.Unlock()

	if err := c.switchServiceLocked(ctx, fmt.Sprintf(svcTransportTmpl, serial)); err != nil {
		return err
	}

	c.state = stateTransport

	return nil
}

// TransportAny selects the single attached device as this connection's
// transport. With no device attached it fails with ErrNoDevices; with an
// untrusted device, ErrUnauthorized.
func (c *Conn) TransportAny(ctx context.Context) error {
	c.mu.Lock()
	defer c.mu.Unlock()

	if err := c.switchServiceLocked(ctx, svcTransportAny); err != nil {
		return err
	}

	c.state = stateTransport

	return nil
}

// Sync turns this connection into a sync session, and hands the socket to the
// returned SyncConn: the Conn cannot be used for anything afterwards, and
// closing the Conn does not close the session. Close the SyncConn instead.
//
// Select a transport first. Measured: sync: with no transport selected fails
// with "device offline (no transport)", so the sync service is transport-gated
// and this method reports ErrOffline rather than hanging.
func (c *Conn) Sync(ctx context.Context) (*SyncConn, error) {
	c.mu.Lock()
	defer c.mu.Unlock()

	if err := c.switchServiceLocked(ctx, svcSync); err != nil {
		return nil, err
	}

	nc := c.nc
	c.nc, c.state = nil, stateHandedOff

	return newSyncConn(nc), nil
}

// checkSerial refuses a serial that would corrupt a service string. NUL is
// refused everywhere in this package because it is measured to truncate silently
// on the device side, which would make the audit log describe an operation that
// never happened.
//
// A colon is allowed: adb's own TCP serials contain one, and disambiguating
// host-serial:<serial>:features is the server's problem, not ours.
func checkSerial(serial string) error {
	switch {
	case serial == "":
		return fmt.Errorf("adbwire: empty device serial: %w", ErrProtocol)

	case strings.ContainsAny(serial, "\x00\n\t"):
		return fmt.Errorf("adbwire: device serial %q contains a byte that cannot appear in a service string: %w", serial, ErrProtocol)

	default:
		return nil
	}
}
