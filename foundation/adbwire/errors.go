package adbwire

import (
	"errors"
	"strings"
)

// The sentinels every failure in this package resolves to. Callers match with
// errors.Is; nothing outside this package should match on adb's prose.
var (
	// ErrNoServer means nothing was listening on ServerAddr. This package never
	// starts a server: there is no exec path in it at all, deliberately, so the
	// broker can never be the thing that spawns adbd's parent process.
	ErrNoServer = errors.New("adbwire: no adb server listening on " + ServerAddr)

	// ErrNoDevices means the adb server said so in a FAIL payload. It is NOT
	// returned for an empty device list: measured, an empty list is OKAY with a
	// zero-length payload, and Devices reports that as an empty slice and a nil
	// error so the caller decides what "no phone" means.
	ErrNoDevices = errors.New("adbwire: no devices or emulators found")

	// ErrDeviceNotFound means the named serial is not known to the server.
	ErrDeviceNotFound = errors.New("adbwire: device serial not found")

	// ErrUnauthorized means the device is attached but has not trusted this
	// host's key. Measured: host:transport-any, host:transport:<serial> and
	// host-serial:<serial>:features all return the identical prose, so the
	// failing request cannot be identified from the message. The prose also
	// contains the advice "Try 'adb kill-server'", which the broker must never
	// act on — this package matches the text and discards the instruction.
	ErrUnauthorized = errors.New("adbwire: device unauthorized")

	// ErrOffline means no transport is selected, or the selected one is gone.
	// Measured: sending sync: with no transport fails with this, and so does a
	// request whose %04x length prefix was one byte short — an off-by-one in
	// our own encoder surfaces as a device error, which is why framing lives at
	// a single tested chokepoint.
	ErrOffline = errors.New("adbwire: device offline (no transport)")

	// ErrUnknownService means the server did not recognise the service string.
	ErrUnknownService = errors.New("adbwire: unknown host service")

	// ErrProtocol covers framing violations: a short read, a reply that is
	// neither OKAY nor FAIL, a non-hex length prefix, a silent close, an
	// exchange that outlived its deadline, or a field that cannot be decoded.
	ErrProtocol = errors.New("adbwire: adb protocol violation")

	// ErrSyncSessionDead means the sync channel can no longer be used and a new
	// one must be built. Measured: any RECV FAIL kills the session — after
	// "open failed: No such file or directory", "open failed: Permission
	// denied" and "read failed: Is a directory", each on a fresh channel, the
	// channel was dead every time. Framing errors and an aborted List kill it
	// too, because in both cases undrained bytes remain in the stream.
	ErrSyncSessionDead = errors.New("adbwire: sync session is dead; rebuild it")
)

// failMapping is one row of the prose table below.
type failMapping struct {
	substr   string // lower-cased, deliberately short and stable
	sentinel error
}

// failTable is the ONLY place in the broker that matches adb's English. adb is
// free to reword these messages, so each row matches a short stable substring
// rather than a whole message; the full observed messages live in the tests, one
// case per string. Every message here was captured from a real adb server.
//
//	no device attached       "no devices/emulators found"
//	named serial absent      "device 'EXAMPLESERIAL1' not found"
//	present but not trusted  "device unauthorized.\nThis adb server's ..."
//	no transport selected    "device offline (no transport)"
//	bad service name         "unknown host service"
//
// Unrecognised prose never maps to success: it becomes a FailError whose
// sentinel is ErrProtocol for a host exchange, or ErrSyncSessionDead for a sync
// exchange, and the message is preserved verbatim for humans.
var failTable = []failMapping{
	{"no devices", ErrNoDevices},
	{"unauthorized", ErrUnauthorized},
	{"not found", ErrDeviceNotFound},
	{"device offline", ErrOffline},
	{"unknown host service", ErrUnknownService},
}

// mapFailMessage returns the sentinel adb's prose maps to, or nil if the message
// matches no row. Matching is case-insensitive so a capitalisation change
// upstream does not silently drop a row.
func mapFailMessage(msg string) error {
	lower := strings.ToLower(msg)
	for _, m := range failTable {
		if strings.Contains(lower, m.substr) {
			return m.sentinel
		}
	}

	return nil
}

// FailError carries adb's FAIL payload. The Message is prose meant for humans
// and for the audit trail; code must branch on the sentinel it unwraps to, never
// on the text.
type FailError struct {
	Service string // the service string or sync command that failed
	Message string // adb's prose, for humans only

	// sentinel is the mapped sentinel. It is unexported so the mapping table
	// stays the single source of truth; a FailError built without it still
	// unwraps correctly, by consulting the table from its Message.
	sentinel error
}

// newHostFailError maps a FAIL payload from a host exchange. Unrecognised prose
// becomes ErrProtocol rather than a silent success.
func newHostFailError(service, msg string) FailError {
	sentinel := mapFailMessage(msg)
	if sentinel == nil {
		sentinel = ErrProtocol
	}

	return FailError{Service: service, Message: msg, sentinel: sentinel}
}

// newSyncFailError maps a FAIL payload from a sync command. Unrecognised prose
// becomes ErrSyncSessionDead, because a sync FAIL is measured to end the
// session regardless of what it says — it is not a framing violation.
func newSyncFailError(service, msg string) FailError {
	sentinel := mapFailMessage(msg)
	if sentinel == nil {
		sentinel = ErrSyncSessionDead
	}

	return FailError{Service: service, Message: msg, sentinel: sentinel}
}

// Error renders the service and adb's prose. The unauthorized message is
// multi-line on the wire and is reproduced as-is.
func (e FailError) Error() string {
	return "adbwire: " + e.Service + " failed: " + e.Message
}

// Unwrap returns the sentinel this message mapped to, so errors.Is on a wrapped
// FailError reaches ErrNoDevices, ErrUnauthorized and the rest.
func (e FailError) Unwrap() error {
	if e.sentinel != nil {
		return e.sentinel
	}

	if sentinel := mapFailMessage(e.Message); sentinel != nil {
		return sentinel
	}

	return ErrProtocol
}
