package adbsyncdb

import (
	"context"
	"errors"

	"github.com/jroedel/adb-broker/business/types/errcode"
	"github.com/jroedel/adb-broker/business/types/serial"
	"github.com/jroedel/adb-broker/foundation/adbwire"
)

// This file owns the transport's lifetime: establishing a session, retiring one that a
// terminal failure killed, and rebuilding it.
//
// It is a separate file because the reconnect is a deliberate design decision rather than
// an implementation detail. Measured, any RECV failure kills the sync session — on fresh
// channels, for "open failed: No such file or directory", "open failed: Permission
// denied" and "read failed: Is a directory", the channel was dead every time — so an
// unreadable file costs a full re-establishment of the transport. On a first run over a
// tree with several such files that is several round trips of pure overhead. It is
// accepted, and it is here in one place, named, so that nobody discovers it later as a
// mysterious slowness with no explanation attached.
//
// Every function here requires s.mu, which every exported method already holds for its
// whole duration.

// sessionLocked returns the live session, establishing one if there is none.
//
// want names a device. A non-zero want that does not match the live session's device
// rebuilds rather than silently serving the device already selected: returning the wrong
// phone's files under the requested serial would make the audit record a faithful account
// of something that never happened. A zero want reuses the pinned serial, so a rebuild
// after a failure cannot drift onto another device.
func (s *Store) sessionLocked(ctx context.Context, want serial.Serial) (*session, error) {
	if s.sess != nil && !want.IsZero() && want.String() != s.sess.row.serial {
		s.closeSessionLocked()
	}

	if s.sess != nil {
		return s.sess, nil
	}

	if want.IsZero() && s.pinnedSerial != "" {
		ser, err := serial.ParseSerial(s.pinnedSerial)
		if err != nil {
			return nil, codeErr(errcode.CodeInternal, err, "the pinned device serial %q is no longer parseable", s.pinnedSerial)
		}

		want = ser
	}

	sess, err := s.connectLocked(ctx, want)
	if err != nil {
		return nil, err
	}

	s.sess, s.pinnedSerial = sess, sess.row.serial

	return sess, nil
}

// connectLocked builds a session: dial, read the server version, select a device, gate on
// the device's features, select the transport, open the sync channel.
//
// The order is forced by the protocol and by the capability check. Features must be read
// BEFORE the transport is selected, because once a transport is selected on a socket only
// sync: may follow — and they must be read from host-serial:<serial>:features, because
// measured, the server's own host:host-features answers "stat_v2,ls_v2,sendrecv_v2" with no
// device attached at all. A V2 gate wired to the server's list can never fail, which makes
// it worse than no gate: it reads as evidence.
func (s *Store) connectLocked(ctx context.Context, want serial.Serial) (*session, error) {
	conn, err := s.tr.dial(ctx)
	if err != nil {
		return nil, codeErr(codeForWire(err, errcode.CodeInternal), err, "dial the adb server")
	}

	// Closing the Conn is correct in both outcomes. On failure it releases the socket; on
	// success Sync has already handed the socket to the SyncConn and the Conn's Close is a
	// no-op that does not touch the session.
	defer func() { _ = conn.Close() }()

	serverVersion, err := conn.ServerVersion(ctx)
	if err != nil {
		return nil, codeErr(codeForWire(err, errcode.CodeInternal), err, "read the adb server version")
	}

	entries, err := conn.Devices(ctx)
	if err != nil {
		return nil, codeErr(codeForWire(err, errcode.CodeInternal), err, "list the attached devices")
	}

	entry, err := selectDevice(entries, want)
	if err != nil {
		return nil, err
	}

	// The state token travels into every failure message from here down. A device in a
	// state other than "device" fails one of the steps below with prose that is measured
	// to be identical across several different causes, so the token is the only thing that
	// can say which condition it actually was.
	features, err := conn.DeviceFeatures(ctx, entry.Serial)
	if err != nil {
		return nil, codeErr(codeForWire(err, errcode.CodeInternal), err, "read the features of device %q (state %q)", entry.Serial, entry.State)
	}

	if err := requireV2(features); err != nil {
		return nil, codeErr(errcode.CodeUnsupported, err, "device %q (state %q) cannot be served", entry.Serial, entry.State)
	}

	if err := conn.TransportSerial(ctx, entry.Serial); err != nil {
		return nil, codeErr(codeForWire(err, errcode.CodeInternal), err, "select device %q (state %q) as the transport", entry.Serial, entry.State)
	}

	sc, err := conn.Sync(ctx)
	if err != nil {
		return nil, codeErr(codeForWire(err, errcode.CodeInternal), err, "open a sync session on device %q (state %q)", entry.Serial, entry.State)
	}

	return &session{
		sc: sc,
		row: deviceRow{
			serial:        entry.Serial,
			state:         entry.State,
			serverVersion: serverVersion,
			brokerVersion: s.brokerVersion,
			features:      features,
		},
	}, nil
}

// reconnectLocked retires the current session and establishes a new one on the same device.
//
// It is called after a terminal failure, where "terminal" is not a judgement call: adbwire
// marks the session dead and every later command on it fails fast, so without this the next
// operation would report a dead channel instead of doing its work.
func (s *Store) reconnectLocked(ctx context.Context) error {
	s.closeSessionLocked()
	s.reconnects++

	if _, err := s.sessionLocked(ctx, serial.Serial{}); err != nil {
		return err
	}

	return nil
}

// dropSessionIfDeadLocked retires the session when err says the sync channel is gone.
//
// The alternative — keeping it and letting the next command fail — is how "every directory
// is empty" gets reported confidently and wrongly: a dead channel has undrained bytes on
// it, and there is no resync, only a rebuild.
func (s *Store) dropSessionIfDeadLocked(err error) {
	if errors.Is(err, adbwire.ErrSyncSessionDead) {
		s.closeSessionLocked()
	}
}

// closeSessionLocked closes the sync channel and forgets it. The pinned serial survives, so
// the next operation rebuilds on the same device.
func (s *Store) closeSessionLocked() {
	if s.sess == nil {
		return
	}

	_ = s.sess.sc.Close()
	s.sess = nil
}
