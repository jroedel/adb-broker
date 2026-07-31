// Package adbsyncdb implements devicebus.Storer over the adb sync protocol.
//
// devicepath decides the confinement rules; this package is what applies them to
// everything the device hands back. adbd applies no confinement of its own — measured, it
// answers for /data, /proc/1/maps and the root filesystem as readily as it answers for
// media — so a name that came out of a device listing is exactly as untrusted as one that
// came from a caller, and is validated the same way, by devicepath.
//
// Four rules here exist because of measured device behaviour rather than caution:
//
//   - Every entry's dev must equal the pinned volume's. This catches a BIND MOUNT inside
//     the tree, which introduces a foreign filesystem with no symlink involved and which no
//     string rule could ever see — measured, media is dev=190, /data is dev=65088, the root
//     filesystem is dev=65034.
//   - Only regular files are emitted. Directories are descended into; symlinks, sockets,
//     FIFOs, block and character devices are omitted and never followed. This is what
//     catches a SYMLINK ESCAPE.
//
// The two are not redundant, and the division of labour is worth stating because it is the
// opposite of what it looks like. A LIST_V2 dirent carries lstat semantics, so for a symlink
// the dev reported is the filesystem holding the SYMLINK INODE, not its target — measured on
// /sdcard itself, LST2 says dev=65034 where STA2 says dev=190. A symlink planted inside the
// media tree therefore reports the pinned dev no matter where it points, and the dev check
// passes it. Only the kind check refuses it. Conversely a bind mount is a genuine directory,
// so only the dev check sees it. Removing either as "redundant with the other" reopens one of
// the two escapes.
//   - The V2 sync commands are required, not preferred. Legacy STAT and LIST report size
//     as 32 bits, so a video over 4 GiB would list with a silently wrong size. Refusing to
//     start is worse for one run and better forever: the wrong size is found years later,
//     the refusal immediately.
//   - A RECV failure kills the sync session. Measured on fresh channels for "open failed:
//     No such file or directory", "open failed: Permission denied" and "read failed: Is a
//     directory", the channel was dead every time, so the transport is rebuilt after every
//     failed transfer. See reconnect.go.
//
// Nothing here writes to the local filesystem: no temp file, no cache, no spool. Fetch
// streams to the io.Writer the caller supplied and hashes the bytes on the way past.
//
// # Reading the error classification
//
// Every error this package returns carries an errcode.Code. The type is unexported; a
// caller recovers the code with an interface assertion against a locally declared
// interface, which is what keeps the taxonomy the only coupling:
//
//	var coded interface{ Code() errcode.Code }
//	if errors.As(err, &coded) {
//		switch coded.Code() { ... }
//	}
//
// adbwire deliberately does not import business/types, so sentinel-to-code translation
// lives here, in codeForWire, and matches with errors.Is — never on adb's prose.
package adbsyncdb

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"slices"
	"strings"
	"sync"

	"github.com/jroedel/adb-broker/business/domain/device/devicebus"
	"github.com/jroedel/adb-broker/business/types/devicepath"
	"github.com/jroedel/adb-broker/business/types/errcode"
	"github.com/jroedel/adb-broker/business/types/filekind"
	"github.com/jroedel/adb-broker/business/types/serial"
	"github.com/jroedel/adb-broker/foundation/adbwire"
)

// The sync protocol V2 features this store requires. All three or nothing: there is no
// fallback path in this package, deliberately. See the package doc.
const (
	featureStatV2     = "stat_v2"
	featureLsV2       = "ls_v2"
	featureSendrecvV2 = "sendrecv_v2"
)

// requiredFeatures is the gate Probe applies, read from host-serial:<serial>:features.
var requiredFeatures = [...]string{featureStatV2, featureLsV2, featureSendrecvV2}

// The errnos the sync protocol delivers in-band, in Stat.Errno with a nil error. They are
// plain Linux errnos and are written out here because the value came off the wire from an
// Android device rather than from this host's syscall package.
const (
	errnoENOENT = 2 // measured on the device; see codeForErrno for why it is not "absent"
	errnoEACCES = 13
)

// transport is everything this store needs in order to reach a device, and all it needs.
// It exists so the traversal — the security-critical part of this package — is testable
// with no phone attached: the real implementation is wireTransport, a few lines over
// adbwire, and the tests inject a fake that answers with the measured values.
//
// The seam is deliberately this narrow. A wider one (an interface over net.Conn, say)
// would put framing back inside the test fake, where a protocol mistake in the fake could
// make a confinement test pass for the wrong reason.
type transport interface {
	dial(ctx context.Context) (hostConn, error)
}

// hostConn is one connection to the adb server. The method set is a subset of
// *adbwire.Conn's, chosen so that the forbidden services (shell:, exec:, SEND, reverse:,
// root:, tcpip:, host:host-features) are not merely unused here but unreachable: this
// store cannot name them.
type hostConn interface {
	ServerVersion(ctx context.Context) (string, error)
	Devices(ctx context.Context) ([]adbwire.DeviceEntry, error)
	DeviceFeatures(ctx context.Context, serial string) ([]string, error)
	TransportSerial(ctx context.Context, serial string) error
	Sync(ctx context.Context) (syncConn, error)
	Close() error
}

// syncConn is a sync session on a selected transport. *adbwire.SyncConn satisfies it
// directly; there is no SEND and no write path of any kind in the set.
type syncConn interface {
	// Lstat is LST2, which does NOT follow symlinks. Every confinement check uses it.
	Lstat(ctx context.Context, path string) (adbwire.Stat, error)

	// Stat is STA2, which DOES follow symlinks. It is used only against the compiled
	// devicepath.VolumeRoot constant, never against a device-supplied name.
	Stat(ctx context.Context, path string) (adbwire.Stat, error)

	List(ctx context.Context, path string, fn func(adbwire.Dirent) error) error
	Recv(ctx context.Context, path string, w io.Writer) (int64, error)
	Close() error
}

// wireTransport is the real transport, and the only one a caller can get: NewStore wires
// it in and nothing exported can replace it.
type wireTransport struct{}

func (wireTransport) dial(ctx context.Context) (hostConn, error) {
	conn, err := adbwire.Dial(ctx)
	if err != nil {
		return nil, err
	}

	return wireHost{Conn: conn}, nil
}

// wireHost adapts *adbwire.Conn to hostConn. Only Sync needs a body: Go has no covariant
// returns, so the concrete *adbwire.SyncConn has to be widened to the interface here.
type wireHost struct {
	*adbwire.Conn
}

func (h wireHost) Sync(ctx context.Context) (syncConn, error) {
	sc, err := h.Conn.Sync(ctx)
	if err != nil {
		return nil, err
	}

	return sc, nil
}

// session is one established transport: a live sync channel plus the natives the probe
// that built it collected. It is rebuilt wholesale after a terminal failure rather than
// repaired, because a dead sync channel has undrained bytes on it and no way to resync.
type session struct {
	sc  syncConn
	row deviceRow
}

// Store is the devicebus.Storer over the adb sync protocol.
//
// It holds one sync session for its lifetime and rebuilds it after a terminal failure.
// Every exported method takes mu for its whole duration: a sync channel is a protocol
// channel, not a pool, and two interleaved exchanges on one channel would desync it.
type Store struct {
	brokerVersion string
	tr            transport

	mu sync.Mutex

	// sess is the live session, nil before the first operation and after a terminal
	// failure retired one.
	sess *session

	// pinnedSerial is the serial of the device this store selected, kept across a
	// reconnect so a rebuild cannot land on a different phone. It is the serial and
	// never a transport_id: measured, a transport_id advances on re-enumeration, so a
	// cached one identifies nothing after a replug.
	pinnedSerial string

	// reconnects counts rebuilds, so the cost of the measured RECV-kills-the-session
	// behaviour is countable rather than invisible.
	reconnects int
}

// Compile-time proof this store is usable as the Business layer's port.
var _ devicebus.Storer = (*Store)(nil)

// NewStore constructs the store. brokerVersion is reported verbatim on Device; it is the
// broker's own version and is not read from the device.
func NewStore(brokerVersion string) *Store {
	return &Store{
		brokerVersion: brokerVersion,
		tr:            wireTransport{},
	}
}

// Probe reads the device's identity: the adb server version, the selected device and its
// state token, and the feature list that decides whether this device can be served at all.
//
// Model is left empty. It is not obtainable without a shell, this package has no shell and
// never will, and inventing a source for it would put a value in the audit record that
// nothing measured.
func (s *Store) Probe(ctx context.Context, ser serial.Serial) (devicebus.Device, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	sess, err := s.sessionLocked(ctx, ser)
	if err != nil {
		return devicebus.Device{}, err
	}

	dev, err := toBusDevice(sess.row)
	if err != nil {
		return devicebus.Device{}, codeErr(errcode.CodeInternal, err, "the adb server reported a device this broker cannot name")
	}

	return dev, nil
}

// ResolveVolume pins the device's shared-storage filesystem by handing devicepath a stat
// function backed by STA2.
//
// STA2 follows symlinks, which is necessary rather than convenient: measured, /sdcard is
// itself a symlink (mode 0o120644) and so is /storage/self/primary, so a resolver that
// refused to follow one could never resolve shared storage at all. This is the one place
// in the binary that deliberately follows a symlink, it happens against a compiled
// constant, and the directory check and the pinning both belong to devicepath — not to
// this package.
func (s *Store) ResolveVolume(ctx context.Context) (devicepath.Volume, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	sess, err := s.sessionLocked(ctx, serial.Serial{})
	if err != nil {
		return devicepath.Volume{}, err
	}

	vol, err := devicepath.ResolveVolume(s.statFuncLocked(ctx, sess))
	if err != nil {
		return devicepath.Volume{}, codeErr(errcode.CodeVolumeUnresolved, err, "pin the device's shared storage volume")
	}

	return vol, nil
}

// statFuncLocked adapts the sync session to devicepath.StatFunc. The caller holds s.mu.
func (s *Store) statFuncLocked(ctx context.Context, sess *session) devicepath.StatFunc {
	return func(path string) (dev, ino int64, mode uint32, err error) {
		st, err := sess.sc.Stat(ctx, path)
		if err != nil {
			s.dropSessionIfDeadLocked(err)

			return 0, 0, 0, err
		}

		if st.Errno != 0 {
			// In-band and not a transport failure: the channel is still usable, so this
			// returns an error without retiring the session.
			return 0, 0, 0, fmt.Errorf("stat %q: the device answered errno %d", path, st.Errno)
		}

		return st.Dev, st.Ino, st.Mode, nil
	}
}

// List walks in.Root, emitting one FileRecord per regular file as it is discovered.
//
// The walk itself is in walk.go, where the per-entry rules are. This method's job is the
// preconditions: a listing cannot be expressed without a pinned volume, and a walk with a
// depth this package cannot interpret is refused rather than guessed at.
func (s *Store) List(ctx context.Context, in devicebus.ListInput, vol devicepath.Volume, fn func(devicebus.FileRecord) error) (devicebus.ListSummary, error) {
	switch {
	case fn == nil:
		return devicebus.ListSummary{}, codeErr(errcode.CodeInternal, nil, "List needs a record callback")

	case vol.IsZero():
		// An unpinned volume authorises nothing, so this is not merely unhelpful: every
		// entry would be refused and the summary would read as "the whole tree is
		// forbidden" rather than "nobody pinned the volume".
		return devicebus.ListSummary{}, codeErr(errcode.CodeVolumeUnresolved, nil, "listing %q was attempted with an unpinned volume", in.Root.String())

	case in.Root.IsZero():
		return devicebus.ListSummary{}, codeErr(errcode.CodePathDenied, nil, "listing was attempted with the zero path, which names nothing")

	case in.MaxDepth < 0:
		return devicebus.ListSummary{}, codeErr(errcode.CodeInternal, nil, "MaxDepth %d has no meaning; 0 is unlimited and 1 is immediate children", in.MaxDepth)
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	sess, err := s.sessionLocked(ctx, in.Serial)
	if err != nil {
		return devicebus.ListSummary{}, err
	}

	w := walker{
		store:    s,
		sess:     sess,
		vol:      vol,
		fn:       fn,
		maxDepth: in.MaxDepth,
	}

	// The partial summary travels with the error: a walk that aborted half way still
	// counted what it refused, and discarding that would hide the reason it aborted.
	err = w.walkRoot(ctx, in.Root)

	return w.summary, err
}

// Fetch streams p's contents to w and reports the byte count and the SHA-256 of the bytes
// forwarded.
//
// The path is checked twice before any RECV is issued: LST2 (which does NOT follow
// symlinks) must report a regular file, and its dev must equal the pinned volume's. A
// symlink is refused here even though RECV would happily follow it, which is the whole
// point of using LST2 rather than STA2.
//
// # Accepted residual risk
//
// There is a window between the LST2 and the RECV, and RECV follows symlinks device-side.
// An adversary with code execution on the phone could replace a regular file with a
// symlink inside that window and be read out through it. The sync protocol offers no
// openat-style handle — there is no way to name the inode LST2 saw — so the race cannot be
// closed here, and it is accepted rather than papered over: an adversary already running
// code on the device has better options than racing this broker. Do not read the check
// below as stronger than it is.
func (s *Store) Fetch(ctx context.Context, p devicepath.AuthorizedPath, vol devicepath.Volume, w io.Writer, before func(devicebus.FetchInfo) error) (devicebus.FetchResult, error) {
	switch {
	case w == nil:
		return devicebus.FetchResult{}, codeErr(errcode.CodeInternal, nil, "Fetch needs a destination writer")

	case vol.IsZero():
		return devicebus.FetchResult{}, codeErr(errcode.CodeVolumeUnresolved, nil, "fetching %q was attempted with an unpinned volume", p.String())

	case p.IsZero():
		return devicebus.FetchResult{}, codeErr(errcode.CodePathDenied, nil, "fetch was attempted with the zero path, which names nothing")
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	sess, err := s.sessionLocked(ctx, serial.Serial{})
	if err != nil {
		return devicebus.FetchResult{}, err
	}

	path := toSyncPath(p)

	st, err := sess.sc.Lstat(ctx, path)
	if err != nil {
		s.dropSessionIfDeadLocked(err)

		return devicebus.FetchResult{}, codeErr(codeForWire(err, errcode.CodeTransferFailed), err, "lstat %q", p.String())
	}

	switch {
	case st.Errno != 0:
		return devicebus.FetchResult{}, codeErr(codeForErrno(st.Errno, errcode.CodePathNotFound), nil, "lstat %q: the device answered errno %d", p.String(), st.Errno)

	case !filekind.ParseKind(st.Mode).IsRegular():
		// Refused before RECV, and RECV is what would have followed the symlink.
		return devicebus.FetchResult{}, codeErr(errcode.CodePathDenied, nil, "%q is a %s (mode 0o%o), and only regular files are transferred", p.String(), filekind.ParseKind(st.Mode), st.Mode)

	case !vol.Contains(st.Dev):
		return devicebus.FetchResult{}, codeErr(errcode.CodePathDenied, nil, "%q is on dev=%d, not the pinned volume dev=%d, so it is off shared storage", p.String(), st.Dev, vol.Dev())
	}

	// The size is known from the LST2 above and is handed over before a single byte
	// moves, so a caller can frame the stream instead of buffering it. Refusing here
	// abandons the transfer, which is why this runs before RECV rather than after.
	if before != nil {
		if err := before(devicebus.FetchInfo{Size: st.Size}); err != nil {
			return devicebus.FetchResult{}, err
		}
	}

	digest := sha256.New()

	n, err := sess.sc.Recv(ctx, path, io.MultiWriter(w, digest))
	if err != nil {
		code := codeForWire(err, errcode.CodeTransferFailed)

		// Measured: every RECV failure observed killed the session, on a fresh channel,
		// for each of three different causes. The transport is therefore rebuilt after
		// any RECV failure rather than after a guess about which ones spare it — on a
		// first run every unreadable file costs one full re-establishment, and that cost
		// is deliberate.
		if rerr := s.reconnectLocked(ctx); rerr != nil {
			err = errors.Join(err, rerr)
		}

		return devicebus.FetchResult{}, codeErr(code, err, "recv %q stopped after %d bytes", p.String(), n)
	}

	// Serial names the device the bytes actually came from. ExtBusiness.Fetch takes no
	// serial — a fetch identifies only a path — so this store is the only layer that
	// knows, and without it every fetch record in the audit log would say the bytes came
	// from some unnamed phone. A parse failure here is not worth failing a completed
	// transfer over: the session's serial came from host:devices and was already parsed
	// once during probe, so the zero value can only mean a bug, and losing the whole
	// fetch would be a worse outcome than a record with one field missing.
	ser, _ := serial.ParseSerial(sess.row.serial)

	return devicebus.FetchResult{
		Bytes:  n,
		SHA256: hex.EncodeToString(digest.Sum(nil)),
		Serial: ser,
	}, nil
}

// selectDevice picks the device to serve, and refuses rather than guessing.
func selectDevice(entries []adbwire.DeviceEntry, want serial.Serial) (adbwire.DeviceEntry, error) {
	switch {
	case len(entries) == 0:
		// Measured: with no phone attached the server answers OKAY with a zero-length
		// payload, not FAIL, so adbwire reports an empty slice and a nil error. This is
		// where "no device" is decided; code that keys off FAIL alone never notices.
		return adbwire.DeviceEntry{}, codeErr(errcode.CodeNoDevice, nil, "no device is attached")

	case !want.IsZero():
		i := slices.IndexFunc(entries, func(e adbwire.DeviceEntry) bool { return e.Serial == want.String() })
		if i < 0 {
			return adbwire.DeviceEntry{}, codeErr(errcode.CodeNoDevice, nil, "device %q is not attached (attached: %s)", want.String(), serialsOf(entries))
		}

		return entries[i], nil

	case len(entries) == 1:
		return entries[0], nil

	default:
		// Never pick one silently. The serials are in the message because the operator's
		// next action is to name one, and they cannot name what they were not told.
		return adbwire.DeviceEntry{}, codeErr(errcode.CodeMultipleDevices, nil, "%d devices are attached and none was named: %s", len(entries), serialsOf(entries))
	}
}

// serialsOf renders the attached serials for an operator-facing message.
func serialsOf(entries []adbwire.DeviceEntry) string {
	serials := make([]string, len(entries))
	for i, e := range entries {
		serials[i] = e.Serial
	}

	return strings.Join(serials, " ")
}

// requireV2 gates on the three V2 sync features. It reports every missing one, because an
// operator learning that one is absent will only ask about the next.
func requireV2(features []string) error {
	missing := make([]string, 0, len(requiredFeatures))
	for _, want := range requiredFeatures {
		if !slices.Contains(features, want) {
			missing = append(missing, want)
		}
	}

	if len(missing) == 0 {
		return nil
	}

	return fmt.Errorf(
		"the device does not report %s; there is no fallback because legacy STAT and LIST report size as 32 bits, so a file over 4 GiB would be listed with a silently wrong size (device reported: %s)",
		strings.Join(missing, ", "),
		strings.Join(features, ","),
	)
}

// codeError carries the broker's classification of a failure alongside the failure itself.
//
// The type is unexported on purpose: the taxonomy in errcode is the contract, not this
// struct. A caller reads the classification through an interface assertion, as the package
// doc shows, and never by matching on a message.
type codeError struct {
	code errcode.Code
	msg  string
	err  error
}

// codeErr builds a classified error. err may be nil, for a failure this package decided
// on its own rather than one it is relaying.
func codeErr(code errcode.Code, err error, format string, args ...any) error {
	return &codeError{code: code, msg: fmt.Sprintf(format, args...), err: err}
}

func (e *codeError) Error() string {
	if e.err == nil {
		return e.code.String() + ": " + e.msg
	}

	return e.code.String() + ": " + e.msg + ": " + e.err.Error()
}

// Unwrap exposes the relayed failure, so errors.Is still reaches adbwire's sentinels
// through a classified error.
func (e *codeError) Unwrap() error { return e.err }

// Code returns the classification.
func (e *codeError) Code() errcode.Code { return e.code }

// codeForWire translates adbwire's sentinels into the broker's taxonomy. adbwire
// deliberately does not import business/types, so this is where the two vocabularies meet
// — and matching is by errors.Is, never on adb's prose, which is measured to be identical
// for several different failures.
//
// fallback is the caller's classification for a failure that is not one of the named
// conditions, because the right answer depends on what was being attempted: a dead sync
// channel is one failed transfer during a fetch and a truncated listing during a walk, and
// those are not the same news.
func codeForWire(err error, fallback errcode.Code) errcode.Code {
	switch {
	case errors.Is(err, adbwire.ErrNoServer):
		return errcode.CodeNoADBServer

	case errors.Is(err, adbwire.ErrUnauthorized):
		return errcode.CodeUnauthorized

	case errors.Is(err, adbwire.ErrOffline):
		return errcode.CodeOffline

	case errors.Is(err, adbwire.ErrNoDevices), errors.Is(err, adbwire.ErrDeviceNotFound):
		return errcode.CodeNoDevice

	case errors.Is(err, adbwire.ErrProtocol), errors.Is(err, adbwire.ErrSyncSessionDead):
		// Named explicitly rather than left to the default: these two are the ones whose
		// classification is genuinely context-dependent, and a reader should see that
		// this package knows it rather than assume they fell through.
		return fallback

	default:
		return fallback
	}
}

// codeForErrno translates an in-band device errno into the taxonomy. notFound is the code
// for ENOENT, which differs by position: a missing root ends one source, a missing file
// during a fetch ends one file.
//
// Measured trap: ENOENT does not prove absence.
// /data/data/com.android.providers.media answers error=2 although it exists — adbd hides
// existence rather than admitting a permission failure. So neither code may be presented
// to a human as proof a path is gone; the wording must say the path could not be read.
func codeForErrno(errno uint32, notFound errcode.Code) errcode.Code {
	switch errno {
	case errnoENOENT:
		return notFound

	case errnoEACCES:
		return errcode.CodePermissionDenied

	default:
		// An errno this broker has not measured is a per-path failure, not a fatal one:
		// the channel survived it, so one odd path must not end a run.
		return errcode.CodeTransferFailed
	}
}
