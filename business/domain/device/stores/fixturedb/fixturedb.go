//go:build fixture

// Package fixturedb implements devicebus.Storer over a local directory, so the whole
// broker path — probe, volume pin, list, fetch — can be exercised with no phone attached.
//
// # The build tag is a security control, not a convenience
//
// A flag that remaps /sdcard/… onto an arbitrary local directory is an allowlist bypass
// by construction: devicepath's whole guarantee is that no input read at runtime can
// widen this binary's authority, and a store that serves ANY local directory as though it
// were the device is exactly such an input. So this package, and every file in it, is
// gated by the fixture build tag and MUST NEVER be reachable from a build that omits it.
// There is no flag, no environment variable and no config key that selects it — the only
// way to get this code into a binary is to compile with -tags=fixture, which is why
// NewStore takes its directory as a constructor argument rather than reading one from the
// environment: a runtime-supplied fixture root, even behind a tag, would be one more thing
// to audit. Do not add a runtime switch that reaches this package from an untagged build,
// and do not weaken the tag to a flag "for convenience" — that is the one thing this
// comment exists to forbid.
//
// # Path mapping
//
// NewStore serves dir as the device's filesystem. A device path /sdcard/X maps to
// <dir>/sdcard/X, via filepath.Join — which is also why a caller can never walk out of
// dir: every device path this store is handed has already passed
// devicepath.ParseAuthorizedPath or AuthorizedPath.Child, so it is absolute, contains no
// ".." segment and no NUL byte, and Join has nothing to collapse.
//
// # Reproducing adbsyncdb's confinement on a local filesystem
//
// devicepath decides the confinement rules; this package applies them to a directory tree
// instead of a phone. Three checks are reproduced, and one of them is deliberately NOT a
// literal port, for a measured reason:
//
//   - The kind check. os.Lstat — which does not follow a symlink — classifies every entry.
//     Only a regular file is emitted; only a directory is descended into. A symlink,
//     socket, FIFO or device is refused and counted in RefusedEntries, exactly as
//     adbsyncdb's walk refuses them by filekind.
//
//   - The volume pin. ResolveVolume stats the fixture directory's own VolumeRoot mapping
//     with os.Stat — which DOES follow a symlink, matching the sync protocol's STA2 — and
//     pins its real dev, never a stubbed one. See devicepath.ResolveVolume.
//
//   - The per-entry dev check, during a List walk, is where this package parts from a
//     literal translation. adbsyncdb's LST2 never follows a symlink, so on the wire a
//     symlink's own dev is always the dev of the directory that holds it — measured, that
//     is why the wire-protocol dev check "cannot catch a symlink that stays on the
//     volume": ONLY a bind mount, which changes what filesystem a path resolves to without
//     any symlink at all, moves an entry's Lstat dev. A local fixture tree has no bind
//     mount a test can create without root, so a literal Lstat-only dev check here would
//     make devicepath.Volume.Contains's dev half untestable through this package. Instead,
//     the per-entry dev check follows a symlink (os.Stat) purely to learn which filesystem
//     it leads to, while the kind classification above still comes from Lstat and still
//     refuses every symlink outright, whatever its target. The two checks therefore run in
//     the same order adbsyncdb's do — dev first, kind second — and remain independent: a
//     symlink leading off the pinned volume is caught by the dev check before the kind
//     check ever runs, and a symlink resolving within the volume reaches the kind check and
//     is refused there, the one case a dev check can never catch. For a regular file, a
//     directory, or any other non-link entry, Stat and Lstat report the identical dev, so
//     nothing here is more permissive than the wire protocol — only more able to prove it
//     in a test. The listing root and Fetch's target are NOT given this treatment: both use
//     a plain Lstat dev check, matching adbsyncdb exactly, because neither has a test that
//     needs the distinction and a root or fetch target that is itself a symlink is refused
//     by the kind check regardless.
//
// # Error classification
//
// Every error this package returns carries an errcode.Code, exactly like adbsyncdb: an
// unexported type with an exported Code() method, wrapped so errcode.From (or a local
// errors.As against errcode.Coder) recovers it. A fixture store whose errors classified
// differently from the real one would make a fixture-mode test prove something about the
// fixture rather than about the broker.
package fixturedb

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"syscall"

	"github.com/jroedel/adb-broker/business/domain/device/devicebus"
	"github.com/jroedel/adb-broker/business/types/devicepath"
	"github.com/jroedel/adb-broker/business/types/errcode"
	"github.com/jroedel/adb-broker/business/types/filekind"
	"github.com/jroedel/adb-broker/business/types/mtime"
	"github.com/jroedel/adb-broker/business/types/serial"
)

// fixtureSerial is the serial this store reports for its one synthetic device. It is a
// compiled constant, not something derived from a request, which is what makes
// serial.MustParseSerial the right constructor here rather than a bug waiting to panic on
// bad input.
const fixtureSerial = "fixture-device"

// fixtureVersionSuffix is appended to the caller-supplied broker version on every Probe, so
// a fixture binary that somehow ran in a production path is visible in the very first probe
// response and in whatever audit log records it, rather than being indistinguishable from a
// real device session.
const fixtureVersionSuffix = "+fixture"

// fixtureFeatures is the V2 feature set this store reports, so the capability gate a real
// Probe applies (see adbsyncdb's requireV2) passes against a fixture exactly as it would
// against a device that actually speaks the V2 sync commands.
var fixtureFeatures = [...]string{"stat_v2", "ls_v2", "sendrecv_v2"}

// Store is the devicebus.Storer that serves dir as though it were the device's filesystem.
//
// It holds no session and no mutable state: every call re-reads the local filesystem, so
// concurrent use needs no lock of its own.
type Store struct {
	dir           string
	brokerVersion string
	serial        serial.Serial

	// failAfter truncates a fetch after this many bytes, or -1 to transfer whole files.
	// Zero is meaningful — truncate before the first byte — so the disabled value cannot
	// be zero.
	failAfter int64

	// injectError, when non-empty, is returned by every operation instead of doing it.
	injectError errcode.Code
}

// An Option configures a fixture Store. These exist only under the fixture build tag, so
// none of this reaches the release binary.
type Option func(*Store)

// WithFailAfter truncates a fetch after n bytes, so a consumer's truncated-transfer path can
// be tested deliberately rather than hoped about.
//
// The truncation happens AFTER the size has been handed to the caller's framing callback and
// after the header is therefore already on stdout. That is the point: it reproduces the one
// failure shape a consumer cannot otherwise produce — a stream that promised n bytes and
// delivered fewer — which is what makes the required-trailer rule testable at all.
func WithFailAfter(n int64) Option {
	return func(st *Store) { st.failAfter = n }
}

// WithInjectError makes every operation fail with code instead of doing anything.
//
// A consumer's branching on the taxonomy's codes is safety-critical — the difference between
// skipping one file and aborting a run — and is otherwise reachable only by contriving a
// real device fault for each one. Injection makes each branch reachable on demand.
func WithInjectError(code errcode.Code) Option {
	return func(st *Store) { st.injectError = code }
}

// Compile-time proof this store is usable as the Business layer's port.
var _ devicebus.Storer = (*Store)(nil)

// NewStore constructs a Store serving dir as the device's filesystem. brokerVersion is
// reported on Probe with fixtureVersionSuffix appended.
func NewStore(dir, brokerVersion string, opts ...Option) *Store {
	st := &Store{
		dir:           dir,
		brokerVersion: brokerVersion,
		serial:        serial.MustParseSerial(fixtureSerial),
		failAfter:     -1,
	}

	for _, opt := range opts {
		if opt != nil {
			opt(st)
		}
	}

	return st
}

// injected reports the error to return instead of performing an operation, or nil.
func (s *Store) injected(op string) error {
	if s.injectError == "" {
		return nil
	}

	return codeErr(s.injectError, nil, "%s: error injected by fixture mode", op)
}

// mapRaw maps a raw device path string onto dir. It is used directly only for
// devicepath.VolumeRoot, which is a compiled constant and not an AuthorizedPath; every
// other caller of this store supplies an AuthorizedPath and goes through localPath instead.
func (s *Store) mapRaw(devicePath string) string {
	return filepath.Join(s.dir, devicePath)
}

// localPath maps an already-authorized device path onto dir. p has necessarily passed
// devicepath.ParseAuthorizedPath or AuthorizedPath.Child, so it is absolute, contains no
// ".." segment and no NUL byte — filepath.Join has nothing to collapse and cannot be made
// to escape dir.
func (s *Store) localPath(p devicepath.AuthorizedPath) string {
	return s.mapRaw(p.String())
}

// Probe reports this store's one synthetic device: state "device", the caller's broker
// version with fixtureVersionSuffix appended, and the V2 feature set the capability gate
// requires. It reports no model, matching adbsyncdb; see adbsyncdb.Store.Probe for why.
//
// AttachedDevices is 1, and it is a fact about this store rather than a stub: a fixture
// Store serves exactly one synthetic device — Probe refuses any serial but its own — so
// there is never a second one to count. That makes fixture mode the "unambiguous device"
// case, which is the case a consumer uses the count to detect, so a consumer exercised
// against a fixture takes the same branch it would take against one attached phone.
func (s *Store) Probe(_ context.Context, ser serial.Serial) (devicebus.Device, error) {
	if err := s.injected("probe"); err != nil {
		return devicebus.Device{}, err
	}

	if !ser.IsZero() && ser != s.serial {
		return devicebus.Device{}, codeErr(errcode.CodeNoDevice, nil, "the fixture serves only %q, not %q", s.serial.String(), ser.String())
	}

	features := make([]string, len(fixtureFeatures))
	copy(features, fixtureFeatures[:])

	return devicebus.Device{
		Serial:          s.serial,
		State:           "device",
		BrokerVersion:   s.brokerVersion + fixtureVersionSuffix,
		ServerVersion:   "fixture",
		Features:        features,
		AttachedDevices: 1,
	}, nil
}

// ResolveVolume pins the fixture directory's own volume by stat'ing its VolumeRoot mapping
// with os.Stat, which follows a symlink exactly as the sync protocol's STA2 does. The
// pinned dev is whatever the host filesystem actually assigns <dir>/sdcard — never a
// stubbed value — so the pin is exercised for real, not merely simulated.
func (s *Store) ResolveVolume(_ context.Context) (devicepath.Volume, error) {
	vol, err := devicepath.ResolveVolume(s.statFollow)
	if err != nil {
		return devicepath.Volume{}, codeErr(errcode.CodeVolumeUnresolved, err, "pin the fixture directory's volume")
	}

	return vol, nil
}

// statFollow implements devicepath.StatFunc against the fixture directory.
func (s *Store) statFollow(path string) (dev, ino int64, mode uint32, err error) {
	local := s.mapRaw(path)

	info, err := os.Stat(local)
	if err != nil {
		return 0, 0, 0, err
	}

	st, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return 0, 0, 0, fmt.Errorf("%s: no syscall.Stat_t available on this platform", local)
	}

	return int64(st.Dev), int64(st.Ino), st.Mode, nil
}

// devOf extracts the device number syscall.Stat_t reports for info, or false if the
// platform's FileInfo.Sys() does not provide one.
func devOf(info fs.FileInfo) (int64, bool) {
	st, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return 0, false
	}

	return int64(st.Dev), true
}

// List walks in.Root, emitting one FileRecord per regular file as it is discovered.
func (s *Store) List(ctx context.Context, in devicebus.ListInput, vol devicepath.Volume, fn func(devicebus.FileRecord) error) (devicebus.ListSummary, error) {
	if err := s.injected("list"); err != nil {
		return devicebus.ListSummary{}, err
	}

	switch {
	case fn == nil:
		return devicebus.ListSummary{}, codeErr(errcode.CodeInternal, nil, "List needs a record callback")

	case vol.IsZero():
		return devicebus.ListSummary{}, codeErr(errcode.CodeVolumeUnresolved, nil, "listing %q was attempted with an unpinned volume", in.Root.String())

	case in.Root.IsZero():
		return devicebus.ListSummary{}, codeErr(errcode.CodePathDenied, nil, "listing was attempted with the zero path, which names nothing")

	case in.MaxDepth < 0:
		return devicebus.ListSummary{}, codeErr(errcode.CodeInternal, nil, "MaxDepth %d has no meaning; 0 is unlimited and 1 is immediate children", in.MaxDepth)
	}

	var summary devicebus.ListSummary

	err := s.walkRoot(ctx, in.Root, vol, in.MaxDepth, fn, &summary)

	return summary, err
}

// walkRoot checks the listing root's own kind and dev — via os.Lstat, never following a
// symlink, exactly like adbsyncdb's LST2-based walkRoot — and then walks it.
func (s *Store) walkRoot(ctx context.Context, root devicepath.AuthorizedPath, vol devicepath.Volume, maxDepth int, fn func(devicebus.FileRecord) error, summary *devicebus.ListSummary) error {
	local := s.localPath(root)

	info, err := os.Lstat(local)
	if err != nil {
		return codeErr(codeForRootStatErr(err), err, "the listing root %q could not be read", root.String())
	}

	if !info.IsDir() {
		return codeErr(errcode.CodeNotADirectory, nil, "the listing root %q is not a directory", root.String())
	}

	dev, ok := devOf(info)
	if !ok {
		return codeErr(errcode.CodeInternal, nil, "the listing root %q has no dev information on this platform", root.String())
	}

	if !vol.Contains(dev) {
		return codeErr(errcode.CodePathDenied, nil, "the listing root %q is on dev=%d, not the pinned volume dev=%d", root.String(), dev, vol.Dev())
	}

	return s.walkDir(ctx, root, 1, vol, maxDepth, fn, summary)
}

// walkDir lists one directory and recurses into the subdirectories it accepted. depth is
// the depth of the ENTRIES this call will see: dir's own children are at depth 1, which is
// what MaxDepth: 1 means.
func (s *Store) walkDir(ctx context.Context, dir devicepath.AuthorizedPath, depth int, vol devicepath.Volume, maxDepth int, fn func(devicebus.FileRecord) error, summary *devicebus.ListSummary) error {
	if err := ctx.Err(); err != nil {
		return codeErr(errcode.CodeInternal, err, "listing %q was cancelled", dir.String())
	}

	entries, err := os.ReadDir(s.localPath(dir))
	if err != nil {
		// Recorded and stepped over: an unreadable directory says nothing about its
		// siblings, so it must not end the whole walk.
		summary.Errors = append(summary.Errors, devicebus.PathError{Path: dir, Code: errcode.CodePermissionDenied})

		return nil
	}

	mayDescend := maxDepth == 0 || depth < maxDepth

	for _, entry := range entries {
		child, ok := s.childOf(dir, entry.Name(), summary)
		if !ok {
			continue
		}

		if err := s.visit(ctx, dir, child, depth, mayDescend, vol, maxDepth, fn, summary); err != nil {
			return err
		}
	}

	return nil
}

// visit applies the per-entry rules to one directory entry: the dev check (which follows a
// symlink; see the package doc for why), then the kind check (which does not), then either
// emits a regular file, descends into a directory, or refuses anything else.
func (s *Store) visit(ctx context.Context, dir, child devicepath.AuthorizedPath, depth int, mayDescend bool, vol devicepath.Volume, maxDepth int, fn func(devicebus.FileRecord) error, summary *devicebus.ListSummary) error {
	local := s.localPath(child)

	lst, err := os.Lstat(local)
	if err != nil {
		summary.Errors = append(summary.Errors, devicebus.PathError{Path: child, Code: errcode.CodePathNotFound})

		return nil
	}

	resolvedDev, ok := s.resolvedDev(local)
	if !ok || !vol.Contains(resolvedDev) {
		summary.RefusedEntries++

		return nil
	}

	switch {
	case lst.Mode().IsRegular():
		rec := devicebus.FileRecord{
			Path:  child,
			Size:  lst.Size(),
			Mtime: mtime.ParseMtime(lst.ModTime().Unix()),
			Kind:  filekind.KindRegular,
		}

		if err := fn(rec); err != nil {
			return err
		}

		summary.Files++

		return nil

	case lst.IsDir():
		if !mayDescend {
			// Beyond the requested depth: not refused and not an error, simply not
			// visited, so it is counted as neither.
			return nil
		}

		return s.walkDir(ctx, child, depth+1, vol, maxDepth, fn, summary)

	default:
		// A symlink that resolved onto the pinned volume, a socket, a FIFO, or a device.
		// The dev check above cannot catch a same-volume symlink — the link resolves
		// right back onto the pinned volume — so the kind check is what refuses it here,
		// never followed and never emitted.
		summary.RefusedEntries++

		return nil
	}
}

// resolvedDev reports the device number local ultimately resolves to, following a symlink
// the way os.Stat does. For a regular file, a directory, or any other non-link entry this
// is identical to its own Lstat dev, so nothing changes for them. See the package doc for
// why the per-entry check needs this and the root and Fetch checks do not.
func (s *Store) resolvedDev(local string) (int64, bool) {
	info, err := os.Stat(local)
	if err != nil {
		// Cannot prove where this leads — a dangling symlink, a loop, or a target this
		// process cannot reach — so it is refused rather than assumed safe.
		return 0, false
	}

	return devOf(info)
}

// childOf builds the path for one directory entry via AuthorizedPath.Child, never string
// concatenation, so a name this constructor refuses is reported against the parent
// directory rather than silently vanishing from both the records and the errors.
func (s *Store) childOf(dir devicepath.AuthorizedPath, name string, summary *devicebus.ListSummary) (devicepath.AuthorizedPath, bool) {
	child, err := dir.Child([]byte(name))
	if err != nil {
		summary.Errors = append(summary.Errors, devicebus.PathError{Path: dir, Code: errcode.CodePathDenied})

		return devicepath.AuthorizedPath{}, false
	}

	return child, true
}

// Fetch streams p's contents to w and reports the byte count, the SHA-256 of the bytes
// forwarded, and the synthetic serial this store reports on every Probe.
//
// The path is checked with os.Lstat — which does NOT follow a symlink — before any read:
// it must be a regular file and its dev must equal the pinned volume's. A symlink is
// refused here even though os.Open would happily follow it, which is the whole point of
// using Lstat rather than Stat. As in adbsyncdb, there is a window between the Lstat and
// the Open in which the entry could be replaced; that race is accepted rather than closed,
// for the same reason: nothing this store's caller can do would close it either.
func (s *Store) Fetch(_ context.Context, p devicepath.AuthorizedPath, vol devicepath.Volume, w io.Writer, before func(devicebus.FetchInfo) error) (devicebus.FetchResult, error) {
	if err := s.injected("fetch"); err != nil {
		return devicebus.FetchResult{}, err
	}

	switch {
	case w == nil:
		return devicebus.FetchResult{}, codeErr(errcode.CodeInternal, nil, "Fetch needs a destination writer")

	case vol.IsZero():
		return devicebus.FetchResult{}, codeErr(errcode.CodeVolumeUnresolved, nil, "fetching %q was attempted with an unpinned volume", p.String())

	case p.IsZero():
		return devicebus.FetchResult{}, codeErr(errcode.CodePathDenied, nil, "fetch was attempted with the zero path, which names nothing")
	}

	local := s.localPath(p)

	info, err := os.Lstat(local)
	if err != nil {
		return devicebus.FetchResult{}, codeErr(codeForFetchStatErr(err), err, "lstat %q", p.String())
	}

	dev, ok := devOf(info)
	if !ok {
		return devicebus.FetchResult{}, codeErr(errcode.CodeInternal, nil, "%q has no dev information on this platform", p.String())
	}

	switch {
	case !info.Mode().IsRegular():
		// CodeNotARegularFile, matching adbsyncdb exactly — a fixture whose kind check
		// classified differently from the real store would make a fixture-mode test prove
		// something about the fixture. Nothing about what is refused changed, including
		// for a symlink; see errcode.CodeNotARegularFile for why the scope is per-file.
		return devicebus.FetchResult{}, codeErr(errcode.CodeNotARegularFile, nil, "%q is not a regular file, and only regular files are transferred", p.String())

	case !vol.Contains(dev):
		return devicebus.FetchResult{}, codeErr(errcode.CodePathDenied, nil, "%q is on dev=%d, not the pinned volume dev=%d", p.String(), dev, vol.Dev())
	}

	f, err := os.Open(local)
	if err != nil {
		return devicebus.FetchResult{}, codeErr(codeForFetchStatErr(err), err, "open %q", p.String())
	}
	defer f.Close()

	// Handed over before a byte moves, from the same Lstat the confinement checks used,
	// so a caller frames the stream rather than buffering it. Mirrors adbsyncdb.
	if before != nil {
		if err := before(devicebus.FetchInfo{Size: info.Size()}); err != nil {
			return devicebus.FetchResult{}, err
		}
	}

	digest := sha256.New()

	// A truncated transfer, on demand. The header is already on stdout promising
	// info.Size() bytes, so stopping short here produces the one shape a consumer cannot
	// otherwise be made to face: fewer bytes than promised, followed by whatever the
	// framing does next. That is what makes the required-trailer rule testable.
	if s.failAfter >= 0 {
		n, err := io.Copy(io.MultiWriter(w, digest), io.LimitReader(f, s.failAfter))
		if err != nil {
			return devicebus.FetchResult{}, codeErr(errcode.CodeTransferFailed, err, "read %q stopped after %d bytes", p.String(), n)
		}

		return devicebus.FetchResult{}, codeErr(errcode.CodeTransferFailed, nil,
			"fixture mode truncated %q after %d of %d bytes", p.String(), n, info.Size())
	}

	n, err := io.Copy(io.MultiWriter(w, digest), f)
	if err != nil {
		return devicebus.FetchResult{}, codeErr(errcode.CodeTransferFailed, err, "read %q stopped after %d bytes", p.String(), n)
	}

	return devicebus.FetchResult{
		Bytes:  n,
		SHA256: hex.EncodeToString(digest.Sum(nil)),
		Serial: s.serial,
	}, nil
}

// codeForRootStatErr classifies a failure to Lstat the listing root. Anything other than a
// permission failure is reported as root_not_found — matching errcode.CodeRootNotFound's
// own doc, a root that could not be read is not proof it is absent, so the same code covers
// both a missing directory and any other reason the stat failed.
func codeForRootStatErr(err error) errcode.Code {
	code := errcode.CodeRootNotFound
	if errors.Is(err, fs.ErrPermission) {
		code = errcode.CodePermissionDenied
	}

	return code
}

// codeForFetchStatErr classifies a failure to Lstat or Open a fetch target: a vanished file
// is path_not_found, a permission failure is permission_denied, and anything else is
// transfer_failed — a per-file failure that must not end the run.
func codeForFetchStatErr(err error) errcode.Code {
	code := errcode.CodeTransferFailed

	switch {
	case errors.Is(err, fs.ErrNotExist):
		code = errcode.CodePathNotFound
	case errors.Is(err, fs.ErrPermission):
		code = errcode.CodePermissionDenied
	}

	return code
}

// codeError carries the broker's classification of a failure alongside the failure itself.
// The type is unexported: the taxonomy in errcode is the contract, not this struct. It
// mirrors adbsyncdb's codeError exactly, so a caller recovers the code the same way
// regardless of which Storer produced the failure.
type codeError struct {
	code errcode.Code
	msg  string
	err  error
}

// codeErr builds a classified error. err may be nil, for a failure this package decided on
// its own rather than one it is relaying.
func codeErr(code errcode.Code, err error, format string, args ...any) error {
	return &codeError{code: code, msg: fmt.Sprintf(format, args...), err: err}
}

func (e *codeError) Error() string {
	if e.err == nil {
		return e.code.String() + ": " + e.msg
	}

	return e.code.String() + ": " + e.msg + ": " + e.err.Error()
}

// Unwrap exposes the relayed failure, so errors.Is and errcode.From still reach it through
// a classified error.
func (e *codeError) Unwrap() error { return e.err }

// Code returns the classification, satisfying errcode.Coder.
func (e *codeError) Code() errcode.Code { return e.code }
