//go:build device

package adbwire

// These tests talk to a REAL phone through a REAL adb server. There is no phone
// attached to the machine these are normally developed and compiled on, and there
// will not be one while that is true: every test here skips, rather than fails,
// when the precondition it needs is not met, so `make test-device` stays
// meaningful to run on a day a phone genuinely is attached.
//
// Every assertion below encodes a value or a behaviour recorded in
// docs/adb_experiment.md. Where the manifest calls a value device-specific (a
// serial, a file size, a device number), the test asserts the property the
// design depends on rather than the literal — that is called out test by test.
//
// Nothing here sends SEND, writes to the phone, or reads an environment variable
// to select a device: the broker is setuid and ignores its environment, and a
// test that modelled reading one would be testing behaviour the binary refuses
// to have. With more than one device attached and no way to name one, the tests
// skip rather than guess.

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"slices"
	"testing"
	"time"

	"github.com/jroedel/adb-broker/business/types/devicepath"
)

// Device-side mode bits, as the sync protocol delivers them in Stat.Mode. Written
// out locally rather than imported from business/types/filekind: this package is
// foundation and does not depend on the business layer in its non-test code, and
// these four values are all this file needs.
const (
	stIFMT  = 0o170000 // S_IFMT: file-type mask
	stIFDIR = 0o040000 // S_IFDIR
	stIFREG = 0o100000 // S_IFREG
	stIFLNK = 0o120000 // S_IFLNK
)

// deviceFixture is what every test in this file needs once requireDevice has
// established it: the serial of the single attached, authorized device.
type deviceFixture struct {
	serial string
}

// requireDevice is THE skip helper for this file. It dials the real adb server,
// reads host:devices, and returns a deviceFixture naming the one usable device —
// or skips, explaining exactly which precondition failed, so a human reading
// `make test-device` output learns why nothing ran rather than seeing a cryptic
// failure.
//
// It skips, rather than fails, when:
//   - nothing is listening on ServerAddr (no adb server);
//   - host:devices returns an empty list — measured, this is OKAY with a
//     zero-length payload, not FAIL, so it is reported as "no device attached",
//     not as a protocol error;
//   - more than one device is attached with no serial to disambiguate (this
//     package never reads one from the environment);
//   - the single device's state token is anything other than "device" (e.g.
//     "unauthorized"), named verbatim in the skip message.
func requireDevice(t *testing.T) deviceFixture {
	t.Helper()

	ctx := deviceCtx(t)

	c, err := Dial(ctx)
	if errors.Is(err, ErrNoServer) {
		t.Skipf("no adb server listening on %s: %v", ServerAddr, err)
	}
	if err != nil {
		t.Fatalf("Dial: %v", err)
	}

	entries, err := c.Devices(ctx)
	if cerr := c.Close(); cerr != nil {
		t.Logf("closing the probe connection: %v", cerr)
	}
	if err != nil {
		t.Fatalf("Devices: %v", err)
	}

	switch {
	case len(entries) == 0:
		// Measured (Phase 0): with no phone attached, host:devices answers OKAY
		// with a zero-length payload, not FAIL. This is the no-device case, not
		// an error, and the message says so explicitly.
		t.Skip("no device attached (host:devices returned an empty list, which is OKAY with a zero-length payload, not a failure)")

	case len(entries) > 1:
		t.Skipf("%d devices are attached and no serial was given to disambiguate; this package never reads one from the environment, since the broker is setuid and ignores it", len(entries))
	}

	entry := entries[0]
	if entry.State != "device" {
		t.Skipf("the attached device %s is in state %q, not %q", redactSerial(entry.Serial), entry.State, "device")
	}

	return deviceFixture{serial: entry.Serial}
}

// deviceCtx bounds one test's exchanges with the real server, generously: several
// tests walk a bounded but real directory tree, which is slower than the
// synthetic fixtures elsewhere in this package.
func deviceCtx(t *testing.T) context.Context {
	t.Helper()

	ctx, cancel := context.WithTimeout(t.Context(), 2*time.Minute)
	t.Cleanup(cancel)

	return ctx
}

// dial opens a fresh Conn to the real server. It is plumbing, not a second skip
// helper: by the time a test calls this, requireDevice has already established
// that a server and an authorized device exist, so any failure here is a real
// failure and is reported with t.Fatalf rather than a skip.
func (f deviceFixture) dial(t *testing.T, ctx context.Context) *Conn {
	t.Helper()

	c, err := Dial(ctx)
	if err != nil {
		t.Fatalf("Dial: %v", err)
	}
	t.Cleanup(func() { _ = c.Close() })

	return c
}

// sync dials a fresh Conn, selects f's device as the transport, and opens a sync
// session on it. A Conn is single-use for a transport switch — Sync hands its
// socket to the returned SyncConn — so every test that needs a sync channel gets
// its own via this helper rather than sharing one across tests.
func (f deviceFixture) sync(t *testing.T, ctx context.Context) *SyncConn {
	t.Helper()

	c := f.dial(t, ctx)

	if err := c.TransportSerial(ctx, f.serial); err != nil {
		t.Fatalf("TransportSerial(%q): %v", f.serial, err)
	}

	sc, err := c.Sync(ctx)
	if err != nil {
		t.Fatalf("Sync: %v", err)
	}
	t.Cleanup(func() { _ = sc.Close() })

	return sc
}

// deviceFileStat is one regular file found while walking the allowlist roots
// looking for a real file to operate on.
type deviceFileStat struct {
	path string
	stat Stat
}

// collectDeviceFiles walks every root from devicepath.Roots(), depth-first, down
// to maxDepth levels, and returns every regular file it saw, capped at maxFiles.
//
// It never returns an error from a List callback to stop early: List's contract
// is that any callback error retires the whole sync session (the rest of the
// stream is still on the socket and cannot be accounted for), and several callers
// of this helper need the session alive again immediately afterward. So it always
// lets each LIS2 stream finish naturally, and merely stops recording once the cap
// is reached.
func collectDeviceFiles(t *testing.T, ctx context.Context, sc *SyncConn, maxDepth, maxFiles int) []deviceFileStat {
	t.Helper()

	var found []deviceFileStat

	var walk func(dir string, depth int)
	walk = func(dir string, depth int) {
		if depth > maxDepth || len(found) >= maxFiles {
			return
		}

		var subdirs []string

		err := sc.List(ctx, dir, func(d Dirent) error {
			name := string(d.Name)
			if name == "." || name == ".." || len(found) >= maxFiles {
				return nil
			}

			child := dir + "/" + name

			switch d.Mode & stIFMT {
			case stIFREG:
				found = append(found, deviceFileStat{path: child, stat: d.Stat})
			case stIFDIR:
				subdirs = append(subdirs, child)
			}

			return nil
		})
		if err != nil {
			t.Fatalf("List(%q) during the bounded device walk: %v", dir, err)
		}

		for _, sub := range subdirs {
			if len(found) >= maxFiles {
				return
			}
			walk(sub, depth+1)
		}
	}

	for _, root := range devicepath.Roots() {
		walk(root, 1)
	}

	return found
}

// TestDeviceProbeReportsDeviceState encodes Phase 2: host:devices reports the
// state token flipping from unauthorized to device once the trust dialog is
// accepted, and the short tab-separated form is the structured signal the whole
// broker reads device state from, in preference to any FAIL prose (which is
// measured to be identical across several distinct failures).
func TestDeviceProbeReportsDeviceState(t *testing.T) {
	fx := requireDevice(t)
	ctx := deviceCtx(t)
	c := fx.dial(t, ctx)

	entries, err := c.Devices(ctx)
	if err != nil {
		t.Fatalf("Devices: %v", err)
	}

	if len(entries) != 1 {
		t.Fatalf("Devices returned %d entries, want exactly 1 (requireDevice already gated on this): %v", len(entries), entries)
	}

	entry := entries[0]
	if entry.Serial == "" {
		t.Error("device entry has an empty serial")
	}
	if entry.State != "device" {
		t.Errorf("device state = %q, want %q", entry.State, "device")
	}
}

// TestDeviceFeaturesIncludeV2 encodes Phase 2: host-serial:<serial>:features on
// the authorized device includes stat_v2, ls_v2 and sendrecv_v2 — the three
// features the no-fallback size decision depends on. A failure here on real
// hardware means this phone genuinely lacks V2 support, which is exactly the
// condition the spec's hard-fail-rather-than-degrade path exists for.
func TestDeviceFeaturesIncludeV2(t *testing.T) {
	fx := requireDevice(t)
	ctx := deviceCtx(t)
	c := fx.dial(t, ctx)

	features, err := c.DeviceFeatures(ctx, fx.serial)
	if err != nil {
		t.Fatalf("DeviceFeatures(%q): %v", fx.serial, err)
	}

	for _, want := range []string{"stat_v2", "ls_v2", "sendrecv_v2"} {
		if !slices.Contains(features, want) {
			t.Errorf("device features %v do not include %q", features, want)
		}
	}
}

// TestDeviceFeaturesAreNotServerFeatures encodes Phase 1b, the spec bug: the
// server's own host:host-features answers "stat_v2,ls_v2,sendrecv_v2" with no
// device attached at all, because it describes the SERVER, not the phone — a V2
// gate wired to it can never fail. Measured, the two lists are genuinely
// different sets: the server's has push_sync, which the device's lacks; the
// device's has devraw, app_info and delayed_ack, which the server's lacks.
//
// adbwire deliberately provides no method to send host:host-features (see the
// package doc) — it is a trap this package refuses to be able to walk into — so
// this test cannot query both sides and diff them. It asserts the shape of the
// trap from the side that can be reached: the device list must contain a feature
// the server-side list is measured to lack (devraw), and must NOT contain one the
// server-side list is measured to have (push_sync). Say it plainly: a real
// failure here would mean this device's feature set has converged with the
// server's, which would be surprising news about the device rather than a test
// bug.
func TestDeviceFeaturesAreNotServerFeatures(t *testing.T) {
	fx := requireDevice(t)
	ctx := deviceCtx(t)
	c := fx.dial(t, ctx)

	features, err := c.DeviceFeatures(ctx, fx.serial)
	if err != nil {
		t.Fatalf("DeviceFeatures(%q): %v", fx.serial, err)
	}

	if !slices.Contains(features, "devraw") {
		t.Errorf("device features %v do not contain %q, which host:host-features (the server's own list) is measured to lack", features, "devraw")
	}
	if slices.Contains(features, "push_sync") {
		t.Errorf("device features %v contain %q, which is measured to appear only in host:host-features (the server's own list) — the device list should not match the server's", features, "push_sync")
	}
}

// TestDeviceLstatDoesNotFollowSymlinkButStatDoes encodes Phase 4.1 and 7b: /sdcard
// is itself a symlink (mode 0o120644) to /storage/self/primary, so LST2 and STA2
// on it genuinely disagree. This is the free test case the platform provides —
// no fixture symlink had to be created on the phone to prove "LST2 does not
// follow symlinks, STA2 does". It is also the finding that broke the original
// confinement design ("refuse a symlink at every path component" rejects every
// path meant to be allowed).
func TestDeviceLstatDoesNotFollowSymlinkButStatDoes(t *testing.T) {
	fx := requireDevice(t)
	ctx := deviceCtx(t)
	sc := fx.sync(t, ctx)

	lst, err := sc.Lstat(ctx, "/sdcard")
	if err != nil {
		t.Fatalf("Lstat(/sdcard): %v", err)
	}
	if lst.Errno != 0 {
		t.Fatalf("Lstat(/sdcard) errno = %d, want 0", lst.Errno)
	}
	if lst.Mode != 0o120644 {
		t.Errorf("Lstat(/sdcard) mode = 0o%o, want the measured 0o120644", lst.Mode)
	}
	if lst.Mode&stIFMT != stIFLNK {
		t.Errorf("Lstat(/sdcard) S_IFMT = 0o%o, want 0o%o (S_IFLNK)", lst.Mode&stIFMT, stIFLNK)
	}

	st, err := sc.Stat(ctx, "/sdcard")
	if err != nil {
		t.Fatalf("Stat(/sdcard): %v", err)
	}
	if st.Errno != 0 {
		t.Fatalf("Stat(/sdcard) errno = %d, want 0", st.Errno)
	}
	if st.Mode&stIFMT != stIFDIR {
		t.Errorf("Stat(/sdcard) S_IFMT = 0o%o, want 0o%o (S_IFDIR) — STA2 should follow the symlink", st.Mode&stIFMT, stIFDIR)
	}
}

// TestDeviceAllSixRootsExist encodes Phase 4: all six allowlist roots exist, are
// directories, mode 0o2770, uid=10269 gid=1023, and share one dev (measured:
// 190). dev is asserted as "shared across all six roots", not literally 190:
// device numbers are assigned at mount time and are not stable across reboots or
// remounts, which is exactly why devicepath.Volume pins it per run rather than
// compiling it in.
func TestDeviceAllSixRootsExist(t *testing.T) {
	fx := requireDevice(t)
	ctx := deviceCtx(t)
	sc := fx.sync(t, ctx)

	roots := devicepath.Roots()
	if len(roots) == 0 {
		t.Fatal("devicepath.Roots() returned no roots to check")
	}

	var commonDev int64

	for i, root := range roots {
		st, err := sc.Lstat(ctx, root)
		if err != nil {
			t.Fatalf("Lstat(%q): %v", root, err)
		}
		if st.Errno != 0 {
			t.Errorf("root %q: errno = %d, want 0 (exists)", root, st.Errno)
			continue
		}
		if st.Mode&stIFMT != stIFDIR {
			t.Errorf("root %q: S_IFMT = 0o%o, want 0o%o (S_IFDIR)", root, st.Mode&stIFMT, stIFDIR)
		}

		switch i {
		case 0:
			commonDev = st.Dev
		default:
			if st.Dev != commonDev {
				t.Errorf("root %q: dev=%d, want %d (the dev of %q) — all six roots should share one filesystem", root, st.Dev, commonDev, roots[0])
			}
		}
	}
}

// TestDeviceRootsHaveNoRegularFilesAtDepthOne encodes Phase 5: all 7 entries of
// /sdcard/DCIM and all 8 of /sdcard/Movies were directories, and no allowlist
// root had a single regular file at its own top level.
//
// This assertion — that an empty result is correct — looks backwards, and it is
// deliberate. The bug it guards against is a depth-limited listing silently
// reporting a phone with no photos on it: a confident, wrong, successful answer,
// not a crash. If a regular file ever does show up at depth one on real hardware,
// that is real news about how this device's storage is organised, not a broken
// test.
func TestDeviceRootsHaveNoRegularFilesAtDepthOne(t *testing.T) {
	fx := requireDevice(t)
	ctx := deviceCtx(t)
	sc := fx.sync(t, ctx)

	var depthOneEmpty int

	for _, root := range devicepath.Roots() {
		var regularCount int

		err := sc.List(ctx, root, func(d Dirent) error {
			if d.Mode&stIFMT == stIFREG {
				regularCount++
			}
			return nil
		})
		if err != nil {
			t.Fatalf("List(%q): %v", root, err)
		}

		// Reported, not asserted. The original version of this test required zero, on the
		// strength of a discovery run that sampled only DCIM and Movies and generalized to
		// all six roots. Measured 2026-07-31 that generalization is false: Download had 503
		// regular files at depth 1 and Pictures had 47, while DCIM, Movies, Music and
		// Recordings had none.
		//
		// Requiring zero would be asserting a property of one phone's file layout rather
		// than of this code, and it would fail the moment anyone saves a file to Download.
		// What matters is that the trap stays visible, and it is worse than uniformly empty:
		// a depth-limited configuration appears to work, because Download and Pictures
		// produce files, while silently archiving nothing from DCIM.
		t.Logf("root %q: %d regular file(s) at depth 1", root, regularCount)

		if regularCount == 0 {
			depthOneEmpty++
		}
	}

	// The trap only exists if at least one root is empty at depth 1. If a future device
	// has files at the top level of every root, a depth-limited run would no longer
	// silently archive nothing and this warning could be retired.
	if depthOneEmpty == 0 {
		t.Log("no root is empty at depth 1 on this device; the depth-1 trap does not arise here")
	} else {
		t.Logf("%d of %d roots are empty at depth 1: a --max-depth 1 run archives nothing from those",
			depthOneEmpty, len(devicepath.Roots()))
	}
}

// TestDeviceListDoneBodyDoesNotDesyncTheChannel is the regression test for the
// framing bug found while implementing List: LIS2's DONE is not a bare 4-byte
// ID here, it carries a full zeroed 72-byte dirent body (Phase 5) that must be
// consumed. A reader that stops at the ID leaves 72 stray bytes in the stream,
// desyncing every later command — which is what "these directories are all
// empty" turned out to be: a confident, silent, wrong answer, not an error on
// the listing itself. So this asserts on the command AFTER the listing, not on
// the listing.
func TestDeviceListDoneBodyDoesNotDesyncTheChannel(t *testing.T) {
	fx := requireDevice(t)
	ctx := deviceCtx(t)
	sc := fx.sync(t, ctx)

	root := devicepath.Roots()[0]

	if err := sc.List(ctx, root, func(Dirent) error { return nil }); err != nil {
		t.Fatalf("List(%q): %v", root, err)
	}

	st, err := sc.Stat(ctx, root)
	if err != nil {
		t.Fatalf("Stat(%q) after List on the same channel: %v — the channel likely desynced on the LIS2 DONE body", root, err)
	}
	if st.Errno != 0 {
		t.Errorf("Stat(%q) after List errno = %d, want 0", root, st.Errno)
	}
}

// TestDeviceRecvZeroByteFileProducesNoData encodes Phase 6: a zero-byte file
// produces NO DATA packets at all, just an immediate DONE. Its SHA-256 is the
// empty-input digest, which is also the value the spec's own example audit
// record uses. An implementation that expects at least one DATA packet, or
// treats "no data" as failure, breaks on a file exactly like this one.
func TestDeviceRecvZeroByteFileProducesNoData(t *testing.T) {
	fx := requireDevice(t)
	ctx := deviceCtx(t)
	sc := fx.sync(t, ctx)

	files := collectDeviceFiles(t, ctx, sc, 8, 3000)

	var target string
	for _, f := range files {
		if f.stat.Size == 0 {
			target = f.path
			break
		}
	}
	if target == "" {
		t.Skip("no zero-byte regular file found under the allowlist roots in a bounded walk")
	}

	var buf bytes.Buffer
	n, err := sc.Recv(ctx, target, &buf)
	if err != nil {
		t.Fatalf("Recv(%q): %v", target, err)
	}
	if n != 0 {
		t.Errorf("Recv(%q) returned %d bytes, want 0", target, n)
	}
	if buf.Len() != 0 {
		t.Errorf("Recv(%q) wrote %d bytes to the destination, want 0", target, buf.Len())
	}

	const emptyDigest = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"

	sum := sha256.Sum256(buf.Bytes())
	if got := hex.EncodeToString(sum[:]); got != emptyDigest {
		t.Errorf("SHA-256 of the zero-byte read = %s, want the empty-input digest %s", got, emptyDigest)
	}
}

// TestDeviceRecvByteCountMatchesListedSize encodes Phase 6: the byte count RECV
// delivers matched the size LIS2 reported exactly (a 27,190,943-byte file round
// tripped exactly). The consumer's incremental fast path depends on that equality
// holding exactly, not approximately — this asserts the property (listed size ==
// received bytes) against whichever file this bounded walk happens to find
// largest, since the literal size is device-specific.
func TestDeviceRecvByteCountMatchesListedSize(t *testing.T) {
	fx := requireDevice(t)
	ctx := deviceCtx(t)
	sc := fx.sync(t, ctx)

	files := collectDeviceFiles(t, ctx, sc, 8, 3000)
	if len(files) == 0 {
		t.Skip("no regular file found under the allowlist roots in a bounded walk")
	}

	largest := files[0]
	for _, f := range files[1:] {
		if f.stat.Size > largest.stat.Size {
			largest = f
		}
	}

	n, err := sc.Recv(ctx, largest.path, io.Discard)
	if err != nil {
		t.Fatalf("Recv(%q): %v", largest.path, err)
	}
	if n != largest.stat.Size {
		t.Errorf("Recv(%q) returned %d bytes, want exactly the listed size %d", largest.path, n, largest.stat.Size)
	}
}

// TestDeviceRecvDoneArgumentWidthIsFourBytes is the most important test in this
// file. RECV's terminating DONE argument width is the only unverified protocol
// assumption in the codebase: LIS2's DONE was measured to carry a full 72-byte
// dirent body (Phase 5), but RECV's was never measured, because Phase 6's
// successful transfers never needed to read past it. adbwire assumes a 4-byte
// argument (an 8-byte DONE packet total) on the strength of adb's own client
// (sizeof(msg.data)) and AOSP SYNC.TXT's note that the length is ignored — not
// on a device measurement.
//
// This settles it the only way that works: complete a real Recv, then issue
// another sync command on the SAME channel. If the width assumption is wrong,
// stray bytes remain on the wire and the following command desyncs — the same
// silent-wrong-answer shape as the LIS2 DONE bug, surfacing on the command AFTER
// this one rather than on the Recv itself. This test exists to settle
// adb_experiment.md's "Still untested" item.
func TestDeviceRecvDoneArgumentWidthIsFourBytes(t *testing.T) {
	fx := requireDevice(t)
	ctx := deviceCtx(t)
	sc := fx.sync(t, ctx)

	files := collectDeviceFiles(t, ctx, sc, 8, 1)
	if len(files) == 0 {
		t.Skip("no regular file found under the allowlist roots to Recv for this test")
	}

	if _, err := sc.Recv(ctx, files[0].path, io.Discard); err != nil {
		t.Fatalf("Recv(%q): %v", files[0].path, err)
	}

	root := devicepath.Roots()[0]

	st, err := sc.Stat(ctx, root)
	if err != nil {
		t.Fatalf("Stat(%q) after Recv on the same channel: %v — this is the RECV DONE-width regression this test exists to catch", root, err)
	}
	if st.Errno != 0 {
		t.Errorf("Stat(%q) after Recv errno = %d, want 0", root, st.Errno)
	}
}

// TestDeviceRecvFailIsTerminal encodes Phase 6c: a RECV FAIL is terminal.
// Measured messages were "open failed: No such file or directory", "open failed:
// Permission denied", and "read failed: Is a directory" — each on its own fresh
// channel, the channel was dead every time. This directly shapes the fetch loop:
// an unreadable file costs a full transport re-establishment, never a retry on
// the same channel.
func TestDeviceRecvFailIsTerminal(t *testing.T) {
	fx := requireDevice(t)
	ctx := deviceCtx(t)
	sc := fx.sync(t, ctx)

	root := devicepath.Roots()[0]

	_, err := sc.Recv(ctx, root, io.Discard)
	if err == nil {
		t.Fatalf("Recv(%q) succeeded; want it to fail because %q is a directory", root, root)
	}
	if !errors.Is(err, ErrSyncSessionDead) {
		t.Errorf("Recv(%q) error = %v, want it to wrap ErrSyncSessionDead", root, err)
	}
	t.Logf("Recv(directory) error (adb's prose, informational only): %v", err)

	if _, err := sc.Lstat(ctx, root); !errors.Is(err, ErrSyncSessionDead) {
		t.Errorf("Lstat after a failed Recv = %v, want ErrSyncSessionDead — the session should be dead, not merely unlucky", err)
	}
}

// TestDeviceErrnoIsInBandAndChannelSurvives encodes Phase 4.3 / 6c: unlike a RECV
// failure, an LST2 error is in-band — the errno lands in Stat.Errno with a nil Go
// error — and the channel survives. Measured, two further commands succeeded on
// the same socket after one such error.
func TestDeviceErrnoIsInBandAndChannelSurvives(t *testing.T) {
	fx := requireDevice(t)
	ctx := deviceCtx(t)
	sc := fx.sync(t, ctx)

	root := devicepath.Roots()[0]
	missing := root + "/adb-broker-device-test-nonexistent-path"

	st, err := sc.Lstat(ctx, missing)
	if err != nil {
		t.Fatalf("Lstat(%q): %v, want a nil error with the errno carried in-band", missing, err)
	}
	if st.Errno != 2 {
		t.Errorf("Lstat(%q) errno = %d, want 2 (ENOENT)", missing, st.Errno)
	}

	if _, err := sc.Lstat(ctx, root); err != nil {
		t.Errorf("Lstat(%q) after the ENOENT: %v, want the channel to still be usable", root, err)
	}
	if _, err := sc.Stat(ctx, root); err != nil {
		t.Errorf("Stat(%q) after the ENOENT: %v, want the channel to still be usable", root, err)
	}
}

// redactSerial shortens a device serial for test output.
//
// This repository has a standing rule that a device serial is never recorded in full: it is
// a durable, unique handle to a specific physical phone, and the docs were once corrected
// because an experiment record set that rule and then broke it six times. Test output ends up
// pasted into commit messages and findings documents, so the rule applies here too.
func redactSerial(s string) string {
	const keep = 4
	if len(s) <= keep {
		return "…"
	}

	return s[:keep] + "…"
}
