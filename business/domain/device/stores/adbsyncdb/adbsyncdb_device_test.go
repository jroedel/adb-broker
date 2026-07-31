//go:build device

package adbsyncdb

// These tests exercise Store against a real phone through a real adb server.
// There is no phone attached to the machine these are normally compiled on, and
// there will not be one while that is true: every test skips, rather than
// fails, when the precondition it needs is not met.
//
// Each assertion below encodes a value or a behaviour recorded in
// docs/adb_experiment.md. Where the manifest calls a value device-specific (a
// dev number, a file size), the test asserts the property this store's design
// depends on rather than the literal — called out test by test.
//
// No environment variable selects a device here either, for the same reason as
// foundation/adbwire's device tests: the broker is setuid and ignores its
// environment, and a test that modelled reading one would test behaviour the
// binary refuses to have.

import (
	"bytes"
	"context"
	"errors"
	"slices"
	"testing"
	"time"

	"github.com/jroedel/adb-broker/business/domain/device/devicebus"
	"github.com/jroedel/adb-broker/business/types/devicepath"
	"github.com/jroedel/adb-broker/business/types/errcode"
	"github.com/jroedel/adb-broker/business/types/filekind"
	"github.com/jroedel/adb-broker/business/types/serial"
	"github.com/jroedel/adb-broker/foundation/adbwire"
)

// errStopSampling stops a List callback early once a test has collected enough
// records for its sample. Returning it deliberately kills the sync session —
// that is List's documented behaviour for any callback error, since the rest of
// the stream is still on the socket and cannot be accounted for. That is
// acceptable here: every caller that uses it either opens an independent
// adbwire connection afterward or does not need the Store's session again this
// test.
var errStopSampling = errors.New("adbsyncdb device test: sample limit reached")

// requireDeviceStore is THE skip helper for this file. It mirrors
// foundation/adbwire's own device-skip discipline — necessarily reimplemented
// rather than shared, since that helper is unexported in a different package —
// and returns a fresh Store together with the serial of the one usable device,
// or skips explaining exactly why.
//
// It skips, rather than fails, when:
//   - nothing is listening on adbwire.ServerAddr (no adb server);
//   - host:devices returns an empty list (no device attached — measured to be
//     OKAY with a zero-length payload, not a failure);
//   - more than one device is attached with no serial to disambiguate;
//   - the single device's state token is anything other than "device".
func requireDeviceStore(t *testing.T) (*Store, serial.Serial) {
	t.Helper()

	ctx := deviceStoreCtx(t)

	c, err := adbwire.Dial(ctx)
	if errors.Is(err, adbwire.ErrNoServer) {
		t.Skipf("no adb server listening on %s: %v", adbwire.ServerAddr, err)
	}
	if err != nil {
		t.Fatalf("adbwire.Dial: %v", err)
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
		t.Skip("no device attached (host:devices returned an empty list, which is OKAY with a zero-length payload, not a failure)")

	case len(entries) > 1:
		t.Skipf("%d devices are attached and no serial was given to disambiguate; this package never reads one from the environment, since the broker is setuid and ignores it", len(entries))
	}

	entry := entries[0]
	if entry.State != "device" {
		t.Skipf("the attached device %q is in state %q, not %q", entry.Serial, entry.State, "device")
	}

	ser, err := serial.ParseSerial(entry.Serial)
	if err != nil {
		t.Fatalf("serial.ParseSerial(%q): %v", entry.Serial, err)
	}

	return NewStore("adbsyncdb-device-test"), ser
}

// deviceStoreCtx bounds one test's exchanges with the real device, generously:
// several tests walk a real directory tree or transfer a real file, which is
// slower than the fake-transport tests elsewhere in this package.
func deviceStoreCtx(t *testing.T) context.Context {
	t.Helper()

	ctx, cancel := context.WithTimeout(t.Context(), 2*time.Minute)
	t.Cleanup(cancel)

	return ctx
}

// pathUnder reports whether child lies strictly beneath root, comparing whole
// path segments. devicepath has an equivalent (within) but it is unexported, so
// this is a small local reimplementation for this one assertion.
func pathUnder(child, root string) bool {
	return len(child) > len(root) && child[:len(root)] == root && child[len(root)] == '/'
}

// TestDeviceStoreProbeSucceedsAndGatesOnV2 encodes Phase 2 as seen through this
// store's own Probe: the device's feature list, read via
// host-serial:<serial>:features, includes stat_v2, ls_v2 and sendrecv_v2 — the
// three requireV2 gates on. Success here is itself evidence the gate passed
// against the real device: had any been missing, Probe would have failed with
// CodeUnsupported, and this store never queries host:host-features (the trap
// that would pass with no phone in the room at all).
func TestDeviceStoreProbeSucceedsAndGatesOnV2(t *testing.T) {
	store, ser := requireDeviceStore(t)
	ctx := deviceStoreCtx(t)

	dev, err := store.Probe(ctx, ser)
	if err != nil {
		t.Fatalf("Probe: %v", err)
	}

	if dev.State != "device" {
		t.Errorf("Probe device state = %q, want %q", dev.State, "device")
	}

	for _, want := range []string{"stat_v2", "ls_v2", "sendrecv_v2"} {
		if !slices.Contains(dev.Features, want) {
			t.Errorf("Probe device features %v do not include %q", dev.Features, want)
		}
	}
}

// TestDeviceStoreVolumePinResolvesToADirectory encodes Phase 4.1's fix: STA2
// /sdcard follows the platform's storage symlinks down to a real directory, and
// ResolveVolume pins its dev.
//
// It does NOT assert dev == 190: device numbers are assigned at mount time and
// differ across reboots and remounts, which is precisely why devicepath.Volume
// establishes the pin per run rather than compiling a number in. Asserting the
// literal here would make this test fail the first time the phone rebooted for
// a reason that has nothing to do with a regression.
func TestDeviceStoreVolumePinResolvesToADirectory(t *testing.T) {
	store, _ := requireDeviceStore(t)
	ctx := deviceStoreCtx(t)

	vol, err := store.ResolveVolume(ctx)
	if err != nil {
		t.Fatalf("ResolveVolume: %v", err)
	}
	if vol.IsZero() {
		t.Fatal("ResolveVolume returned an unpinned (zero) Volume")
	}
	if vol.Dev() == 0 {
		t.Error("ResolveVolume pinned dev=0, want a non-zero device number")
	}
}

// TestDeviceStoreListEmitsOnlyRegularFilesOnThePinnedVolume encodes the
// confinement guarantee walk.go implements: a full-depth List of one root emits
// only regular files, every one of them under that root, and ListSummary.Errors
// carries only per-path failures — never a fatal classification, since a fatal
// condition would have failed the whole List call instead of being recorded
// per-path.
func TestDeviceStoreListEmitsOnlyRegularFilesOnThePinnedVolume(t *testing.T) {
	store, ser := requireDeviceStore(t)
	ctx := deviceStoreCtx(t)

	vol, err := store.ResolveVolume(ctx)
	if err != nil {
		t.Fatalf("ResolveVolume: %v", err)
	}

	rootStr := devicepath.Roots()[0]
	root, err := devicepath.ParseAuthorizedPath(rootStr)
	if err != nil {
		t.Fatalf("ParseAuthorizedPath(%q): %v", rootStr, err)
	}

	var records []devicebus.FileRecord

	summary, err := store.List(ctx, devicebus.ListInput{Root: root, Serial: ser, MaxDepth: 0}, vol, func(rec devicebus.FileRecord) error {
		records = append(records, rec)
		return nil
	})
	if err != nil {
		t.Fatalf("List(%q): %v", rootStr, err)
	}

	for _, rec := range records {
		if rec.Kind != filekind.KindRegular {
			t.Errorf("List emitted %q with kind %s, want only regular files", rec.Path.String(), rec.Kind)
		}
		if !pathUnder(rec.Path.String(), rootStr) {
			t.Errorf("List emitted %q, which is not under root %q", rec.Path.String(), rootStr)
		}
	}

	for _, pe := range summary.Errors {
		if pe.Code.Fatal() {
			t.Errorf("ListSummary.Errors contains a fatal code %q for %q; List's Errors should hold only per-path warnings, and a fatal condition should have failed the whole call instead", pe.Code, pe.Path.String())
		}
	}

	t.Logf("List(%q) emitted %d files, refused %d entries, %d per-path errors", rootStr, summary.Files, summary.RefusedEntries, len(summary.Errors))
}

// TestDeviceStoreListedSizesMatchPerFileStat encodes Phase 4/6: size is
// genuinely 64-bit and round trips exactly, which is what the archiver's
// incremental fast path depends on. This samples a bounded set of emitted
// records rather than every one: a full-tree Lstat-per-file pass is a much
// larger operation than making this point requires.
func TestDeviceStoreListedSizesMatchPerFileStat(t *testing.T) {
	store, ser := requireDeviceStore(t)
	ctx := deviceStoreCtx(t)

	vol, err := store.ResolveVolume(ctx)
	if err != nil {
		t.Fatalf("ResolveVolume: %v", err)
	}

	rootStr := devicepath.Roots()[0]
	root, err := devicepath.ParseAuthorizedPath(rootStr)
	if err != nil {
		t.Fatalf("ParseAuthorizedPath(%q): %v", rootStr, err)
	}

	const sampleSize = 10

	var records []devicebus.FileRecord

	_, err = store.List(ctx, devicebus.ListInput{Root: root, Serial: ser, MaxDepth: 0}, vol, func(rec devicebus.FileRecord) error {
		records = append(records, rec)
		if len(records) >= sampleSize {
			return errStopSampling
		}
		return nil
	})
	if err != nil && !errors.Is(err, errStopSampling) {
		t.Fatalf("List(%q): %v", rootStr, err)
	}
	if len(records) == 0 {
		t.Skip("no regular files found under the first allowlist root to sample")
	}

	// The sampling List call above deliberately killed the store's session (any
	// callback error does), so this opens an independent connection for the
	// direct per-file stat — which is also a cleaner test of "did List's number
	// agree with a stat that owes it nothing", rather than reusing internal
	// state the store already trusted.
	c, err := adbwire.Dial(ctx)
	if err != nil {
		t.Fatalf("adbwire.Dial: %v", err)
	}
	defer func() { _ = c.Close() }()

	if err := c.TransportSerial(ctx, ser.String()); err != nil {
		t.Fatalf("TransportSerial(%q): %v", ser.String(), err)
	}

	sc, err := c.Sync(ctx)
	if err != nil {
		t.Fatalf("Sync: %v", err)
	}
	defer func() { _ = sc.Close() }()

	for _, rec := range records {
		st, err := sc.Lstat(ctx, rec.Path.String())
		if err != nil {
			t.Errorf("Lstat(%q): %v", rec.Path.String(), err)
			continue
		}
		if st.Errno != 0 {
			t.Errorf("Lstat(%q) errno = %d, want 0", rec.Path.String(), st.Errno)
			continue
		}
		if st.Size != rec.Size {
			t.Errorf("Lstat(%q) size = %d, List reported %d", rec.Path.String(), st.Size, rec.Size)
		}
		if st.Mtime != rec.Mtime.Seconds() {
			t.Errorf("Lstat(%q) mtime = %d, List reported %d", rec.Path.String(), st.Mtime, rec.Mtime.Seconds())
		}
	}
}

// TestDeviceStoreRefusesOffAllowlistRoot encodes the confinement guarantee at
// its strongest: /data/data, /sdcard and / are refused as roots BEFORE any
// AuthorizedPath naming them can even exist, since ParseAuthorizedPath is the
// only way to produce one and Store.List takes a devicepath.AuthorizedPath, not
// a string. "List an off-allowlist root" is therefore not merely rejected, it is
// a call that cannot be written — so it cannot open a transport connection
// either.
//
// A real device is required here only so this file's skip discipline stays
// uniform across all seven tests; none of the assertions below touch the
// network.
func TestDeviceStoreRefusesOffAllowlistRoot(t *testing.T) {
	requireDeviceStore(t)

	for _, s := range []string{"/data/data", "/sdcard", "/"} {
		_, err := devicepath.ParseAuthorizedPath(s)
		if err == nil {
			t.Errorf("ParseAuthorizedPath(%q) succeeded, want it refused", s)
			continue
		}
		if !errors.Is(err, devicepath.ErrPathDenied) {
			t.Errorf("ParseAuthorizedPath(%q) error = %v, want it to wrap devicepath.ErrPathDenied", s, err)
		}
		if got := errcode.From(err); got != errcode.CodePathDenied {
			t.Errorf("ParseAuthorizedPath(%q) classification = %q, want %q", s, got, errcode.CodePathDenied)
		}
	}
}

// TestDeviceStoreFetchDigestMatchesReRead fetches the same file twice and
// compares both the byte count and the digest.
//
// This does NOT prove end-to-end device integrity: the broker never re-reads
// the device to verify a transfer, and --verify-device was removed from the
// design because hashing on the phone needs a shell, which this binary will
// never open. It only proves the read path is deterministic across two
// independent Fetch calls of one path — a real bug if it ever fails, just a
// smaller claim than "the bytes are correct", and nobody should cite it as
// more than that.
func TestDeviceStoreFetchDigestMatchesReRead(t *testing.T) {
	store, ser := requireDeviceStore(t)
	ctx := deviceStoreCtx(t)

	vol, err := store.ResolveVolume(ctx)
	if err != nil {
		t.Fatalf("ResolveVolume: %v", err)
	}

	rootStr := devicepath.Roots()[0]
	root, err := devicepath.ParseAuthorizedPath(rootStr)
	if err != nil {
		t.Fatalf("ParseAuthorizedPath(%q): %v", rootStr, err)
	}

	var target devicepath.AuthorizedPath

	_, err = store.List(ctx, devicebus.ListInput{Root: root, Serial: ser, MaxDepth: 0}, vol, func(rec devicebus.FileRecord) error {
		if target.IsZero() {
			target = rec.Path
		}
		return errStopSampling
	})
	if err != nil && !errors.Is(err, errStopSampling) {
		t.Fatalf("List(%q): %v", rootStr, err)
	}
	if target.IsZero() {
		t.Skip("no regular file found under the first allowlist root to fetch")
	}

	var buf1 bytes.Buffer

	res1, err := store.Fetch(ctx, target, vol, &buf1)
	if err != nil {
		t.Fatalf("first Fetch(%q): %v", target.String(), err)
	}

	var buf2 bytes.Buffer

	res2, err := store.Fetch(ctx, target, vol, &buf2)
	if err != nil {
		t.Fatalf("second Fetch(%q): %v", target.String(), err)
	}

	if res1.Bytes != res2.Bytes {
		t.Errorf("byte counts differ across two Fetch calls of %q: %d vs %d", target.String(), res1.Bytes, res2.Bytes)
	}
	if res1.SHA256 != res2.SHA256 {
		t.Errorf("digests differ across two Fetch calls of %q: %s vs %s", target.String(), res1.SHA256, res2.SHA256)
	}
}

// TestDeviceStoreNoSymlinksFoundBelowTheRoots walks the allowlist roots and
// records how many entries were refused as non-regular or off-volume.
//
// Measured (Phase 7b): a bounded 12-directory walk over the media tree found
// 1,778 regular files and ZERO symlinks, so refusing symlinks below the root
// costs nothing on this device. This test asserts only that the walk completes
// — it does NOT assert RefusedEntries == 0, because the point is to make the
// cost of the refusal rule visible if it ever stops being zero, not to enforce
// that it stays zero. Depth is bounded for tractability across all six roots in
// one test run; the property under test does not need an exhaustive walk.
func TestDeviceStoreNoSymlinksFoundBelowTheRoots(t *testing.T) {
	store, ser := requireDeviceStore(t)
	ctx := deviceStoreCtx(t)

	vol, err := store.ResolveVolume(ctx)
	if err != nil {
		t.Fatalf("ResolveVolume: %v", err)
	}

	const boundedDepth = 6

	var totalFiles, totalRefused int

	for _, rootStr := range devicepath.Roots() {
		root, err := devicepath.ParseAuthorizedPath(rootStr)
		if err != nil {
			t.Fatalf("ParseAuthorizedPath(%q): %v", rootStr, err)
		}

		summary, err := store.List(ctx, devicebus.ListInput{Root: root, Serial: ser, MaxDepth: boundedDepth}, vol, func(devicebus.FileRecord) error {
			return nil
		})
		if err != nil {
			t.Fatalf("List(%q): %v", rootStr, err)
		}

		totalFiles += summary.Files
		totalRefused += summary.RefusedEntries
	}

	t.Logf("walked %d roots to depth %d: %d regular files, %d entries refused as non-regular or off-volume", len(devicepath.Roots()), boundedDepth, totalFiles, totalRefused)
}
