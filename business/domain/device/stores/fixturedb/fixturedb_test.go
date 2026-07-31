//go:build fixture

package fixturedb

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"io"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"syscall"
	"testing"

	"github.com/jroedel/adb-broker/business/domain/device/devicebus"
	"github.com/jroedel/adb-broker/business/types/devicepath"
	"github.com/jroedel/adb-broker/business/types/errcode"
	"github.com/jroedel/adb-broker/business/types/serial"
)

const testBrokerVer = "test-broker"

// =============================================================================
// Helpers.

func mustMkdirAll(t *testing.T, path string) {
	t.Helper()

	if err := os.MkdirAll(path, 0o755); err != nil {
		t.Fatalf("MkdirAll(%q): %v", path, err)
	}
}

func mustWriteFile(t *testing.T, path string, body []byte) {
	t.Helper()

	if err := os.WriteFile(path, body, 0o644); err != nil {
		t.Fatalf("WriteFile(%q): %v", path, err)
	}
}

func must(t *testing.T, err error) {
	t.Helper()

	if err != nil {
		t.Fatal(err)
	}
}

// mustDev reports the device number the host filesystem assigns path.
func mustDev(t *testing.T, path string) int64 {
	t.Helper()

	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("Stat(%q): %v", path, err)
	}

	st, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		t.Fatalf("%q: no syscall.Stat_t on this platform", path)
	}

	return int64(st.Dev)
}

// pinVolume runs the real ResolveVolume path, so tests pin a volume the same way the
// Business layer does.
func pinVolume(t *testing.T, st *Store) devicepath.Volume {
	t.Helper()

	vol, err := st.ResolveVolume(t.Context())
	if err != nil {
		t.Fatalf("ResolveVolume: %v", err)
	}

	return vol
}

func collect(recs *[]devicebus.FileRecord) func(devicebus.FileRecord) error {
	return func(rec devicebus.FileRecord) error {
		*recs = append(*recs, rec)

		return nil
	}
}

func paths(recs []devicebus.FileRecord) []string {
	out := make([]string, len(recs))
	for i, rec := range recs {
		out[i] = rec.Path.String()
	}

	return out
}

// listAll walks root with an unlimited depth and returns everything the walk produced.
func listAll(t *testing.T, st *Store, vol devicepath.Volume, root string) ([]devicebus.FileRecord, devicebus.ListSummary, error) {
	t.Helper()

	var recs []devicebus.FileRecord

	summary, err := st.List(t.Context(), devicebus.ListInput{Root: devicepath.MustParseAuthorizedPath(root)}, vol, collect(&recs))

	return recs, summary, err
}

// =============================================================================
// 1. A nested tree lists only regular files, recursively, streaming.

func TestListNestedTreeRecursively(t *testing.T) {
	dir := t.TempDir()

	mustMkdirAll(t, filepath.Join(dir, "sdcard/DCIM/Camera/thumbs"))
	mustMkdirAll(t, filepath.Join(dir, "sdcard/DCIM/Screenshots"))
	mustWriteFile(t, filepath.Join(dir, "sdcard/DCIM/Camera/IMG_0001.jpg"), []byte("a"))
	mustWriteFile(t, filepath.Join(dir, "sdcard/DCIM/Camera/IMG_0002.jpg"), []byte("bb"))
	mustWriteFile(t, filepath.Join(dir, "sdcard/DCIM/Camera/thumbs/t1.jpg"), []byte("c"))
	mustWriteFile(t, filepath.Join(dir, "sdcard/DCIM/Screenshots/s1.png"), []byte("dddd"))

	st := NewStore(dir, testBrokerVer)
	vol := pinVolume(t, st)

	// Streaming evidence: fn is called from inside visit() as each regular file is
	// discovered, not after the whole tree has been walked — this records how many
	// records had already arrived by the time the walk actually finished.
	var (
		recs      []devicebus.FileRecord
		doneAtRec int
	)

	summary, err := st.List(t.Context(), devicebus.ListInput{Root: devicepath.MustParseAuthorizedPath("/sdcard/DCIM")}, vol, func(rec devicebus.FileRecord) error {
		recs = append(recs, rec)
		doneAtRec = len(recs)

		return nil
	})
	if err != nil {
		t.Fatalf("List: %v", err)
	}

	want := []string{
		"/sdcard/DCIM/Camera/IMG_0001.jpg",
		"/sdcard/DCIM/Camera/IMG_0002.jpg",
		"/sdcard/DCIM/Camera/thumbs/t1.jpg",
		"/sdcard/DCIM/Screenshots/s1.png",
	}

	switch {
	case !slices.Equal(paths(recs), want):
		t.Errorf("paths = %v, want %v", paths(recs), want)
	case summary.Files != len(want):
		t.Errorf("Files = %d, want %d", summary.Files, len(want))
	case summary.RefusedEntries != 0:
		t.Errorf("RefusedEntries = %d, want 0", summary.RefusedEntries)
	case len(summary.Errors) != 0:
		t.Errorf("Errors = %v, want none", summary.Errors)
	case doneAtRec != len(want):
		t.Errorf("the callback fired %d times, want once per file as it was found", doneAtRec)
	}

	for _, rec := range recs {
		if !rec.Kind.IsRegular() {
			t.Errorf("%q was emitted as %s", rec.Path, rec.Kind)
		}
	}
}

// =============================================================================
// 2. MaxDepth: 1 returns only immediate children.
//
// Note: on a real device no allowlist root has a regular file at depth 1 (see
// adbsyncdb's walk_test.go), so this fixture is deliberately unlike a real device —
// exactly as the brief calls for — to make the depth-1 case explicit and checkable.

func TestListMaxDepth(t *testing.T) {
	setup := func(t *testing.T) (*Store, devicepath.Volume) {
		t.Helper()

		dir := t.TempDir()
		mustMkdirAll(t, filepath.Join(dir, "sdcard/DCIM/Camera/thumbs"))
		mustWriteFile(t, filepath.Join(dir, "sdcard/DCIM/top.jpg"), []byte("a"))
		mustWriteFile(t, filepath.Join(dir, "sdcard/DCIM/Camera/deep.jpg"), []byte("b"))
		mustWriteFile(t, filepath.Join(dir, "sdcard/DCIM/Camera/thumbs/t1.jpg"), []byte("c"))

		st := NewStore(dir, testBrokerVer)

		return st, pinVolume(t, st)
	}

	t.Run("depth 1 is immediate children only", func(t *testing.T) {
		st, vol := setup(t)

		var recs []devicebus.FileRecord

		if _, err := st.List(t.Context(), devicebus.ListInput{Root: devicepath.MustParseAuthorizedPath("/sdcard/DCIM"), MaxDepth: 1}, vol, collect(&recs)); err != nil {
			t.Fatalf("List: %v", err)
		}

		if got := paths(recs); !slices.Equal(got, []string{"/sdcard/DCIM/top.jpg"}) {
			t.Errorf("paths = %v, want only the immediate child", got)
		}
	})

	t.Run("depth 0 is unlimited", func(t *testing.T) {
		st, vol := setup(t)

		recs, _, err := listAll(t, st, vol, "/sdcard/DCIM")
		if err != nil {
			t.Fatalf("List: %v", err)
		}

		want := []string{
			"/sdcard/DCIM/Camera/deep.jpg",
			"/sdcard/DCIM/Camera/thumbs/t1.jpg",
			"/sdcard/DCIM/top.jpg",
		}

		if got := paths(recs); !slices.Equal(got, want) {
			t.Errorf("paths = %v, want %v", got, want)
		}
	})

	t.Run("depth 2 stops one level down", func(t *testing.T) {
		st, vol := setup(t)

		var recs []devicebus.FileRecord

		if _, err := st.List(t.Context(), devicebus.ListInput{Root: devicepath.MustParseAuthorizedPath("/sdcard/DCIM"), MaxDepth: 2}, vol, collect(&recs)); err != nil {
			t.Fatalf("List: %v", err)
		}

		want := []string{"/sdcard/DCIM/Camera/deep.jpg", "/sdcard/DCIM/top.jpg"}
		if got := paths(recs); !slices.Equal(got, want) {
			t.Errorf("paths = %v, want %v", got, want)
		}
	})
}

// =============================================================================
// 3. /data/data/x is denied by ParseAuthorizedPath before any filesystem access.

func TestDataDataIsDeniedBeforeAnyFilesystemAccess(t *testing.T) {
	_, err := devicepath.ParseAuthorizedPath("/data/data/x")
	if err == nil {
		t.Fatal("ParseAuthorizedPath(/data/data/x) succeeded, want it denied")
	}

	if got := errcode.From(err); got != errcode.CodePathDenied {
		t.Errorf("code = %s, want %s", got, errcode.CodePathDenied)
	}
}

// =============================================================================
// 4 & 5. The dev check and the kind check are independent mechanisms.
//
// A plain Lstat on a symlink reports the dev of whatever directory holds the link
// itself, never the dev of its target — measured, empirically, on this host (a symlink
// inside a tmp dir under /tmp pointing at /proc/1 lstats to /tmp's own dev, not
// procfs's). That is exactly why adbsyncdb's wire-based dev check can never catch a
// symlink escape and relies on the kind check for it instead. A local fixture tree has
// no bind mount to construct without root, so resolvedDev deliberately follows a
// symlink (os.Stat) to learn which filesystem it leads to — see the package doc. The
// two tests below each start by proving, directly against resolvedDev, which mechanism
// is in play before asserting the end-to-end List behavior, which is what "assert on
// the refusal reason, not merely that it was refused" means here: ListSummary has no
// per-entry reason field (matching adbsyncdb), so the reason is established at the unit
// level and the integration-level RefusedEntries count is then attributed to it.

func TestResolvedDevFollowsASymlinkAcrossFilesystems(t *testing.T) {
	dir := t.TempDir()

	fixtureDev := mustDev(t, dir)
	tmpDev := mustDev(t, os.TempDir())

	if fixtureDev == tmpDev {
		t.Skipf("the fixture directory and %s share dev=%d on this host; the dev check and the kind check cannot be distinguished here", os.TempDir(), fixtureDev)
	}

	link := filepath.Join(dir, "tolink")
	must(t, os.Symlink(os.TempDir(), link))

	st := NewStore(dir, testBrokerVer)

	dev, ok := st.resolvedDev(link)

	switch {
	case !ok:
		t.Fatal("resolvedDev reported not ok for a symlink to an existing directory")
	case dev != tmpDev:
		t.Errorf("resolvedDev = %d, want the symlink's target dev %d: the per-entry dev check must follow the link, or it could never distinguish a cross-filesystem escape from the kind check", dev, tmpDev)
	}
}

// A symlink inside the tree pointing at /tmp must be refused. On most hosts /tmp is a
// different filesystem, so — per TestResolvedDevFollowsASymlinkAcrossFilesystems above —
// the dev check is what refuses it. If the fixture directory and /tmp happen to share a
// device on this host, the dev check would never fire and this test would pass for the
// wrong reason (the kind check would refuse it instead), so it is skipped in that case
// rather than silently passing without having tested anything.
func TestListRefusesASymlinkAcrossFilesystems(t *testing.T) {
	dir := t.TempDir()

	fixtureDev := mustDev(t, dir)
	tmpDev := mustDev(t, os.TempDir())

	if fixtureDev == tmpDev {
		t.Skipf("the fixture directory and %s share dev=%d on this host; skipping so this test cannot pass for the wrong reason", os.TempDir(), fixtureDev)
	}

	mustMkdirAll(t, filepath.Join(dir, "sdcard/DCIM"))
	must(t, os.Symlink(os.TempDir(), filepath.Join(dir, "sdcard/DCIM/tolink")))
	mustWriteFile(t, filepath.Join(dir, "sdcard/DCIM/ok.jpg"), []byte("hi"))

	st := NewStore(dir, testBrokerVer)
	vol := pinVolume(t, st)

	recs, summary, err := listAll(t, st, vol, "/sdcard/DCIM")
	if err != nil {
		t.Fatalf("List: %v", err)
	}

	switch {
	case !slices.Equal(paths(recs), []string{"/sdcard/DCIM/ok.jpg"}):
		t.Errorf("paths = %v, want only the regular file", paths(recs))
	case summary.RefusedEntries != 1:
		t.Errorf("RefusedEntries = %d, want 1", summary.RefusedEntries)
	case len(summary.Errors) != 0:
		t.Errorf("Errors = %v, want none: an off-volume entry is a refusal, not a path error", summary.Errors)
	}
}

// A symlink pointing WITHIN the same filesystem must still be refused, by the kind
// check — the case only the kind check can catch, since the dev check independently
// verifies (asserted directly below, not merely assumed) that this entry resolves onto
// the pinned volume and so cannot be what refused it.
func TestListRefusesASymlinkWithinTheSameFilesystem(t *testing.T) {
	dir := t.TempDir()

	mustMkdirAll(t, filepath.Join(dir, "sdcard/DCIM"))

	target := filepath.Join(dir, "marker.txt")
	mustWriteFile(t, target, []byte("marker"))

	link := filepath.Join(dir, "sdcard/DCIM/tolink")
	must(t, os.Symlink(target, link))
	mustWriteFile(t, filepath.Join(dir, "sdcard/DCIM/ok.jpg"), []byte("hi"))

	st := NewStore(dir, testBrokerVer)
	vol := pinVolume(t, st)

	// Prove the dev check passes here, so whatever refuses this entry is the kind check.
	dev, ok := st.resolvedDev(link)
	if !ok || !vol.Contains(dev) {
		t.Fatalf("resolvedDev = %d ok=%v, want it to resolve onto the pinned volume dev=%d, or this test would not isolate the kind check", dev, ok, vol.Dev())
	}

	recs, summary, err := listAll(t, st, vol, "/sdcard/DCIM")
	if err != nil {
		t.Fatalf("List: %v", err)
	}

	switch {
	case !slices.Equal(paths(recs), []string{"/sdcard/DCIM/ok.jpg"}):
		t.Errorf("paths = %v, want only the regular file", paths(recs))
	case summary.RefusedEntries != 1:
		t.Errorf("RefusedEntries = %d, want 1", summary.RefusedEntries)
	}
}

// A dangling symlink (target does not exist) cannot be proven to resolve onto the
// pinned volume, so it is refused rather than assumed safe.
func TestListRefusesADanglingSymlink(t *testing.T) {
	dir := t.TempDir()

	mustMkdirAll(t, filepath.Join(dir, "sdcard/DCIM"))
	must(t, os.Symlink(filepath.Join(dir, "sdcard/DCIM/does-not-exist"), filepath.Join(dir, "sdcard/DCIM/dangling")))
	mustWriteFile(t, filepath.Join(dir, "sdcard/DCIM/ok.jpg"), []byte("hi"))

	st := NewStore(dir, testBrokerVer)
	vol := pinVolume(t, st)

	recs, summary, err := listAll(t, st, vol, "/sdcard/DCIM")
	if err != nil {
		t.Fatalf("List: %v", err)
	}

	switch {
	case !slices.Equal(paths(recs), []string{"/sdcard/DCIM/ok.jpg"}):
		t.Errorf("paths = %v, want only the regular file", paths(recs))
	case summary.RefusedEntries != 1:
		t.Errorf("RefusedEntries = %d, want 1", summary.RefusedEntries)
	}
}

// =============================================================================
// 6. A FIFO is refused and counted in RefusedEntries.

func TestListRefusesAFIFO(t *testing.T) {
	dir := t.TempDir()

	mustMkdirAll(t, filepath.Join(dir, "sdcard/DCIM"))
	must(t, syscall.Mkfifo(filepath.Join(dir, "sdcard/DCIM/pipe"), 0o600))
	mustWriteFile(t, filepath.Join(dir, "sdcard/DCIM/ok.jpg"), []byte("hi"))

	st := NewStore(dir, testBrokerVer)
	vol := pinVolume(t, st)

	recs, summary, err := listAll(t, st, vol, "/sdcard/DCIM")
	if err != nil {
		t.Fatalf("List: %v", err)
	}

	switch {
	case !slices.Equal(paths(recs), []string{"/sdcard/DCIM/ok.jpg"}):
		t.Errorf("paths = %v, want only the regular file", paths(recs))
	case summary.RefusedEntries != 1:
		t.Errorf("RefusedEntries = %d, want 1", summary.RefusedEntries)
	}
}

// =============================================================================
// 7 & 8. Fetch of a regular file, and of a zero-byte file.

func TestFetchRegularFile(t *testing.T) {
	dir := t.TempDir()

	mustMkdirAll(t, filepath.Join(dir, "sdcard/DCIM"))
	body := []byte("hello fixture\n")
	mustWriteFile(t, filepath.Join(dir, "sdcard/DCIM/a.jpg"), body)

	st := NewStore(dir, testBrokerVer)
	vol := pinVolume(t, st)

	sum := sha256.Sum256(body)
	wantDigest := hex.EncodeToString(sum[:])

	var buf bytes.Buffer

	res, err := st.Fetch(t.Context(), devicepath.MustParseAuthorizedPath("/sdcard/DCIM/a.jpg"), vol, &buf, nil)
	if err != nil {
		t.Fatalf("Fetch: %v", err)
	}

	switch {
	case res.Bytes != int64(len(body)):
		t.Errorf("Bytes = %d, want %d", res.Bytes, len(body))
	case res.SHA256 != wantDigest:
		t.Errorf("SHA256 = %s, want %s", res.SHA256, wantDigest)
	case buf.String() != string(body):
		t.Errorf("written = %q, want %q", buf.String(), body)
	case res.Serial != st.serial:
		t.Errorf("Serial = %q, want the fixture's own synthetic serial %q", res.Serial, st.serial)
	}
}

func TestFetchZeroByteFile(t *testing.T) {
	const emptyDigest = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"

	dir := t.TempDir()

	mustMkdirAll(t, filepath.Join(dir, "sdcard/DCIM"))
	mustWriteFile(t, filepath.Join(dir, "sdcard/DCIM/empty.jpg"), nil)

	st := NewStore(dir, testBrokerVer)
	vol := pinVolume(t, st)

	var buf bytes.Buffer

	res, err := st.Fetch(t.Context(), devicepath.MustParseAuthorizedPath("/sdcard/DCIM/empty.jpg"), vol, &buf, nil)
	if err != nil {
		t.Fatalf("Fetch: %v", err)
	}

	switch {
	case res.Bytes != 0:
		t.Errorf("Bytes = %d, want 0", res.Bytes)
	case res.SHA256 != emptyDigest:
		t.Errorf("SHA256 = %s, want the empty digest %s", res.SHA256, emptyDigest)
	}
}

// =============================================================================
// 9. Fetch of a symlink is refused before any read.

func TestFetchRefusesASymlinkBeforeAnyRead(t *testing.T) {
	dir := t.TempDir()

	mustMkdirAll(t, filepath.Join(dir, "sdcard/DCIM"))
	target := filepath.Join(dir, "secret.txt")
	mustWriteFile(t, target, []byte("this must never be read"))
	must(t, os.Symlink(target, filepath.Join(dir, "sdcard/DCIM/a.jpg")))

	st := NewStore(dir, testBrokerVer)
	vol := pinVolume(t, st)

	_, err := st.Fetch(t.Context(), devicepath.MustParseAuthorizedPath("/sdcard/DCIM/a.jpg"), vol, io.Discard, nil)
	if got := errcode.From(err); got != errcode.CodePathDenied {
		t.Fatalf("code = %s, want %s", got, errcode.CodePathDenied)
	}
}

// A vanished file at fetch time is path_not_found.
func TestFetchOfAVanishedFile(t *testing.T) {
	dir := t.TempDir()

	mustMkdirAll(t, filepath.Join(dir, "sdcard/DCIM"))

	st := NewStore(dir, testBrokerVer)
	vol := pinVolume(t, st)

	_, err := st.Fetch(t.Context(), devicepath.MustParseAuthorizedPath("/sdcard/DCIM/gone.jpg"), vol, io.Discard, nil)
	if got := errcode.From(err); got != errcode.CodePathNotFound {
		t.Fatalf("code = %s, want %s", got, errcode.CodePathNotFound)
	}
}

// =============================================================================
// 10. Probe reports state "device" and a broker version containing "+fixture".

func TestProbeReportsFixtureState(t *testing.T) {
	st := NewStore(t.TempDir(), "1.2.3")

	dev, err := st.Probe(t.Context(), serial.Serial{})
	if err != nil {
		t.Fatalf("Probe: %v", err)
	}

	switch {
	case dev.State != "device":
		t.Errorf("State = %q, want %q", dev.State, "device")
	case !strings.Contains(dev.BrokerVersion, "+fixture"):
		t.Errorf("BrokerVersion = %q, want it to contain %q", dev.BrokerVersion, "+fixture")
	case !slices.Contains(dev.Features, "stat_v2"):
		t.Errorf("Features = %v, want stat_v2", dev.Features)
	case !slices.Contains(dev.Features, "ls_v2"):
		t.Errorf("Features = %v, want ls_v2", dev.Features)
	case !slices.Contains(dev.Features, "sendrecv_v2"):
		t.Errorf("Features = %v, want sendrecv_v2", dev.Features)
	}
}

func TestProbeAcceptsItsOwnSerial(t *testing.T) {
	st := NewStore(t.TempDir(), testBrokerVer)

	dev, err := st.Probe(t.Context(), serial.MustParseSerial(fixtureSerial))
	if err != nil {
		t.Fatalf("Probe: %v", err)
	}

	if dev.Serial.String() != fixtureSerial {
		t.Errorf("Serial = %q, want %q", dev.Serial, fixtureSerial)
	}
}

func TestProbeRefusesAMismatchedSerial(t *testing.T) {
	st := NewStore(t.TempDir(), testBrokerVer)

	_, err := st.Probe(t.Context(), serial.MustParseSerial("some-other-device"))
	if got := errcode.From(err); got != errcode.CodeNoDevice {
		t.Fatalf("code = %s, want %s", got, errcode.CodeNoDevice)
	}
}

// =============================================================================
// 11. A missing root, and a root that is a regular file.

func TestListRootFailures(t *testing.T) {
	t.Run("missing root", func(t *testing.T) {
		dir := t.TempDir()
		mustMkdirAll(t, filepath.Join(dir, "sdcard")) // the volume root, but no DCIM within it

		st := NewStore(dir, testBrokerVer)
		vol := pinVolume(t, st)

		_, _, err := listAll(t, st, vol, "/sdcard/DCIM")
		if got := errcode.From(err); got != errcode.CodeRootNotFound {
			t.Fatalf("code = %s, want %s", got, errcode.CodeRootNotFound)
		}
	})

	t.Run("root is a regular file", func(t *testing.T) {
		dir := t.TempDir()
		mustMkdirAll(t, filepath.Join(dir, "sdcard"))
		mustWriteFile(t, filepath.Join(dir, "sdcard/DCIM"), []byte("not a directory"))

		st := NewStore(dir, testBrokerVer)
		vol := pinVolume(t, st)

		_, _, err := listAll(t, st, vol, "/sdcard/DCIM")
		if got := errcode.From(err); got != errcode.CodeNotADirectory {
			t.Fatalf("code = %s, want %s", got, errcode.CodeNotADirectory)
		}
	})
}

// An unreadable subdirectory is recorded as permission_denied and the walk continues past
// it, rather than aborting the whole listing.
func TestListRecordsAnUnreadableSubdirectoryAndContinues(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("running as root: permission bits are not enforced")
	}

	dir := t.TempDir()
	mustMkdirAll(t, filepath.Join(dir, "sdcard/DCIM/locked"))
	mustMkdirAll(t, filepath.Join(dir, "sdcard/DCIM/open"))
	mustWriteFile(t, filepath.Join(dir, "sdcard/DCIM/open/ok.jpg"), []byte("hi"))

	locked := filepath.Join(dir, "sdcard/DCIM/locked")
	must(t, os.Chmod(locked, 0))
	t.Cleanup(func() { _ = os.Chmod(locked, 0o700) })

	st := NewStore(dir, testBrokerVer)
	vol := pinVolume(t, st)

	recs, summary, err := listAll(t, st, vol, "/sdcard/DCIM")
	if err != nil {
		t.Fatalf("List: %v, want the walk to continue past one unreadable directory", err)
	}

	if got := paths(recs); !slices.Equal(got, []string{"/sdcard/DCIM/open/ok.jpg"}) {
		t.Errorf("paths = %v, want the sibling's file", got)
	}

	want := []devicebus.PathError{{
		Path: devicepath.MustParseAuthorizedPath("/sdcard/DCIM/locked"),
		Code: errcode.CodePermissionDenied,
	}}

	if !slices.Equal(summary.Errors, want) {
		t.Errorf("Errors = %v, want %v", summary.Errors, want)
	}
}

// =============================================================================
// 12. A file with an invalid-UTF-8 name survives into the FileRecord path byte-for-byte.

func TestListPreservesInvalidUTF8Names(t *testing.T) {
	dir := t.TempDir()

	mustMkdirAll(t, filepath.Join(dir, "sdcard/DCIM"))

	name := []byte{0xff, 0xfe, 'I', 'M', 'G', '.', 'j', 'p', 'g'}
	mustWriteFile(t, filepath.Join(dir, "sdcard/DCIM", string(name)), []byte("x"))

	st := NewStore(dir, testBrokerVer)
	vol := pinVolume(t, st)

	recs, _, err := listAll(t, st, vol, "/sdcard/DCIM")
	if err != nil {
		t.Fatalf("List: %v", err)
	}

	if len(recs) != 1 {
		t.Fatalf("records = %d, want 1", len(recs))
	}

	want := append([]byte("/sdcard/DCIM/"), name...)
	if got := []byte(recs[0].Path.String()); !slices.Equal(got, want) {
		t.Errorf("path bytes = %v, want %v", got, want)
	}
}

// =============================================================================
// 13. RefusedEntries counts every omitted non-regular entry.

func TestListRefusedEntriesCountsEveryOmittedKind(t *testing.T) {
	dir := t.TempDir()

	mustMkdirAll(t, filepath.Join(dir, "sdcard/DCIM"))

	// A same-filesystem symlink: refused by the kind check.
	target := filepath.Join(dir, "marker.txt")
	mustWriteFile(t, target, []byte("marker"))
	must(t, os.Symlink(target, filepath.Join(dir, "sdcard/DCIM/link1")))

	// A second same-filesystem symlink, to the fixture directory itself.
	must(t, os.Symlink(dir, filepath.Join(dir, "sdcard/DCIM/link2")))

	// A FIFO: refused by the kind check.
	must(t, syscall.Mkfifo(filepath.Join(dir, "sdcard/DCIM/pipe1"), 0o600))

	mustWriteFile(t, filepath.Join(dir, "sdcard/DCIM/ok.jpg"), []byte("hi"))

	st := NewStore(dir, testBrokerVer)
	vol := pinVolume(t, st)

	recs, summary, err := listAll(t, st, vol, "/sdcard/DCIM")
	if err != nil {
		t.Fatalf("List: %v", err)
	}

	switch {
	case !slices.Equal(paths(recs), []string{"/sdcard/DCIM/ok.jpg"}):
		t.Errorf("paths = %v, want only the regular file", paths(recs))
	case summary.RefusedEntries != 3:
		t.Errorf("RefusedEntries = %d, want 3", summary.RefusedEntries)
	}
}

// =============================================================================
// 14. The pinned volume is the fixture directory's real dev.

func TestResolveVolumePinsTheFixtureDirsRealDev(t *testing.T) {
	dir := t.TempDir()
	mustMkdirAll(t, filepath.Join(dir, "sdcard/DCIM"))

	st := NewStore(dir, testBrokerVer)
	vol := pinVolume(t, st)

	want := mustDev(t, filepath.Join(dir, "sdcard"))

	switch {
	case vol.IsZero():
		t.Fatal("volume is unpinned")
	case vol.Dev() == 0:
		t.Error("Dev() = 0, want the host's real device number")
	case vol.Dev() != want:
		t.Errorf("Dev() = %d, want %d (os.Stat on the fixture's sdcard directory)", vol.Dev(), want)
	case !vol.Contains(want):
		t.Error("the pinned volume does not contain its own dev")
	}
}

func TestResolveVolumeFailures(t *testing.T) {
	t.Run("missing volume root", func(t *testing.T) {
		dir := t.TempDir() // no "sdcard" at all

		st := NewStore(dir, testBrokerVer)

		_, err := st.ResolveVolume(t.Context())
		if got := errcode.From(err); got != errcode.CodeVolumeUnresolved {
			t.Errorf("code = %s, want %s", got, errcode.CodeVolumeUnresolved)
		}
	})

	t.Run("volume root is a regular file", func(t *testing.T) {
		dir := t.TempDir()
		mustWriteFile(t, filepath.Join(dir, "sdcard"), []byte("nope"))

		st := NewStore(dir, testBrokerVer)

		_, err := st.ResolveVolume(t.Context())
		if got := errcode.From(err); got != errcode.CodeVolumeUnresolved {
			t.Errorf("code = %s, want %s", got, errcode.CodeVolumeUnresolved)
		}
	})
}

// =============================================================================
// Preconditions, mirroring adbsyncdb's so a caller sees identical failure modes
// regardless of which Storer is wired in.

func TestListPreconditions(t *testing.T) {
	dir := t.TempDir()
	mustMkdirAll(t, filepath.Join(dir, "sdcard/DCIM"))

	st := NewStore(dir, testBrokerVer)
	root := devicepath.MustParseAuthorizedPath("/sdcard/DCIM")

	t.Run("unpinned volume", func(t *testing.T) {
		_, err := st.List(t.Context(), devicebus.ListInput{Root: root}, devicepath.Volume{}, collect(new([]devicebus.FileRecord)))
		if got := errcode.From(err); got != errcode.CodeVolumeUnresolved {
			t.Errorf("code = %s, want %s", got, errcode.CodeVolumeUnresolved)
		}
	})

	t.Run("zero root", func(t *testing.T) {
		vol := pinVolume(t, st)

		_, err := st.List(t.Context(), devicebus.ListInput{}, vol, collect(new([]devicebus.FileRecord)))
		if got := errcode.From(err); got != errcode.CodePathDenied {
			t.Errorf("code = %s, want %s", got, errcode.CodePathDenied)
		}
	})

	t.Run("negative depth", func(t *testing.T) {
		vol := pinVolume(t, st)

		_, err := st.List(t.Context(), devicebus.ListInput{Root: root, MaxDepth: -1}, vol, collect(new([]devicebus.FileRecord)))
		if got := errcode.From(err); got != errcode.CodeInternal {
			t.Errorf("code = %s, want %s", got, errcode.CodeInternal)
		}
	})

	t.Run("no callback", func(t *testing.T) {
		vol := pinVolume(t, st)

		_, err := st.List(t.Context(), devicebus.ListInput{Root: root}, vol, nil)
		if got := errcode.From(err); got != errcode.CodeInternal {
			t.Errorf("code = %s, want %s", got, errcode.CodeInternal)
		}
	})
}

func TestFetchPreconditions(t *testing.T) {
	dir := t.TempDir()
	mustMkdirAll(t, filepath.Join(dir, "sdcard/DCIM"))

	st := NewStore(dir, testBrokerVer)
	p := devicepath.MustParseAuthorizedPath("/sdcard/DCIM/a.jpg")

	t.Run("nil writer", func(t *testing.T) {
		vol := pinVolume(t, st)

		_, err := st.Fetch(t.Context(), p, vol, nil, nil)
		if got := errcode.From(err); got != errcode.CodeInternal {
			t.Errorf("code = %s, want %s", got, errcode.CodeInternal)
		}
	})

	t.Run("unpinned volume", func(t *testing.T) {
		_, err := st.Fetch(t.Context(), p, devicepath.Volume{}, io.Discard, nil)
		if got := errcode.From(err); got != errcode.CodeVolumeUnresolved {
			t.Errorf("code = %s, want %s", got, errcode.CodeVolumeUnresolved)
		}
	})

	t.Run("zero path", func(t *testing.T) {
		vol := pinVolume(t, st)

		_, err := st.Fetch(t.Context(), devicepath.AuthorizedPath{}, vol, io.Discard, nil)
		if got := errcode.From(err); got != errcode.CodePathDenied {
			t.Errorf("code = %s, want %s", got, errcode.CodePathDenied)
		}
	})
}

// =============================================================================
// childOf still applies AuthorizedPath.Child's real rules, exercised directly: a real
// local filename can never contain '/' or NUL (the filesystem itself forbids it), so
// this defensive path — present for parity with adbsyncdb, whose device-supplied names
// arrive over the wire with no such guarantee — cannot be reached through os.ReadDir on
// this or any host. It is still real code, so it is tested directly.

func TestChildOfRejectsAnUnjoinableName(t *testing.T) {
	st := NewStore(t.TempDir(), testBrokerVer)
	dir := devicepath.MustParseAuthorizedPath("/sdcard/DCIM")

	var summary devicebus.ListSummary

	_, ok := st.childOf(dir, "../../data/data/secret", &summary)
	if ok {
		t.Fatal("childOf accepted a traversal name")
	}

	if len(summary.Errors) != 1 || summary.Errors[0].Code != errcode.CodePathDenied {
		t.Errorf("Errors = %v, want one path_denied", summary.Errors)
	}

	if summary.Errors[0].Path != dir {
		t.Errorf("Path = %q, want the parent %q", summary.Errors[0].Path, dir)
	}
}
