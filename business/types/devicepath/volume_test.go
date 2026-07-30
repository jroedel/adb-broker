package devicepath

import (
	"errors"
	"fmt"
	"strings"
	"testing"
)

// Modes and device numbers measured on the target device, so the fixtures below are the
// real shapes rather than invented ones.
const (
	measuredDirMode     = 0o042770 // STA2 /sdcard -> dir
	measuredSymlinkMode = 0o120644 // LST2 /sdcard -> SYMLINK, target /storage/self/primary
	measuredRegularMode = 0o100644

	measuredMediaDev = 190   // the media volume
	measuredMediaIno = 3252  // /storage/emulated/0, which /sdcard resolves to
	measuredDataDev  = 65088 // /data
	measuredRootDev  = 65034 // the root filesystem, and the dev of the /sdcard symlink itself
)

// statFor returns a StatFunc that answers with fixed values and records what it was asked.
func statFor(dev, ino int64, mode uint32, err error) (StatFunc, *[]string) {
	var asked []string

	return func(path string) (int64, int64, uint32, error) {
		asked = append(asked, path)
		return dev, ino, mode, err
	}, &asked
}

func mustBeUnresolved(t *testing.T, err error, what string) {
	t.Helper()

	switch {
	case err == nil:
		t.Fatalf("%s: resolved, want ErrVolumeUnresolved", what)
	case !errors.Is(err, ErrVolumeUnresolved):
		t.Fatalf("%s: err = %v, want one wrapping ErrVolumeUnresolved", what, err)
	}
}

// ---------------------------------------------------------------------------
// Case 15 — ResolveVolume
// ---------------------------------------------------------------------------

// TestResolveVolume_PinsDevAndInoForADirectory. The pin is established at runtime from
// whatever the device reports; both fields are recorded, and only dev is later enforced.
func TestResolveVolume_PinsDevAndInoForADirectory(t *testing.T) {
	t.Parallel()

	stat, asked := statFor(measuredMediaDev, measuredMediaIno, measuredDirMode, nil)

	vol, err := ResolveVolume(stat)
	if err != nil {
		t.Fatalf("ResolveVolume: %v", err)
	}

	switch {
	case vol.IsZero():
		t.Fatal("resolved volume reports IsZero")
	case vol.Dev() != measuredMediaDev:
		t.Fatalf("Dev() = %d, want %d", vol.Dev(), measuredMediaDev)
	case vol.Ino() != measuredMediaIno:
		t.Fatalf("Ino() = %d, want %d", vol.Ino(), measuredMediaIno)
	}

	// It stats the compiled constant, exactly once. This is the single deliberate symlink
	// traversal in the whole binary: once, against a constant, not once per caller path.
	if want := []string{VolumeRoot}; len(*asked) != 1 || (*asked)[0] != want[0] {
		t.Fatalf("stat calls = %v, want exactly %v", *asked, want)
	}
}

// TestResolveVolume_StatsTheCompiledConstantWhichRemainsADeniedPath — the resolver takes no
// path argument at all, which is why VolumeRoot cannot leak into the allowlist. The
// assertion is that the constant it stats is the denied spelling "/sdcard", and that
// "/sdcard" is still not parseable afterwards.
func TestResolveVolume_StatsTheCompiledConstantWhichRemainsADeniedPath(t *testing.T) {
	t.Parallel()

	stat, asked := statFor(measuredMediaDev, measuredMediaIno, measuredDirMode, nil)

	if _, err := ResolveVolume(stat); err != nil {
		t.Fatalf("ResolveVolume: %v", err)
	}

	if (*asked)[0] != "/sdcard" {
		t.Fatalf("stat path = %q, want %q", (*asked)[0], "/sdcard")
	}

	if _, err := ParseAuthorizedPath(VolumeRoot); !errors.Is(err, ErrPathDenied) {
		t.Fatalf("ParseAuthorizedPath(%q) = %v, want ErrPathDenied", VolumeRoot, err)
	}
}

// TestResolveVolume_NonDirectoryIsUnresolved. The measured symlink mode is the case that
// matters: /sdcard IS a symlink (0o120644, dev=65034 ino=48) under LST2 semantics. STA2
// follows it and must report a directory. If a transport ever hands back the lstat view, or
// the device presents storage in some other shape, the invocation aborts rather than
// guessing.
func TestResolveVolume_NonDirectoryIsUnresolved(t *testing.T) {
	t.Parallel()

	kinds := map[string]uint32{
		"symlink (the measured LST2 view of /sdcard)": measuredSymlinkMode,
		"regular file":     measuredRegularMode,
		"socket":           0o140755,
		"fifo":             0o010644,
		"block device":     0o060660,
		"character device": 0o020666,
		"mode zero":        0,
	}

	for name, mode := range kinds {
		stat, _ := statFor(measuredRootDev, 48, mode, nil)

		vol, err := ResolveVolume(stat)
		mustBeUnresolved(t, err, name)

		if !vol.IsZero() {
			t.Fatalf("%s: returned a non-zero Volume alongside the error", name)
		}
	}
}

// TestResolveVolume_StatErrorIsUnresolved — a failed STA2 aborts before any path is served,
// and the underlying error is preserved for the operator.
func TestResolveVolume_StatErrorIsUnresolved(t *testing.T) {
	t.Parallel()

	sentinel := errors.New("device returned error=2")
	stat, _ := statFor(0, 0, 0, sentinel)

	vol, err := ResolveVolume(stat)
	mustBeUnresolved(t, err, "stat failure")

	if !errors.Is(err, sentinel) {
		t.Fatalf("err = %v, want it to wrap the transport error", err)
	}
	if !vol.IsZero() {
		t.Fatal("returned a non-zero Volume alongside the error")
	}
}

// TestResolveVolume_StatErrorWinsEvenWhenTheModeLooksLikeADirectory — the error is checked
// first; a transport that fills in a plausible mode alongside a failure must not resolve.
func TestResolveVolume_StatErrorWinsEvenWhenTheModeLooksLikeADirectory(t *testing.T) {
	t.Parallel()

	stat, _ := statFor(measuredMediaDev, measuredMediaIno, measuredDirMode, errors.New("boom"))

	_, err := ResolveVolume(stat)
	mustBeUnresolved(t, err, "error plus directory mode")
}

// TestResolveVolume_NilStatFuncIsUnresolved — a missing transport is an unresolved volume,
// not a panic, and certainly not a usable pin.
func TestResolveVolume_NilStatFuncIsUnresolved(t *testing.T) {
	t.Parallel()

	vol, err := ResolveVolume(nil)
	mustBeUnresolved(t, err, "nil StatFunc")

	if !vol.IsZero() {
		t.Fatal("nil StatFunc produced a non-zero Volume")
	}
}

// TestResolveVolume_PinIsRuntimeAndNeverCompiledIn. dev is assigned at mount time and
// differs across reboots and remounts, so a hard-coded 190 would be a latent silent failure
// the first time the phone rebooted. Two resolutions reporting different numbers must pin
// exactly what they were told.
func TestResolveVolume_PinIsRuntimeAndNeverCompiledIn(t *testing.T) {
	t.Parallel()

	for _, dev := range []int64{measuredMediaDev, 191, 7, 1 << 40} {
		stat, _ := statFor(dev, 4812, measuredDirMode, nil)

		vol, err := ResolveVolume(stat)
		if err != nil {
			t.Fatalf("dev=%d: %v", dev, err)
		}

		if vol.Dev() != dev {
			t.Fatalf("Dev() = %d, want the runtime value %d", vol.Dev(), dev)
		}
		if !vol.Contains(dev) {
			t.Fatalf("dev=%d: Contains(%d) = false", dev, dev)
		}
		if vol.Contains(measuredMediaDev) && dev != measuredMediaDev {
			t.Fatalf("dev=%d: Contains(190) = true, which means 190 is compiled in somewhere", dev)
		}
	}
}

// TestResolveVolume_AcceptsAnyDirectoryMode — the check is on the file-type bits only.
// Permission bits vary (the measured mode is 0o42770, with the setgid bit set) and are not
// this type's business.
func TestResolveVolume_AcceptsAnyDirectoryMode(t *testing.T) {
	t.Parallel()

	for _, mode := range []uint32{0o040000, 0o040755, measuredDirMode, 0o042770, 0o047777} {
		stat, _ := statFor(measuredMediaDev, measuredMediaIno, mode, nil)

		if _, err := ResolveVolume(stat); err != nil {
			t.Fatalf("mode 0o%o: %v", mode, err)
		}
	}
}

// ---------------------------------------------------------------------------
// Case 16 — Contains tests dev, never ino
// ---------------------------------------------------------------------------

// TestVolumeContains_MatchingDevWithADifferentInoIsAllowedBecauseThePinIsDevOnly.
//
// This will look like a bug to anyone who has not read why, so: ino is recorded as
// provenance for the audit record and enforced NOWHERE. It would add exactly one thing —
// distinguishing /storage/emulated/0 from /storage/emulated/10, Android's multi-user layout,
// both of which are dev=190. Re-pointing /sdcard at another user's storage requires
// privilege on the phone, which the threat model puts out of scope, and this device has no
// second user. So a matching dev with a different ino is ALLOWED, deliberately.
func TestVolumeContains_MatchingDevWithADifferentInoIsAllowedBecauseThePinIsDevOnly(t *testing.T) {
	t.Parallel()

	stat, _ := statFor(measuredMediaDev, measuredMediaIno, measuredDirMode, nil)

	vol, err := ResolveVolume(stat)
	if err != nil {
		t.Fatalf("ResolveVolume: %v", err)
	}

	if !vol.Contains(measuredMediaDev) {
		t.Fatal("Contains(pinned dev) = false")
	}

	// Ino is readable for the audit record...
	if vol.Ino() != measuredMediaIno {
		t.Fatalf("Ino() = %d, want %d", vol.Ino(), measuredMediaIno)
	}

	// ...and nothing in the API takes an ino to compare it against. Contains has one
	// parameter, by design; there is no overload that would let a caller enforce ino even
	// if they wanted to. Volumes pinned on the same dev with wildly different inodes —
	// including /storage/emulated/10, the multi-user case ino would have caught — all
	// contain the media dev.
	for _, ino := range []int64{measuredMediaIno, 4812, 129, 0, 1 << 40} {
		otherIno, _ := statFor(measuredMediaDev, ino, measuredDirMode, nil)

		other, err := ResolveVolume(otherIno)
		if err != nil {
			t.Fatalf("ino=%d: %v", ino, err)
		}

		if !other.Contains(measuredMediaDev) {
			t.Fatalf("ino=%d: Contains(pinned dev) = false; ino must not be enforced", ino)
		}
		if !vol.Contains(other.Dev()) {
			t.Fatalf("ino=%d: the original pin rejects a volume with the same dev", ino)
		}
	}
}

// TestVolumeContains_ADifferentDevIsRefused — the check that is actually load-bearing. A
// symlink or bind mount leading off the media volume lands on another filesystem: /data is
// dev=65088, the root filesystem is dev=65034. It is caught by where it leads, not by what
// it is named, which is why this replaced the old per-component symlink rule.
func TestVolumeContains_ADifferentDevIsRefused(t *testing.T) {
	t.Parallel()

	stat, _ := statFor(measuredMediaDev, measuredMediaIno, measuredDirMode, nil)

	vol, err := ResolveVolume(stat)
	if err != nil {
		t.Fatalf("ResolveVolume: %v", err)
	}

	offVolume := map[string]int64{
		"/data":                 measuredDataDev,
		"root filesystem":       measuredRootDev,
		"/storage (dir itself)": 23,
		"zero":                  0,
		"one off":               measuredMediaDev + 1,
		"negative":              -measuredMediaDev,
	}

	for name, dev := range offVolume {
		if vol.Contains(dev) {
			t.Fatalf("Contains(%s, dev=%d) = true, want false", name, dev)
		}
	}
}

// ---------------------------------------------------------------------------
// Case 17 — the zero Volume
// ---------------------------------------------------------------------------

// TestZeroVolume_IsZeroAndContainsNothing. An unpinned volume must authorise nothing, so a
// fetch attempted before ResolveVolume ran cannot pass a dev check by accident — including
// dev=0, which is what a zero-value comparison would otherwise let through.
func TestZeroVolume_IsZeroAndContainsNothing(t *testing.T) {
	t.Parallel()

	var zero Volume

	switch {
	case !zero.IsZero():
		t.Fatal("zero Volume does not report IsZero")
	case zero.Dev() != 0:
		t.Fatalf("zero.Dev() = %d, want 0", zero.Dev())
	case zero.Ino() != 0:
		t.Fatalf("zero.Ino() = %d, want 0", zero.Ino())
	}

	for _, dev := range []int64{0, measuredMediaDev, measuredDataDev, measuredRootDev, -1, 1 << 40} {
		if zero.Contains(dev) {
			t.Fatalf("zero Volume contains dev=%d", dev)
		}
	}

	// A composite literal is the zero value too: there is no exported field to set, so
	// outside this package Volume{} is the only literal expressible and it authorises
	// nothing.
	if (Volume{}) != zero {
		t.Fatal("Volume{} is not the zero value")
	}
}

// TestVolume_IsComparableByValue — value semantics, no pointer, no setter. Two resolutions
// of the same volume are equal, which lets the audit extension compare a re-stat against
// the original pin directly.
func TestVolume_IsComparableByValue(t *testing.T) {
	t.Parallel()

	stat, _ := statFor(measuredMediaDev, measuredMediaIno, measuredDirMode, nil)

	first, err := ResolveVolume(stat)
	if err != nil {
		t.Fatalf("first: %v", err)
	}

	second, err := ResolveVolume(stat)
	if err != nil {
		t.Fatalf("second: %v", err)
	}

	if first != second {
		t.Fatalf("two resolutions of the same volume differ: %+v vs %+v", first, second)
	}

	// A remount that changes dev is visibly a different pin, which is what lets the
	// storage layer abort a source with volume_unresolved instead of emitting a
	// path_denied storm for every remaining entry.
	remounted, _ := statFor(measuredMediaDev+1, measuredMediaIno, measuredDirMode, nil)

	after, err := ResolveVolume(remounted)
	if err != nil {
		t.Fatalf("remounted: %v", err)
	}

	if after == first {
		t.Fatal("a volume on a different dev compares equal to the original pin")
	}
	if after.Contains(first.Dev()) {
		t.Fatal("the re-pinned volume still contains the old dev")
	}
}

// TestErrVolumeUnresolved_IsDistinctFromErrPathDenied — the two failures mean different
// things to the operator ("the ground moved" vs "you asked for something forbidden") and
// map to different audit outcomes, so neither must wrap the other.
func TestErrVolumeUnresolved_IsDistinctFromErrPathDenied(t *testing.T) {
	t.Parallel()

	stat, _ := statFor(measuredRootDev, 48, measuredSymlinkMode, nil)

	_, volErr := ResolveVolume(stat)
	_, pathErr := ParseAuthorizedPath("/data")

	switch {
	case errors.Is(volErr, ErrPathDenied):
		t.Fatalf("volume error %v also matches ErrPathDenied", volErr)
	case errors.Is(pathErr, ErrVolumeUnresolved):
		t.Fatalf("path error %v also matches ErrVolumeUnresolved", pathErr)
	}
}

// TestResolveVolume_ErrorNamesTheRootAndTheMode — the operator has to be able to tell what
// the device actually presented, since the abort happens before any path is served.
func TestResolveVolume_ErrorNamesTheRootAndTheMode(t *testing.T) {
	t.Parallel()

	stat, _ := statFor(measuredRootDev, 48, measuredSymlinkMode, nil)

	_, err := ResolveVolume(stat)
	mustBeUnresolved(t, err, "symlink root")

	msg := err.Error()
	for _, want := range []string{VolumeRoot, fmt.Sprintf("0o%o", measuredSymlinkMode)} {
		if !strings.Contains(msg, want) {
			t.Fatalf("error %q does not mention %q", msg, want)
		}
	}
}
