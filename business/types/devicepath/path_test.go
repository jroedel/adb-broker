package devicepath

import (
	"encoding/base64"
	"errors"
	"slices"
	"strings"
	"sync"
	"testing"
	"unicode/utf8"
)

// restoreAllowlist restores the compiled allowlist when the test ends. Narrow mutates
// package state by design (it is called once, at startup, from main), so any test that
// narrows must put it back or it leaks into every later test.
//
// Tests that call Narrow must therefore NOT call t.Parallel.
func restoreAllowlist(t *testing.T) {
	t.Helper()

	t.Cleanup(func() {
		roots := slices.Clone(compiledAllowlist[:])
		activeAllowlist.Store(&roots)
	})
}

// mustBeDenied asserts that err rejects a path and does so with ErrPathDenied, which is
// what the App layer maps to the path_denied outcome. An error that does not wrap it
// would be reported as an internal failure instead.
func mustBeDenied(t *testing.T, err error, what string) {
	t.Helper()

	switch {
	case err == nil:
		t.Fatalf("%s: accepted, want denied", what)
	case !errors.Is(err, ErrPathDenied):
		t.Fatalf("%s: err = %v, want one wrapping ErrPathDenied", what, err)
	}
}

// ---------------------------------------------------------------------------
// Case 1 — segment-boundary matching
// ---------------------------------------------------------------------------

// TestParseAuthorizedPath_DownloadPrivateIsDeniedAtTheSegmentBoundary is the case the
// design calls out by name. /sdcard/Download must not authorise
// /sdcard/Download-private/… — measured, /sdcard/Download-private returns error=2 on the
// device, i.e. the device would have answered had it existed, so this is a real boundary
// and not a theoretical one. A string-prefix comparison passes it; a segment comparison
// does not.
func TestParseAuthorizedPath_DownloadPrivateIsDeniedAtTheSegmentBoundary(t *testing.T) {
	t.Parallel()

	denied := []string{
		"/sdcard/Download-private/a.jpg",
		"/sdcard/Download-private",
		"/sdcard/Downloads/a.jpg",
		"/sdcard/DCIMX/a.jpg",
		"/sdcard/Pictures-old",
		"/sdcard/Musicology/x.mp3",
	}

	for _, s := range denied {
		_, err := ParseAuthorizedPath(s)
		mustBeDenied(t, err, s)
	}

	// The same root does authorise the entry one segment down, so the rule above is
	// rejecting the boundary rather than rejecting everything.
	if _, err := ParseAuthorizedPath("/sdcard/Download/a.jpg"); err != nil {
		t.Fatalf("/sdcard/Download/a.jpg: %v", err)
	}
}

// ---------------------------------------------------------------------------
// Case 2 — one spelling
// ---------------------------------------------------------------------------

// TestParseAuthorizedPath_OnlyTheSdcardSpellingIsAcceptedWithoutResolution checks all
// three measured spellings of the same directory:
//
//	/sdcard/DCIM                dev=190 ino=4812   accepted
//	/storage/self/primary/DCIM  dev=190 ino=4812   denied
//	/storage/emulated/0/DCIM    dev=190 ino=4812   denied
//
// The two denials are NOT resolved to discover that they name the same inode. That is
// structural here rather than asserted: ParseAuthorizedPath is pure, this package imports
// no transport, and there is no StatFunc anywhere on this path — so there is nothing that
// could have resolved them.
//
// The rule denies access to nothing, since a caller wanting those bytes can ask under the
// accepted name. It is canonicalization, so that one directory cannot appear in the audit
// log under three names.
func TestParseAuthorizedPath_OnlyTheSdcardSpellingIsAcceptedWithoutResolution(t *testing.T) {
	t.Parallel()

	if _, err := ParseAuthorizedPath("/sdcard/DCIM"); err != nil {
		t.Fatalf("/sdcard/DCIM: %v", err)
	}

	sameInodeOtherSpellings := []string{
		"/storage/self/primary/DCIM",
		"/storage/emulated/0/DCIM",
		"/storage/emulated/10/DCIM",
		"/mnt/user/0/primary/DCIM",
		"/storage/self/primary/DCIM/a.jpg",
	}

	for _, s := range sameInodeOtherSpellings {
		_, err := ParseAuthorizedPath(s)
		mustBeDenied(t, err, s)
	}
}

// TestParseAuthorizedPath_DeniesEverythingOutsideSharedStorage covers the locations adbd
// was measured to stat freely — it applies no confinement of its own, which is why these
// rules are the only boundary.
func TestParseAuthorizedPath_DeniesEverythingOutsideSharedStorage(t *testing.T) {
	t.Parallel()

	denied := []string{
		"/data",
		"/data/data/com.something/databases/x.db",
		"/proc/1/maps",
		"/system/build.prop",
		"/sdcardx/DCIM",
		"/sdcard.old/DCIM",
	}

	for _, s := range denied {
		_, err := ParseAuthorizedPath(s)
		mustBeDenied(t, err, s)
	}
}

// TestParseAuthorizedPath_DeniesSiblingsInsideSharedStorage — being on the media volume
// is not sufficient. The allowlist is six roots, not "all of /sdcard".
func TestParseAuthorizedPath_DeniesSiblingsInsideSharedStorage(t *testing.T) {
	t.Parallel()

	denied := []string{
		"/sdcard/Android/data/com.something/files/x",
		"/sdcard/Documents/x.pdf",
		"/sdcard/Podcasts/x.mp3",
		"/sdcard/x.txt",
	}

	for _, s := range denied {
		_, err := ParseAuthorizedPath(s)
		mustBeDenied(t, err, s)
	}
}

// ---------------------------------------------------------------------------
// Case 3 — ".." segments
// ---------------------------------------------------------------------------

// TestParseAuthorizedPath_DotDotSegmentIsDenied covers ".." mid-path and ".." as the
// final segment.
//
// Measured: /sdcard/DCIM/.. returns error=0 and resolves to the volume root, so ".."
// genuinely escapes upward. Resolution is physical — symlinks are expanded first — which
// is why /sdcard/DCIM/.. succeeds on the device while /sdcard/../sdcard/DCIM returns
// error=2. Both spellings are refused here regardless of what the device would do with
// them, because the rule is decided from the string.
func TestParseAuthorizedPath_DotDotSegmentIsDenied(t *testing.T) {
	t.Parallel()

	denied := []string{
		"/sdcard/DCIM/../Download/x.jpg", // mid-path
		"/sdcard/DCIM/..",                // final segment: resolves to the volume root
		"/sdcard/../sdcard/DCIM",         // device returns error=2; still refused
		"/sdcard/DCIM/../../data",
		"/sdcard/DCIM/subdir/../../Download/x.jpg",
		"/sdcard/Download/..",
	}

	for _, s := range denied {
		_, err := ParseAuthorizedPath(s)
		mustBeDenied(t, err, s)
	}

	// A name that merely CONTAINS dots is not a traversal segment and stays allowed —
	// the rule is about segments, not about the byte '.'.
	allowed := []string{
		"/sdcard/DCIM/..a",
		"/sdcard/DCIM/a..",
		"/sdcard/DCIM/...",
		"/sdcard/DCIM/.hidden",
		"/sdcard/DCIM/a..b/c.jpg",
	}

	for _, s := range allowed {
		if _, err := ParseAuthorizedPath(s); err != nil {
			t.Fatalf("%s: %v", s, err)
		}
	}
}

// ---------------------------------------------------------------------------
// Case 4 — NUL byte
// ---------------------------------------------------------------------------

// TestParseAuthorizedPath_NULByteIsDenied is the one to remember.
//
// Measured: STA2 on "/sdcard/DCIM\x00x" returns error=0 and the inode for /sdcard/DCIM.
// The kernel truncates at the NUL. Without this check the broker would validate one string
// while the device acted on a shorter one, and the audit log would record the string that
// was validated — a faithful record of an operation that never happened. It is the only
// measured case where a missing check makes the audit log LIE rather than merely permit an
// unwanted read.
func TestParseAuthorizedPath_NULByteIsDenied(t *testing.T) {
	t.Parallel()

	denied := []string{
		"/sdcard/DCIM\x00x",              // truncates to /sdcard/DCIM on the device
		"/sdcard/DCIM\x00",               // ditto
		"/sdcard/DCIM/a.jpg\x00/../data", // truncates to an allowed path, acts on it
		"\x00/sdcard/DCIM",
		"/sdcard/\x00DCIM",
		"/sdcard/DCIM/\x00",
	}

	for _, s := range denied {
		_, err := ParseAuthorizedPath(s)
		mustBeDenied(t, err, s)
	}
}

// TestParseAuthorizedPath_NULIsCheckedBeforeTheAllowlist — the NUL check must fire even
// for a string whose truncation would have been allowed, which is exactly the dangerous
// case. Asserting the error mentions NUL keeps the ordering honest.
func TestParseAuthorizedPath_NULIsCheckedBeforeTheAllowlist(t *testing.T) {
	t.Parallel()

	_, err := ParseAuthorizedPath("/sdcard/DCIM\x00x")
	mustBeDenied(t, err, "NUL after an allowed prefix")

	if !strings.Contains(err.Error(), "NUL") {
		t.Fatalf("err = %v, want it to name the NUL byte", err)
	}
}

// ---------------------------------------------------------------------------
// Case 5 — relative paths and bare "."
// ---------------------------------------------------------------------------

// TestParseAuthorizedPath_RelativePathIsDenied. Measured: "sdcard/DCIM" returns error=0
// and the same inode as /sdcard/DCIM, because adbd's working directory is /. "." returns
// the root inode.
func TestParseAuthorizedPath_RelativePathIsDenied(t *testing.T) {
	t.Parallel()

	denied := []string{
		"sdcard/DCIM", // same inode as /sdcard/DCIM on the device
		".",           // the root inode
		"..",
		"./sdcard/DCIM",
		"sdcard/DCIM/a.jpg",
		"DCIM",
		"sdcard",
	}

	for _, s := range denied {
		_, err := ParseAuthorizedPath(s)
		mustBeDenied(t, err, s)
	}
}

// TestParseAuthorizedPath_DotSegmentIsDenied — a "." segment is a second spelling of one
// path, in the same family as a doubled slash, and the device resolves it. Rejecting it
// also keeps Child and ParseAuthorizedPath in step, since Child rejects the name ".".
func TestParseAuthorizedPath_DotSegmentIsDenied(t *testing.T) {
	t.Parallel()

	denied := []string{
		"/sdcard/./DCIM",
		"/sdcard/DCIM/.",
		"/sdcard/DCIM/./a.jpg",
	}

	for _, s := range denied {
		_, err := ParseAuthorizedPath(s)
		mustBeDenied(t, err, s)
	}
}

// ---------------------------------------------------------------------------
// Case 6 — empty segments
// ---------------------------------------------------------------------------

// TestParseAuthorizedPath_TrailingOrDoubledSlashIsDenied. Measured: /sdcard/DCIM,
// /sdcard/DCIM/ and /sdcard/DCIM// all return error=0 and the same inode. Accepting more
// than one spelling would put two audit records in the log for one operation.
func TestParseAuthorizedPath_TrailingOrDoubledSlashIsDenied(t *testing.T) {
	t.Parallel()

	denied := []string{
		"/sdcard/DCIM/",
		"/sdcard/DCIM//",
		"/sdcard//DCIM",
		"/sdcard/DCIM/a.jpg/",
		"/sdcard/DCIM//a.jpg",
		"//sdcard/DCIM",
		"/sdcard/Download///",
	}

	for _, s := range denied {
		_, err := ParseAuthorizedPath(s)
		mustBeDenied(t, err, s)
	}
}

// ---------------------------------------------------------------------------
// Case 7 — parent of a root
// ---------------------------------------------------------------------------

// TestParseAuthorizedPath_ParentOfARootIsRefusedNotNarrowed. A caller asking for /sdcard
// or / is asking for something this binary will not do, and saying so is more useful than
// quietly serving the permitted children beneath it. The assertion is both that the parse
// fails AND that the allowlist is untouched afterwards, since "silently narrowed" is the
// failure mode being ruled out.
func TestParseAuthorizedPath_ParentOfARootIsRefusedNotNarrowed(t *testing.T) {
	t.Parallel()

	before := Roots()

	for _, s := range []string{"/sdcard", "/", "/sdcard/", "/storage", "/storage/emulated/0"} {
		_, err := ParseAuthorizedPath(s)
		mustBeDenied(t, err, s)
	}

	if after := Roots(); !slices.Equal(before, after) {
		t.Fatalf("allowlist changed by a denied parse: %v -> %v", before, after)
	}
}

// TestVolumeRootIsNotAnAuthorizedPath — VolumeRoot is the pin target for ResolveVolume,
// not a location this binary serves. It must stay denied as a caller-supplied path; that
// is what keeps the single deliberate symlink traversal in ResolveVolume from leaking into
// the allowlist.
func TestVolumeRootIsNotAnAuthorizedPath(t *testing.T) {
	t.Parallel()

	_, err := ParseAuthorizedPath(VolumeRoot)
	mustBeDenied(t, err, VolumeRoot)
}

// ---------------------------------------------------------------------------
// Case 8 — the six roots
// ---------------------------------------------------------------------------

// TestParseAuthorizedPath_AcceptsEachCompiledRootAndFilesBeneathIt walks the whole
// compiled allowlist: each root as a root, and a file one and two levels beneath it.
func TestParseAuthorizedPath_AcceptsEachCompiledRootAndFilesBeneathIt(t *testing.T) {
	t.Parallel()

	want := []string{
		"/sdcard/DCIM",
		"/sdcard/Download",
		"/sdcard/Movies",
		"/sdcard/Music",
		"/sdcard/Pictures",
		"/sdcard/Recordings",
	}

	if got := Roots(); !slices.Equal(got, want) {
		t.Fatalf("Roots() = %v, want the six compiled roots %v", got, want)
	}

	for _, root := range want {
		for _, s := range []string{root, root + "/a.jpg", root + "/Camera/IMG_0001.jpg"} {
			p, err := ParseAuthorizedPath(s)
			if err != nil {
				t.Fatalf("%s: %v", s, err)
			}
			if p.String() != s {
				t.Fatalf("String() = %q, want %q", p.String(), s)
			}
			if p.IsZero() {
				t.Fatalf("%s: IsZero on a parsed path", s)
			}
		}
	}
}

// TestParseAuthorizedPath_IsCaseSensitive — the allowlist is compared byte for byte;
// "dcim" is not "DCIM". Shared storage on this device is case-insensitive in places, but
// this binary does not model that: a spelling that is not the compiled one is denied, and
// the caller is told, rather than being quietly folded.
func TestParseAuthorizedPath_IsCaseSensitive(t *testing.T) {
	t.Parallel()

	for _, s := range []string{"/sdcard/dcim", "/sdcard/download/x", "/SDCARD/DCIM"} {
		_, err := ParseAuthorizedPath(s)
		mustBeDenied(t, err, s)
	}
}

// ---------------------------------------------------------------------------
// Case 9 — empty string and bare "/sdcard/"
// ---------------------------------------------------------------------------

// TestParseAuthorizedPath_EmptyStringAndBareVolumeRootAreDenied.
func TestParseAuthorizedPath_EmptyStringAndBareVolumeRootAreDenied(t *testing.T) {
	t.Parallel()

	for _, s := range []string{"", "/sdcard/", "/sdcard//", " ", "/ "} {
		_, err := ParseAuthorizedPath(s)
		mustBeDenied(t, err, s)
	}
}

// TestParseAuthorizedPath_DeniedParseReturnsTheZeroValue — a caller that ignores the
// error must not end up holding a usable path.
func TestParseAuthorizedPath_DeniedParseReturnsTheZeroValue(t *testing.T) {
	t.Parallel()

	p, err := ParseAuthorizedPath("/data/data/x")
	mustBeDenied(t, err, "/data/data/x")

	if !p.IsZero() || p.String() != "" {
		t.Fatalf("denied parse returned %q (IsZero=%v), want the zero value", p.String(), p.IsZero())
	}
}

// ---------------------------------------------------------------------------
// Case 10 — Child
// ---------------------------------------------------------------------------

// TestChild_RejectsSeparatorsNULDotAndDotDot. Child is what traversal uses to descend, so
// it must not be able to assemble a path ParseAuthorizedPath would have refused.
func TestChild_RejectsSeparatorsNULDotAndDotDot(t *testing.T) {
	t.Parallel()

	parent := MustParseAuthorizedPath("/sdcard/DCIM")

	cases := map[string][]byte{
		"empty name":           []byte(""),
		"separator":            []byte("a/b"),
		"leading separator":    []byte("/a"),
		"trailing separator":   []byte("a/"),
		"escape via separator": []byte("../Download"),
		"NUL":                  []byte("a\x00b"),
		"trailing NUL":         []byte("a\x00"),
		"dot":                  []byte("."),
		"dotdot":               []byte(".."),
	}

	for name, raw := range cases {
		child, err := parent.Child(raw)
		mustBeDenied(t, err, "Child("+name+")")

		if !child.IsZero() {
			t.Fatalf("Child(%s) returned %q, want the zero value", name, child.String())
		}
	}
}

// TestChild_OnTheZeroValueIsDenied — authority has to come from somewhere. A walk that
// starts from var p AuthorizedPath cannot bootstrap itself into the tree.
func TestChild_OnTheZeroValueIsDenied(t *testing.T) {
	t.Parallel()

	var zero AuthorizedPath

	_, err := zero.Child([]byte("DCIM"))
	mustBeDenied(t, err, "zero.Child")
}

// TestChild_PreservesInvalidUTF8BytesExactly. Entry names are raw bytes from a device
// listing and are never coerced: coercion would corrupt the only string that can be sent
// back to the device to fetch the file. (Honest status: every name sampled on this device
// was ASCII. The rule is prudence, not a measurement — but the cost of the check is nil
// and the cost of being wrong is a silently unarchived file.)
func TestChild_PreservesInvalidUTF8BytesExactly(t *testing.T) {
	t.Parallel()

	parent := MustParseAuthorizedPath("/sdcard/DCIM")
	raw := []byte{0xff, 0xfe, 'a', 0x80, 'b', 0xc3} // invalid UTF-8, deliberately

	if utf8.Valid(raw) {
		t.Fatal("fixture is valid UTF-8; the test is not testing what it claims")
	}

	child, err := parent.Child(raw)
	if err != nil {
		t.Fatalf("Child: %v", err)
	}

	want := append([]byte("/sdcard/DCIM/"), raw...)
	if !slices.Equal(child.Bytes(), want) {
		t.Fatalf("Child bytes = %v, want %v", child.Bytes(), want)
	}
}

// TestChild_RoundTripsThroughParseAuthorizedPath is the property that makes traversal
// safe: anything Child produces, ParseAuthorizedPath would also have accepted, so there is
// no second, weaker way into the tree.
func TestChild_RoundTripsThroughParseAuthorizedPath(t *testing.T) {
	t.Parallel()

	names := [][]byte{
		[]byte("Camera"),
		[]byte("IMG_0001.jpg"),
		[]byte("a b c.jpg"),
		[]byte("...."),
		[]byte(".hidden"),
		[]byte("..a"),
		[]byte("a..b"),
		[]byte{0xff, 0xfe},
		[]byte("naïve.jpg"),
		[]byte("newline\nname"),
	}

	for _, root := range Roots() {
		parent := MustParseAuthorizedPath(root)

		for _, name := range names {
			child, err := parent.Child(name)
			if err != nil {
				t.Fatalf("Child(%q) under %s: %v", name, root, err)
			}

			reparsed, err := ParseAuthorizedPath(child.String())
			if err != nil {
				t.Fatalf("Child produced %q, which ParseAuthorizedPath refuses: %v", child.String(), err)
			}
			if reparsed != child {
				t.Fatalf("round trip changed the path: %q != %q", reparsed.String(), child.String())
			}

			// And it descends: a grandchild works the same way.
			grandchild, err := child.Child([]byte("deeper"))
			if err != nil {
				t.Fatalf("grandchild under %q: %v", child.String(), err)
			}
			if _, err := ParseAuthorizedPath(grandchild.String()); err != nil {
				t.Fatalf("grandchild %q refused by ParseAuthorizedPath: %v", grandchild.String(), err)
			}
		}
	}
}

// TestChild_CannotEscapeANarrowedAllowlist — Child revalidates against the allowlist in
// force, so it cannot walk out of a root that Narrow removed. This test narrows, so it
// does not run in parallel.
func TestChild_CannotEscapeANarrowedAllowlist(t *testing.T) {
	restoreAllowlist(t)

	download := MustParseAuthorizedPath("/sdcard/Download")

	if err := Narrow([]string{"/sdcard/DCIM"}); err != nil {
		t.Fatalf("Narrow: %v", err)
	}

	// The parent was authorised before the narrowing; descending from it is not.
	_, err := download.Child([]byte("a.jpg"))
	mustBeDenied(t, err, "Child under a root that was narrowed away")
}

// ---------------------------------------------------------------------------
// Case 11 — Bytes and Base64
// ---------------------------------------------------------------------------

// TestBytesAndBase64RoundTripRawNonUTF8Bytes. path_b64 is the authoritative path field in
// the wire format precisely because it survives names the human-readable field cannot.
func TestBytesAndBase64RoundTripRawNonUTF8Bytes(t *testing.T) {
	t.Parallel()

	raw := append([]byte("/sdcard/DCIM/"), 0xff, 0xfe, 0x80, 'x', 0xc3, '.', 'j', 'p', 'g')

	p, err := ParseAuthorizedPath(string(raw))
	if err != nil {
		t.Fatalf("ParseAuthorizedPath: %v", err)
	}

	if !slices.Equal(p.Bytes(), raw) {
		t.Fatalf("Bytes() = %v, want %v", p.Bytes(), raw)
	}

	decoded, err := base64.StdEncoding.DecodeString(p.Base64())
	if err != nil {
		t.Fatalf("Base64 output does not decode: %v", err)
	}
	if !slices.Equal(decoded, raw) {
		t.Fatalf("base64 round trip = %v, want %v", decoded, raw)
	}

	// Base64 is standard encoding of the raw bytes, not of a coerced string.
	if want := base64.StdEncoding.EncodeToString(raw); p.Base64() != want {
		t.Fatalf("Base64() = %q, want %q", p.Base64(), want)
	}
}

// TestBytesReturnsACopy — Bytes must not hand out a window into the path. The type has no
// mutating method and this is the only place a caller could get bytes to write through.
func TestBytesReturnsACopy(t *testing.T) {
	t.Parallel()

	p := MustParseAuthorizedPath("/sdcard/DCIM/a.jpg")

	b := p.Bytes()
	b[1] = 'X'

	if p.String() != "/sdcard/DCIM/a.jpg" {
		t.Fatalf("mutating Bytes() changed the path to %q", p.String())
	}
	if got := p.Bytes(); string(got) != "/sdcard/DCIM/a.jpg" {
		t.Fatalf("second Bytes() = %q, want the unmodified path", got)
	}
}

// TestBase64OfTheZeroValueIsEmpty — an unpinned path encodes to nothing, not to a
// plausible-looking record.
func TestBase64OfTheZeroValueIsEmpty(t *testing.T) {
	t.Parallel()

	var zero AuthorizedPath

	if zero.Base64() != "" {
		t.Fatalf("zero.Base64() = %q, want empty", zero.Base64())
	}
	if len(zero.Bytes()) != 0 {
		t.Fatalf("zero.Bytes() = %v, want empty", zero.Bytes())
	}
}

// ---------------------------------------------------------------------------
// Case 12 — MustParseAuthorizedPath
// ---------------------------------------------------------------------------

// TestMustParseAuthorizedPath_PanicsOnADeniedPath. MustParse is for tests and package vars
// with compiled-in constants; a denied constant is a programming error and must be loud.
func TestMustParseAuthorizedPath_PanicsOnADeniedPath(t *testing.T) {
	t.Parallel()

	denied := []string{
		"/data/data/x",
		"/sdcard",
		"/sdcard/DCIM/",
		"/sdcard/DCIM\x00x",
		"/storage/emulated/0/DCIM",
		"",
	}

	for _, s := range denied {
		func() {
			defer func() {
				r := recover()
				if r == nil {
					t.Fatalf("MustParseAuthorizedPath(%q) did not panic", s)
				}

				err, ok := r.(error)
				if !ok || !errors.Is(err, ErrPathDenied) {
					t.Fatalf("MustParseAuthorizedPath(%q) panicked with %v, want an error wrapping ErrPathDenied", s, r)
				}
			}()

			MustParseAuthorizedPath(s)
		}()
	}
}

// TestMustParseAuthorizedPath_ReturnsTheParsedPath — the happy path, so the panic test
// above is not the only thing exercising it.
func TestMustParseAuthorizedPath_ReturnsTheParsedPath(t *testing.T) {
	t.Parallel()

	p := MustParseAuthorizedPath("/sdcard/Pictures/x.png")

	if p.String() != "/sdcard/Pictures/x.png" {
		t.Fatalf("String() = %q", p.String())
	}
}

// ---------------------------------------------------------------------------
// Case 13 — Narrow
// ---------------------------------------------------------------------------

// TestNarrow_RemovesRoots — the ordinary use: restrict a run to a subset of the six.
func TestNarrow_RemovesRoots(t *testing.T) {
	restoreAllowlist(t)

	if err := Narrow([]string{"/sdcard/DCIM", "/sdcard/Movies"}); err != nil {
		t.Fatalf("Narrow: %v", err)
	}

	if got, want := Roots(), []string{"/sdcard/DCIM", "/sdcard/Movies"}; !slices.Equal(got, want) {
		t.Fatalf("Roots() = %v, want %v", got, want)
	}

	if _, err := ParseAuthorizedPath("/sdcard/DCIM/a.jpg"); err != nil {
		t.Fatalf("/sdcard/DCIM/a.jpg after narrowing: %v", err)
	}

	// The removed roots are now denied, which is the whole point.
	for _, s := range []string{"/sdcard/Download", "/sdcard/Download/a.jpg", "/sdcard/Music/x.mp3"} {
		_, err := ParseAuthorizedPath(s)
		mustBeDenied(t, err, s+" after narrowing")
	}
}

// TestNarrow_AcceptsASubpathOfARoot — restricting to a subdirectory is a narrowing, so it
// is allowed, and the subdirectory becomes the new root.
func TestNarrow_AcceptsASubpathOfARoot(t *testing.T) {
	restoreAllowlist(t)

	if err := Narrow([]string{"/sdcard/DCIM/Camera"}); err != nil {
		t.Fatalf("Narrow: %v", err)
	}

	if got, want := Roots(), []string{"/sdcard/DCIM/Camera"}; !slices.Equal(got, want) {
		t.Fatalf("Roots() = %v, want %v", got, want)
	}

	if _, err := ParseAuthorizedPath("/sdcard/DCIM/Camera/IMG_0001.jpg"); err != nil {
		t.Fatalf("file under the narrowed root: %v", err)
	}

	// The parent of the new root is no longer reachable, and neither is a sibling that a
	// string-prefix comparison would have let through.
	for _, s := range []string{"/sdcard/DCIM", "/sdcard/DCIM/a.jpg", "/sdcard/DCIM/CameraX/a.jpg"} {
		_, err := ParseAuthorizedPath(s)
		mustBeDenied(t, err, s+" after narrowing to /sdcard/DCIM/Camera")
	}
}

// TestNarrow_CannotWiden is the invariant test: no input read at runtime can increase this
// binary's authority. /data is outside shared storage; /sdcard and / are PARENTS of the
// compiled roots, which is the interesting case, because "narrow to /sdcard" is exactly
// how someone would try to spell "give me everything" while looking like a restriction.
func TestNarrow_CannotWiden(t *testing.T) {
	restoreAllowlist(t)

	widening := []string{
		"/data",
		"/sdcard",
		"/",
		"/storage/emulated/0/DCIM", // same inode as /sdcard/DCIM, still not an addition
		"/sdcard/Documents",        // on the volume, not on the allowlist
		"/sdcard/Download-private", // segment boundary
		"/proc/1/maps",
	}

	for _, s := range widening {
		before := Roots()

		err := Narrow([]string{s})
		mustBeDenied(t, err, "Narrow("+s+")")

		if after := Roots(); !slices.Equal(before, after) {
			t.Fatalf("Narrow(%q) failed but changed the allowlist: %v -> %v", s, before, after)
		}
	}
}

// TestNarrow_RejectsMalformedEntries — Narrow applies the same string rules as
// ParseAuthorizedPath, so a NUL or a trailing slash cannot enter the allowlist and quietly
// change what later comparisons mean.
func TestNarrow_RejectsMalformedEntries(t *testing.T) {
	restoreAllowlist(t)

	malformed := []string{
		"/sdcard/DCIM/",
		"/sdcard//DCIM",
		"/sdcard/DCIM\x00",
		"sdcard/DCIM",
		"/sdcard/DCIM/..",
		"/sdcard/DCIM/./Camera",
		"",
	}

	for _, s := range malformed {
		err := Narrow([]string{s})
		mustBeDenied(t, err, "Narrow("+s+")")
	}
}

// TestNarrow_IsAllOrNothing — one bad entry must not apply the good ones, or a caller
// whose arguments were partly wrong would run against an allowlist nobody chose.
func TestNarrow_IsAllOrNothing(t *testing.T) {
	restoreAllowlist(t)

	before := Roots()

	err := Narrow([]string{"/sdcard/DCIM", "/data"})
	mustBeDenied(t, err, "Narrow with one denied entry")

	if after := Roots(); !slices.Equal(before, after) {
		t.Fatalf("partial narrowing applied: %v -> %v", before, after)
	}
}

// TestNarrow_EmptySubsetIsAnError — a caller that passes nothing has lost its arguments.
// Leaving zero reachable roots would report every path as denied with no explanation.
func TestNarrow_EmptySubsetIsAnError(t *testing.T) {
	restoreAllowlist(t)

	before := Roots()

	for _, subset := range [][]string{nil, {}} {
		err := Narrow(subset)
		mustBeDenied(t, err, "Narrow(empty)")
	}

	if after := Roots(); !slices.Equal(before, after) {
		t.Fatalf("Narrow(empty) changed the allowlist: %v -> %v", before, after)
	}
}

// TestNarrow_IsMonotone — narrowing twice narrows further; the second call cannot restore
// what the first removed, because entries are checked against the allowlist in force.
func TestNarrow_IsMonotone(t *testing.T) {
	restoreAllowlist(t)

	if err := Narrow([]string{"/sdcard/DCIM"}); err != nil {
		t.Fatalf("first Narrow: %v", err)
	}

	// Re-adding a compiled root that the first call removed is a widening.
	err := Narrow([]string{"/sdcard/DCIM", "/sdcard/Download"})
	mustBeDenied(t, err, "Narrow re-adding a removed root")

	// Narrowing further inside what remains still works.
	if err := Narrow([]string{"/sdcard/DCIM/Camera"}); err != nil {
		t.Fatalf("second Narrow: %v", err)
	}

	if got, want := Roots(), []string{"/sdcard/DCIM/Camera"}; !slices.Equal(got, want) {
		t.Fatalf("Roots() = %v, want %v", got, want)
	}

	// And a parent of the narrowed root cannot be re-established either.
	err = Narrow([]string{"/sdcard/DCIM"})
	mustBeDenied(t, err, "Narrow back up to /sdcard/DCIM")
}

// TestNarrow_NeverProducesARootOutsideTheCompiledSet — the structural statement of the
// invariant: whatever sequence of Narrow calls succeeds, every resulting root is still
// within some compiled root.
func TestNarrow_NeverProducesARootOutsideTheCompiledSet(t *testing.T) {
	restoreAllowlist(t)

	attempts := [][]string{
		{"/sdcard/DCIM", "/sdcard/Download"},
		{"/data"},
		{"/sdcard"},
		{"/sdcard/DCIM/Camera"},
		{"/sdcard/DCIM/Camera/2024"},
		{"/sdcard/Download"},
		{"/"},
		{"/sdcard/DCIM/Camera/2024/01"},
	}

	for _, subset := range attempts {
		_ = Narrow(subset) // errors are asserted elsewhere; the invariant is what matters here

		for _, root := range Roots() {
			if err := checkForm(root); err != nil {
				t.Fatalf("active root %q is malformed after Narrow(%v): %v", root, subset, err)
			}
			if !withinAny(root, compiledAllowlist[:]) {
				t.Fatalf("active root %q escaped the compiled allowlist after Narrow(%v)", root, subset)
			}
		}
	}
}

// TestNarrow_DeduplicatesAndSorts — two spellings of the same restriction produce one
// root, so the operator-facing Roots output and the audit record are stable.
func TestNarrow_DeduplicatesAndSorts(t *testing.T) {
	restoreAllowlist(t)

	if err := Narrow([]string{"/sdcard/Movies", "/sdcard/DCIM", "/sdcard/DCIM"}); err != nil {
		t.Fatalf("Narrow: %v", err)
	}

	if got, want := Roots(), []string{"/sdcard/DCIM", "/sdcard/Movies"}; !slices.Equal(got, want) {
		t.Fatalf("Roots() = %v, want %v", got, want)
	}
}

// TestRoots_ReturnsACopy — mutating the result must not change what the binary will serve.
func TestRoots_ReturnsACopy(t *testing.T) {
	t.Parallel()

	got := Roots()
	got[0] = "/data"
	got = append(got, "/proc")
	_ = got

	if fresh := Roots(); fresh[0] != "/sdcard/DCIM" || len(fresh) != len(compiledAllowlist) {
		t.Fatalf("Roots() = %v, want the compiled allowlist unchanged", fresh)
	}

	if _, err := ParseAuthorizedPath("/data/data/x"); err == nil {
		t.Fatal("/data became reachable by mutating the result of Roots()")
	}
}

// ---------------------------------------------------------------------------
// Case 14 — the zero value
// ---------------------------------------------------------------------------

// TestZeroAuthorizedPath_IsInert. A caller cannot smuggle a path past a Storer by
// declaring var p AuthorizedPath: it reports IsZero, its String is empty, it encodes to
// nothing, and it cannot descend.
func TestZeroAuthorizedPath_IsInert(t *testing.T) {
	t.Parallel()

	var zero AuthorizedPath

	switch {
	case !zero.IsZero():
		t.Fatal("zero value does not report IsZero")
	case zero.String() != "":
		t.Fatalf("zero.String() = %q, want empty", zero.String())
	case zero.Base64() != "":
		t.Fatalf("zero.Base64() = %q, want empty", zero.Base64())
	case len(zero.Bytes()) != 0:
		t.Fatalf("zero.Bytes() = %v, want empty", zero.Bytes())
	}

	if zero != (AuthorizedPath{}) {
		t.Fatal("zero value is not comparable to a composite literal of itself")
	}

	// A composite literal of the type carries no authority either: there is no exported
	// field to set, so AuthorizedPath{} is the only literal expressible outside this
	// package, and it is the zero value.
	_, err := zero.Child([]byte("DCIM"))
	mustBeDenied(t, err, "zero.Child")
}

// TestAuthorizedPath_IsComparableAndUsableAsAMapKey — value semantics, no pointer, no
// mutation; useful for de-duplicating a walk.
func TestAuthorizedPath_IsComparableAndUsableAsAMapKey(t *testing.T) {
	t.Parallel()

	a := MustParseAuthorizedPath("/sdcard/DCIM/a.jpg")
	b := MustParseAuthorizedPath("/sdcard/DCIM/a.jpg")
	c := MustParseAuthorizedPath("/sdcard/DCIM/b.jpg")

	if a != b {
		t.Fatal("equal paths are not equal values")
	}
	if a == c {
		t.Fatal("different paths compare equal")
	}

	seen := map[AuthorizedPath]int{a: 1}
	seen[b]++

	if seen[a] != 2 {
		t.Fatalf("map key semantics: %v", seen)
	}
}

// ---------------------------------------------------------------------------
// Concurrency — the allowlist is read on every parse
// ---------------------------------------------------------------------------

// TestParseAuthorizedPath_IsSafeUnderConcurrentReads. Every dirent of a walk parses a
// path, and a walk may fan out; under -race this catches an unsynchronised read of the
// active allowlist.
func TestParseAuthorizedPath_IsSafeUnderConcurrentReads(t *testing.T) {
	t.Parallel()

	var wg sync.WaitGroup

	for range 8 {
		wg.Go(func() {
			for range 200 {
				if _, err := ParseAuthorizedPath("/sdcard/DCIM/a.jpg"); err != nil {
					t.Errorf("parse: %v", err)
					return
				}
				_ = Roots()
			}
		})
	}

	wg.Wait()
}
