// Package devicepath holds the two halves of this broker's confinement.
//
// The device's own daemon applies no confinement to the paths it will stat: measured,
// adbd answers for /data, /proc/1/maps and the root filesystem as readily as it answers
// for media. Confinement is therefore entirely the host's job, and this package holds the
// part of it that is decidable from a path string and a pinned filesystem.
//
// It is NOT the whole boundary, and an earlier version of this comment claimed it was.
// Confinement below the root rests on THREE load-bearing checks:
//
//   - AuthorizedPath (this file) enforces every rule that is decidable from the path
//     string alone: the compiled allowlist and the accepted spelling.
//   - Volume (volume.go) pins the storage volume at runtime, because "is this on the
//     media filesystem" is a property of a path paired with a mounted volume, not of
//     the path, and so cannot be decided by a constructor.
//   - The kind check, which admits only regular files and directories, lives in the
//     storage layer against filekind.Kind and NOT in this package. It is the check that
//     stops a planted symlink, because a symlink reports its own inode's dev — the media
//     volume it was created on — and so passes the pin whatever it points at. See
//     Volume's doc comment and docs/THREAT_MODEL.md §5.7, which puts it plainly:
//     removing the kind check would make symlink escapes reachable and nothing else in
//     the design would stop them.
//
// The distinction matters because a control credited with more than it does is worse than
// no control. Two claims of this exact shape have already been walked back in this design.
//
// Enforcement is structural rather than procedural. AuthorizedPath has no exported
// fields, no exported way to construct a non-zero value other than ParseAuthorizedPath,
// MustParseAuthorizedPath and Child, and no method that mutates. The storage layer
// accepts AuthorizedPath and nothing else, so "read a path that was never validated" is
// not a bug review has to catch — it is a program that does not compile.
//
// # The invariant
//
// No input read at runtime can increase this binary's authority. The allowlist is
// compiled in; there is no flag, environment variable or configuration file that widens
// it. Narrow can only remove roots or restrict them to subpaths, and an entry that is
// not already within the active allowlist is an error rather than an addition.
package devicepath

import (
	"encoding/base64"
	"fmt"
	"slices"
	"strings"
	"sync"
	"sync/atomic"

	"github.com/jroedel/adb-broker/business/types/errcode"
)

// VolumeRoot is the one accepted spelling of the device's shared storage root, and the
// target of the volume pin in ResolveVolume.
//
// Android reaches the same storage through several paths — /sdcard,
// /storage/self/primary, /storage/emulated/0 and a per-user variant. Measured, they are
// not merely equivalent but the same inode:
//
//	/sdcard/DCIM                dev=190 ino=4812
//	/storage/self/primary/DCIM  dev=190 ino=4812
//	/storage/emulated/0/DCIM    dev=190 ino=4812
//
// Only the /sdcard/… spelling is accepted. A path naming any other prefix is refused
// with ErrPathDenied and is NOT resolved to see whether it would have been permitted:
// resolving alternate spellings means writing path-resolution logic that the
// confinement guarantee then depends on, and that is where confinement bugs live.
//
// Be clear about what that rule buys, because an earlier draft of the design overstated
// it: since the three spellings reach the same directory, refusing the others denies
// access to NOTHING. It is a canonicalization rule, not an authority boundary. It keeps
// this binary's own path construction honest and it makes audit records comparable,
// because one directory cannot appear in the log under three names. The authority
// boundary is the allowlist plus the volume pin.
//
// VolumeRoot is deliberately not an AuthorizedPath and must not become one. It is the
// pin target, not a location this binary will serve, which is why "/sdcard" stays denied
// as a caller-supplied path with no contradiction.
const VolumeRoot = "/sdcard"

// ErrPathDenied is returned by every rejection in this package: a malformed path form, a
// path outside the compiled allowlist, an unaccepted spelling of shared storage, and a
// rejected Child name. Callers match it with errors.Is and map it to the path_denied
// audit outcome. The returned errors wrap it and add which rule fired.
var ErrPathDenied error = &codedError{msg: "path denied", code: errcode.CodePathDenied}

// codedError is a sentinel that carries its own classification from the broker's
// taxonomy, satisfying errcode.Coder.
//
// The classification belongs on the error rather than in a table kept by each
// consumer. Two layers already needed to ask "what code is this failure?" — a store
// deciding what to report and the audit extension deciding what to record — and a
// second, subtly different mapping is exactly how the broker's reason for existing
// gets undone: the CLI adapter it replaces classified failures by matching English
// in two places, which drifted apart.
//
// Identity is preserved, so errors.Is against the package's sentinels works exactly
// as it did when they were errors.New values, and the messages are unchanged.
type codedError struct {
	msg  string
	code errcode.Code
}

func (e *codedError) Error() string { return e.msg }

// Code reports the taxonomy classification for this failure.
func (e *codedError) Code() errcode.Code { return e.code }

// compiledAllowlist is the complete set of locations this binary can ever reach on the
// device. Everything else — /data, /proc, the root filesystem, and the rest of shared
// storage — is unreachable, and no runtime input can add to this list. Narrow may remove
// entries or replace one with a subpath of itself; nothing widens it.
//
// It is an array rather than a slice so that it cannot be extended in place, and it is
// never mutated. Roots and the active allowlist hand out copies.
var compiledAllowlist = [...]string{
	"/sdcard/DCIM",
	"/sdcard/Download",
	"/sdcard/Movies",
	"/sdcard/Music",
	"/sdcard/Pictures",
	"/sdcard/Recordings",
}

// activeAllowlist is the allowlist in force. It starts as a copy of compiledAllowlist
// and only ever shrinks, via Narrow. Reads are lock-free because every parsed path
// consults it; writes take narrowMu so that the read-check-store sequence in Narrow
// cannot interleave with another Narrow and lose a restriction.
var (
	activeAllowlist atomic.Pointer[[]string]
	narrowMu        sync.Mutex
)

func init() {
	roots := slices.Clone(compiledAllowlist[:])
	activeAllowlist.Store(&roots)
}

// Roots returns a copy of the allowlist currently in force, sorted, for logging and for
// the operator-facing description of what this run could reach. It is a copy: mutating
// the result cannot change what this binary will serve.
func Roots() []string {
	return slices.Clone(*activeAllowlist.Load())
}

// Narrow restricts the allowlist to subset. It can only ever reduce this binary's
// authority:
//
//   - Every entry must be a well-formed path by the same rules ParseAuthorizedPath
//     applies, and must be within the allowlist currently in force — either one of its
//     roots or a path beneath one, compared over whole segments.
//   - An entry that is not within the active allowlist is an error, never an addition.
//     That includes a parent of a root: Narrow("/sdcard") and Narrow("/") fail rather
//     than being read as "everything beneath", for the same reason ParseAuthorizedPath
//     refuses them.
//   - Checking against the active list rather than the compiled one makes narrowing
//     monotone, so a second call cannot undo the first.
//
// An empty subset is an error. A caller that wants no narrowing should not call Narrow;
// a caller that passes nothing has almost certainly lost its arguments, and silently
// leaving zero reachable roots would report every path as denied with no explanation.
//
// Narrow returns errors wrapping ErrPathDenied and leaves the allowlist untouched when it
// returns an error — it never applies part of a subset.
func Narrow(subset []string) error {
	if len(subset) == 0 {
		return fmt.Errorf("%w: narrow requires at least one path", ErrPathDenied)
	}

	narrowMu.Lock()
	defer narrowMu.Unlock()

	current := *activeAllowlist.Load()

	narrowed := make([]string, 0, len(subset))
	for _, s := range subset {
		if err := checkForm(s); err != nil {
			return fmt.Errorf("narrow %q: %w", s, err)
		}
		if !withinAny(s, current) {
			return fmt.Errorf("narrow %q: %w: not within the allowlist in force (%s)", s, ErrPathDenied, strings.Join(current, " "))
		}
		if !slices.Contains(narrowed, s) {
			narrowed = append(narrowed, s)
		}
	}

	slices.Sort(narrowed)
	activeAllowlist.Store(&narrowed)

	return nil
}

// AuthorizedPath is an absolute device path that has passed every rule this package can
// decide from the string alone. It holds the raw device bytes in a string, which in Go is
// byte-safe: device names may be invalid UTF-8 and are never coerced here. The lossy
// coercion for human-readable output belongs in the App layer's response converter.
//
// The zero value names nothing. It reports IsZero, its String is empty, and Child refuses
// to descend from it, so a caller cannot smuggle authority past a Storer by declaring
// var p AuthorizedPath.
type AuthorizedPath struct {
	path string
}

// ParseAuthorizedPath validates s and returns the AuthorizedPath naming it, or an error
// wrapping ErrPathDenied. It is the only way a caller-supplied string becomes a path the
// storage layer will accept.
//
// A path is rejected before anything else looks at it if it contains a NUL byte, is not
// absolute, does not begin with "/sdcard/", contains a ".." or "." segment, or contains
// an empty segment (a doubled or trailing slash). Every one of those was measured against
// a real device rather than assumed, and each rejection has a reason:
//
//	/sdcard/DCIM\x00x   error=0, returns the inode for /sdcard/DCIM. The kernel truncates
//	                    at the NUL, so this binary would validate one string while the
//	                    device acted on a shorter one, and the audit log would record the
//	                    string that was validated — a faithful record of an operation that
//	                    never happened. This is the only measured case where a missing
//	                    check makes the audit log LIE rather than merely permit a read.
//	/sdcard/DCIM/..     error=0, resolves to the volume root. ".." genuinely escapes
//	                    upward. Resolution is physical — symlinks are expanded first —
//	                    which is why /sdcard/DCIM/.. succeeds while /sdcard/../sdcard/DCIM
//	                    returns error=2.
//	sdcard/DCIM         error=0, same inode as /sdcard/DCIM. Relative paths resolve, with
//	                    adbd's working directory at /. "." returns the root inode.
//	/sdcard/DCIM/       error=0, same inode; so does /sdcard/DCIM//. Two spellings of one
//	                    path would produce two audit records for one operation.
//
// Having survived those, the path must lie within the allowlist. Matching is over whole
// segments, never over string prefixes: /sdcard/Download authorises
// /sdcard/Download/a.jpg and does NOT authorise /sdcard/Download-private/a.jpg. That
// distinction is not theoretical — measured, /sdcard/Download-private returns error=2,
// meaning the device would have answered had it existed.
//
// A path that is a PARENT of an allowed root — "/sdcard" or "/" — is refused, not
// silently narrowed to the permitted children beneath it. A caller asking for /sdcard is
// asking for something this binary will not do, and saying so is more useful than quietly
// doing something else.
func ParseAuthorizedPath(s string) (AuthorizedPath, error) {
	if err := checkForm(s); err != nil {
		return AuthorizedPath{}, err
	}

	roots := *activeAllowlist.Load()
	if !withinAny(s, roots) {
		return AuthorizedPath{}, fmt.Errorf("%w: %q is not within the allowlist (%s)", ErrPathDenied, s, strings.Join(roots, " "))
	}

	return AuthorizedPath{path: s}, nil
}

// MustParseAuthorizedPath returns the AuthorizedPath naming s and panics if s is denied.
// It is for tests and package-level vars with compiled-in constants only — never for a
// path derived from a request, a flag or a device response, all of which must handle the
// error from ParseAuthorizedPath.
func MustParseAuthorizedPath(s string) AuthorizedPath {
	p, err := ParseAuthorizedPath(s)
	if err != nil {
		panic(err)
	}

	return p
}

// String returns the raw device path bytes as a string, empty for the zero value. The
// bytes are returned unchanged and may be invalid UTF-8; a caller that needs a display
// form must coerce it at the edge, and must not treat the coerced result as
// authoritative — that is what Base64 is for.
func (a AuthorizedPath) String() string { return a.path }

// Bytes returns a copy of the raw device path bytes, which is the form the sync protocol
// puts on the wire. It is a copy, so a caller cannot alter the path through it.
func (a AuthorizedPath) Bytes() []byte { return []byte(a.path) }

// Base64 returns the standard base64 encoding of the raw path bytes. This is the
// authoritative path field in audit records and responses, because it survives names that
// are not valid UTF-8 where the human-readable field cannot.
func (a AuthorizedPath) Base64() string {
	return base64.StdEncoding.EncodeToString([]byte(a.path))
}

// IsZero reports whether a is the zero value, which names nothing and authorises nothing.
func (a AuthorizedPath) IsZero() bool { return a.path == "" }

// Child joins one directory-entry name to a, and is how traversal descends.
//
// name is raw bytes from a device listing and may be invalid UTF-8; it is never coerced.
// A name containing '/' or a NUL byte is rejected, as are ".", ".." and the empty name,
// so a walk cannot assemble a path that ParseAuthorizedPath would have refused. The
// joined path is then revalidated in full, which makes that a guarantee rather than an
// argument: whatever Child returns, ParseAuthorizedPath would also have accepted.
//
// Child on the zero value is denied. Authority has to come from somewhere.
func (a AuthorizedPath) Child(name []byte) (AuthorizedPath, error) {
	switch {
	case a.IsZero():
		return AuthorizedPath{}, fmt.Errorf("%w: cannot descend from the zero path", ErrPathDenied)
	case len(name) == 0:
		return AuthorizedPath{}, fmt.Errorf("%w: empty entry name", ErrPathDenied)
	case slices.Contains(name, '/'):
		return AuthorizedPath{}, fmt.Errorf("%w: entry name %q contains a separator", ErrPathDenied, name)
	case slices.Contains(name, 0):
		return AuthorizedPath{}, fmt.Errorf("%w: entry name %q contains a NUL byte", ErrPathDenied, name)
	case string(name) == ".", string(name) == "..":
		return AuthorizedPath{}, fmt.Errorf("%w: entry name %q is a traversal segment", ErrPathDenied, name)
	}

	return ParseAuthorizedPath(a.path + "/" + string(name))
}

// checkForm applies every rule that does not involve the allowlist: the accepted
// spelling and the rejected path forms. See ParseAuthorizedPath for the measured device
// behaviour behind each one.
func checkForm(s string) error {
	switch {
	case s == "":
		return fmt.Errorf("%w: empty path", ErrPathDenied)
	case strings.IndexByte(s, 0) >= 0:
		// Measured: the device truncates at the NUL and answers for the shorter path.
		return fmt.Errorf("%w: %q contains a NUL byte", ErrPathDenied, s)
	case !strings.HasPrefix(s, "/"):
		// Measured: relative paths resolve, with adbd's working directory at /.
		return fmt.Errorf("%w: %q is not absolute", ErrPathDenied, s)
	case !strings.HasPrefix(s, VolumeRoot+"/"):
		// Covers both an unaccepted spelling of shared storage and a parent of a root,
		// including VolumeRoot itself and "/". Neither is resolved to find out what it
		// would have reached.
		return fmt.Errorf("%w: %q does not begin with %q", ErrPathDenied, s, VolumeRoot+"/")
	}

	// s is absolute, so trimming the leading slash leaves exactly the segments; any
	// empty one is a doubled or trailing slash.
	for seg := range strings.SplitSeq(strings.TrimPrefix(s, "/"), "/") {
		switch seg {
		case "":
			return fmt.Errorf("%w: %q has an empty segment (doubled or trailing slash)", ErrPathDenied, s)
		case ".", "..":
			return fmt.Errorf("%w: %q contains a %q segment", ErrPathDenied, s, seg)
		}
	}

	return nil
}

// withinAny reports whether s is one of roots or lies beneath one of them.
func withinAny(s string, roots []string) bool {
	for _, root := range roots {
		if within(s, root) {
			return true
		}
	}

	return false
}

// within reports whether s is root or lies beneath it, comparing whole path segments.
// A string-prefix test would let /sdcard/Download authorise /sdcard/Download-private,
// which measured returns error=2 on the device — that is, the device would have answered
// had the directory existed.
func within(s, root string) bool {
	if s == root {
		return true
	}

	return len(s) > len(root) && s[len(root)] == '/' && s[:len(root)] == root
}
