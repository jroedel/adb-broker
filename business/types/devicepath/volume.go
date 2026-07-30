package devicepath

import (
	"errors"
	"fmt"
)

// Device-side mode bits. These describe the file type field of a mode as the device's
// kernel reports it over the sync protocol, so they are written out here rather than
// taken from the host's syscall package: the value being tested came off the wire from
// an Android device, not from this machine's filesystem.
const (
	modeTypeMask = 0o170000 // S_IFMT
	modeDir      = 0o040000 // S_IFDIR
)

// ErrVolumeUnresolved is returned by ResolveVolume when the stat of VolumeRoot fails or
// does not yield a directory. The device is not presenting shared storage in the shape
// this broker understands, and guessing is not an option, so the invocation aborts before
// any path is served.
var ErrVolumeUnresolved error = errors.New("volume unresolved")

// StatFunc is everything ResolveVolume needs from a transport, and all it needs. The
// implementation issues the sync protocol's STA2 — which FOLLOWS symlinks, exactly what
// is wanted here — and returns the device's dev, ino and mode.
//
// Keeping the resolver behind this one function is why the volume pin is testable with no
// transport at all, and why this package remains a leaf that imports nothing of its own.
type StatFunc func(path string) (dev, ino int64, mode uint32, err error)

// Volume is a pin on the device's shared-storage filesystem, established once per
// invocation before any listing. It is constructible only by ResolveVolume: there is no
// literal, no setter, and no zero value that means anything, so a fetch attempted before
// the volume was pinned cannot be expressed.
//
// The pin exists because the string rules in path.go cannot cover symlinks. Any app on
// the phone can create /sdcard/Pictures/x as a symlink into /data/data/…, and a broker
// that checks only the requested string has an allowlist any app can step around. An
// earlier design said "refuse a symlink at every path component"; measured, that is
// unimplementable, because /sdcard IS a symlink (mode 0o120644, dev=65034 ino=48, target
// /storage/self/primary) and /storage/self/primary is a symlink too. Refusing symlinks at
// every component rejects every path the allowlist exists to permit.
//
// So the rule compares filesystems instead of spellings. A symlink or bind mount leading
// off the media volume lands on a different dev — measured, the media volume is dev=190,
// /data is dev=65088, the root filesystem is dev=65034 — and is caught by where it
// actually leads rather than by what it is named.
type Volume struct {
	dev      int64
	ino      int64
	resolved bool
}

// ResolveVolume stats the compiled VolumeRoot constant once and pins the result.
//
// This is the ONE place this binary deliberately follows a symlink. It happens once, in
// one function, against a compiled constant — not once per caller-supplied path — which
// is what makes the platform's own root indirection (/sdcard → /storage/self/primary →
// /storage/emulated/0) survivable without granting anything to a caller-supplied symlink.
// VolumeRoot is not an AuthorizedPath and must not become one; the resolver takes the
// constant directly, which is why /sdcard remains denied as a caller-supplied path with
// no contradiction.
//
// The result must be a directory (mode&S_IFMT == S_IFDIR). If it is not, or the stat
// fails, ResolveVolume returns an error wrapping ErrVolumeUnresolved.
//
// The pinned dev is established here, at runtime, per run. dev is NOT stable and must
// never be compiled in: device numbers are assigned at mount time and differ across
// reboots and remounts, so a hard-coded 190 would be a latent silent failure the first
// time the phone rebooted.
func ResolveVolume(stat StatFunc) (Volume, error) {
	if stat == nil {
		return Volume{}, fmt.Errorf("%w: no stat function", ErrVolumeUnresolved)
	}

	dev, ino, mode, err := stat(VolumeRoot)
	if err != nil {
		return Volume{}, fmt.Errorf("%w: stat %s: %w", ErrVolumeUnresolved, VolumeRoot, err)
	}

	if mode&modeTypeMask != modeDir {
		return Volume{}, fmt.Errorf("%w: %s is not a directory (mode 0o%o)", ErrVolumeUnresolved, VolumeRoot, mode)
	}

	return Volume{dev: dev, ino: ino, resolved: true}, nil
}

// Dev returns the pinned device number, the value Contains compares. It is recorded in
// the run's audit record so two runs can be compared after the fact.
func (v Volume) Dev() int64 { return v.dev }

// Ino returns the inode of the resolved root. It is provenance for the audit record — the
// log's job is to answer "what did this binary read", and the identity of the directory it
// started from is part of that answer — and it is compared by NOTHING. See Contains.
func (v Volume) Ino() int64 { return v.ino }

// IsZero reports whether v is an unpinned zero value. An unpinned volume authorises
// nothing: Contains returns false for every dev.
func (v Volume) IsZero() bool { return !v.resolved }

// Contains reports whether an entry on device number dev is on the pinned volume. It is
// the only comparison Volume exposes, and it tests dev and nothing else.
//
// A reader who expects a two-field type to compare both fields will assume that is a bug.
// It is not. ino would add exactly one thing: distinguishing /storage/emulated/0 from
// /storage/emulated/10, Android's multi-user layout — both are dev=190, so dev alone
// cannot tell them apart. Enforcing ino would therefore defend against /sdcard being
// re-pointed at another user's storage, which requires privilege on the PHONE, which the
// threat model puts explicitly out of scope; this device has no second user. dev alone
// catches what IS in scope: a symlink or bind mount leading off the media volume, to
// /data (dev=65088) or the root filesystem (dev=65034). Enforcing ino as well would be a
// control against a threat already declared out of scope, so ino is carried as
// provenance only.
//
// An unpinned Volume contains nothing, so a caller that skipped ResolveVolume cannot
// authorise anything with it.
func (v Volume) Contains(dev int64) bool {
	return v.resolved && v.dev == dev
}
