// Package filekind classifies a POSIX st_mode, as delivered by the adb sync
// protocol, into the handful of kinds this broker cares about.
//
// The broker's listing omits everything except KindRegular and KindDir. That
// is a confinement requirement, not a preference: symlinks are never followed
// below a volume root, because a symlink can point outside it, so a listing
// that included KindSymlink entries would invite exactly that traversal.
// Sockets, FIFOs, and device nodes are also excluded — they are not files a
// broker mediating access to a phone's storage has any business relaying.
package filekind

// Kind classifies a file by the type bits of its st_mode.
type Kind uint8

const (
	// KindRegular is a regular file (S_IFREG).
	KindRegular Kind = iota + 1
	// KindDir is a directory (S_IFDIR).
	KindDir
	// KindSymlink is a symbolic link (S_IFLNK). The broker never follows one
	// below a volume root and never lists one.
	KindSymlink
	// KindOther is anything else: sockets, FIFOs, block and character
	// devices.
	KindOther
)

// POSIX st_mode file-type mask and the bit patterns it selects. These match
// the values the adb sync protocol delivers verbatim from the device's
// st_mode.
const (
	modeTypeMask = 0o170000 // S_IFMT
	modeRegular  = 0o100000 // S_IFREG
	modeDir      = 0o040000 // S_IFDIR
	modeSymlink  = 0o120000 // S_IFLNK
)

// ParseKind maps a raw st_mode, as delivered by the adb sync protocol, to a
// Kind. Every mode maps to something — unrecognized type bits become
// KindOther — so ParseKind cannot fail and returns a single value.
func ParseKind(mode uint32) Kind {
	switch mode & modeTypeMask {
	case modeRegular:
		return KindRegular
	case modeDir:
		return KindDir
	case modeSymlink:
		return KindSymlink
	default:
		return KindOther
	}
}

// String returns "regular", "dir", "symlink", "other", or "unknown" for the
// zero value.
func (k Kind) String() string {
	switch k {
	case KindRegular:
		return "regular"
	case KindDir:
		return "dir"
	case KindSymlink:
		return "symlink"
	case KindOther:
		return "other"
	default:
		return "unknown"
	}
}

// IsRegular reports whether k is KindRegular.
func (k Kind) IsRegular() bool {
	return k == KindRegular
}

// IsDir reports whether k is KindDir.
func (k Kind) IsDir() bool {
	return k == KindDir
}
