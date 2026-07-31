package devicebus

import (
	"github.com/jroedel/adb-broker/business/types/devicepath"
	"github.com/jroedel/adb-broker/business/types/errcode"
	"github.com/jroedel/adb-broker/business/types/filekind"
	"github.com/jroedel/adb-broker/business/types/mtime"
	"github.com/jroedel/adb-broker/business/types/serial"
)

// Device describes one adb-attached phone as it was found at the moment its storage
// volume was pinned.
type Device struct {
	Serial        serial.Serial
	State         string
	Model         string
	BrokerVersion string
	ServerVersion string
	Features      []string

	// Volume is the storage volume pinned for this device during Probe. It is carried
	// OUTWARD here so an extension such as the audit log can record which volume this
	// run trusted — it is never something a caller supplies. See the package doc and
	// Storer for why the asymmetry (an input to the port, an output from the seam)
	// exists.
	Volume devicepath.Volume
}

// FileRecord describes one entry discovered while listing a device's storage. Path is
// already an AuthorizedPath, so nothing downstream re-checks it — authority was decided
// once, at parse time, by devicepath.
type FileRecord struct {
	Path  devicepath.AuthorizedPath
	Size  int64
	Mtime mtime.Mtime
	Kind  filekind.Kind
}

// ListInput names the root and the maximum depth of a listing walk.
type ListInput struct {
	Root     devicepath.AuthorizedPath
	Serial   serial.Serial
	MaxDepth int // 0 = unlimited, 1 = immediate children only
}

// PathError pairs a path with the classification of what went wrong reading it, so a
// consumer can decide from Code alone whether the failure is fatal, or a per-path
// warning to log and continue past.
type PathError struct {
	Path devicepath.AuthorizedPath
	Code errcode.Code
}

// ListSummary reports what a List walk found and skipped, once the walk has finished.
type ListSummary struct {
	Files          int
	RefusedEntries int // non-regular or off-volume entries omitted
	Errors         []PathError

	// Volume is the storage volume this listing was pinned to. It is carried OUTWARD
	// so an extension such as the audit log can record it — it is never an input a
	// caller supplies. See Storer and ExtBusiness for why the volume travels on the
	// port but not on the seam.
	Volume devicepath.Volume
}

// FetchResult reports what was transferred by one Fetch call.
type FetchResult struct {
	Bytes  int64
	SHA256 string

	// Volume is the storage volume this fetch was pinned to. It is carried OUTWARD so
	// an extension such as the audit log can record it — it is never an input a caller
	// supplies. See Storer and ExtBusiness for why the volume travels on the port but
	// not on the seam.
	Volume devicepath.Volume
}
