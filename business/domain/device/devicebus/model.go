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

// FetchInfo is what a Fetch knows about a file BEFORE any of its bytes move.
//
// It exists so a caller can frame a stream without buffering it. The wire format
// requires the exact size to be stated ahead of the first byte, and a consumer
// reads exactly that many bytes and then requires a trailer -- which is how a
// truncated transfer is detectable at all. Without a size up front the only ways
// to satisfy that are to buffer the whole payload in memory or to transfer twice,
// and this device holds videos over 4 GiB. The size being 64-bit is the entire
// reason STAT_V2 is mandatory, so buffering one in memory to learn it would be a
// poor joke.
//
// The Storer calls the callback after it has stat'd the file and before it reads
// any data. If the callback returns an error the transfer is abandoned, so a
// caller that cannot accept the size never receives bytes it cannot frame.
type FetchInfo struct {
	Size int64
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

	// Serial is the device the bytes were actually read from, carried outward for the
	// same reason as Volume.
	//
	// It is here because ExtBusiness.Fetch takes no serial — Probe and List do, but a
	// fetch identifies only a path — so without this field every fetch record in the
	// audit log would have an empty Serial. That is the majority of records on a first
	// run, and "20,000 files were read from some phone" is not evidence of anything.
	// Unlike Volume, Business does NOT overwrite this: the Storer is the only layer
	// that knows which transport it selected.
	Serial serial.Serial
}
