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
	BrokerVersion string
	ServerVersion string
	Features      []string

	// AttachedDevices is how many devices the adb server reported as attached at the
	// moment this store established its transport. Read the next paragraph before using
	// it, because the obvious reading is the wrong one.
	//
	// It counts EVERY entry in the transport's device list. It is NOT the number of
	// devices matching a requested serial: a Probe for one named serial with two phones
	// plugged in reports 2, not 1. It is NOT a count of devices this broker could serve
	// either — a phone in state "unauthorized" or "offline" is attached, is counted here,
	// and would fail the moment anything was asked of it. The only question this number
	// answers is "could an operation that names no device be ambiguous", and a consumer
	// that reads it as anything else will be wrong on a machine with two phones on it.
	//
	// It is carried OUTWARD, like Volume, because only the Storer sees the device list.
	// It exists because ExtBusiness.Fetch takes no serial and must not gain one — that
	// asymmetry is the confinement guarantee documented on ExtBusiness — so the only way
	// the App layer can honour a pinned serial on a fetch is to run a full Probe first,
	// which on a first run of ~20,000 files means 20,000 extra audited operations and
	// 20,000 extra audit records. A consumer that sees exactly 1 here knows a fetch that
	// names no device cannot be ambiguous, and can drop the serial and the probes with it.
	//
	// It is a plain int at both ends of the layering: it is a count, there is no
	// invariant a strong type could enforce over it that the Storer has not already
	// established, and the two stores are the only things that can populate it.
	//
	// A successful Probe reports at least 1 — a Storer that found no device returns an
	// error instead — so a zero here on a successful probe means the Storer did not
	// populate it, not that no phone was attached.
	AttachedDevices int

	// Volume is the storage volume pinned for this device during Probe. It is carried
	// OUTWARD here so an extension such as the audit log can record which volume this
	// run trusted — it is never something a caller supplies. See the package doc and
	// Storer for why the asymmetry (an input to the port, an output from the seam)
	// exists.
	Volume devicepath.Volume
}

// The compiled path allowlist is deliberately NOT on Device.
//
// It is a property of this BINARY — devicepath compiles it in, no runtime input can widen
// it, and Narrow can only take roots away — so no store learns it from a phone and no
// Business logic decides it. Putting it here would mean adbsyncdb and fixturedb each
// populating a compiled constant they did not measure, which is two chances to derive one
// list differently, and it would put the allowlist into every audit record that carries a
// Device as though the device had reported it. The App layer reads devicepath.Roots at
// response-building time instead; see fromBusDeviceResponse. Contrast Volume above, which
// travels outward precisely because only the Storer can know it.

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
