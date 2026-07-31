// Package errcode is the broker's complete error taxonomy.
//
// Every failure the broker reports to a consumer is classified into one of
// these seventeen codes. The taxonomy exists so a consumer can decide, from the
// code alone, whether a failure ends the whole run, ends one source, or is a
// per-path warning to log and continue past — without parsing an error
// message to guess.
package errcode

import "errors"

// Code is one of the broker's error classifications.
type Code string

const (
	// CodeNoDevice means every source is unreachable because no device is
	// present. Fatal: the consumer aborts the whole run.
	CodeNoDevice Code = "no_device"

	// CodeUnauthorized means the device has not authorized this host for
	// debugging. Fatal: the consumer aborts with instructions to authorize.
	CodeUnauthorized Code = "unauthorized"

	// CodeOffline means the device is known to adb but not currently
	// reachable. Fatal: the consumer aborts.
	CodeOffline Code = "offline"

	// CodeMultipleDevices means more than one device is attached and none was
	// specified. Fatal: the consumer aborts rather than guessing a device.
	CodeMultipleDevices Code = "multiple_devices"

	// CodeNoADBServer means no adb server is running on the host. Fatal: the
	// consumer aborts; the host must start it.
	CodeNoADBServer Code = "no_adb_server"

	// CodePathDenied means a configured path was rejected by policy — a
	// configuration error, not a device condition. Not fatal: the consumer
	// aborts that source, not the run.
	CodePathDenied Code = "path_denied"

	// CodeAuditUnavailable means the audit log could not be established.
	// Fatal: the consumer aborts before making any device contact.
	CodeAuditUnavailable Code = "audit_unavailable"

	// CodeVolumeUnresolved means a configured volume could not be resolved to
	// a device path. Fatal: the consumer aborts the run. A remount fails
	// every remaining source identically, so treating this as a per-source
	// failure would only reproduce the same abort one source at a time.
	CodeVolumeUnresolved Code = "volume_unresolved"

	// CodeRootNotFound means a source's root could not be read.
	//
	// Measured trap: ENOENT does not prove absence.
	// /data/data/com.android.providers.media returns error=2 even though it
	// exists — adbd hides existence rather than admitting a permission
	// failure. So this code must never be presented to a human as proof a
	// tree is gone; the wording must say the root could not be read, not that
	// it does not exist.
	//
	// Not fatal: the consumer skips that source and continues — one folder
	// having been removed (or merely denied) says nothing about the others.
	CodeRootNotFound Code = "root_not_found"

	// CodeNotADirectory means a configured root exists but is not a
	// directory. Not fatal: the consumer skips that source.
	CodeNotADirectory Code = "not_a_directory"

	// CodeNotARegularFile means a fetch target exists and is not a regular file
	// — a directory, a symlink, a socket, a FIFO or a device node — so it is
	// refused before any transfer is attempted. Not fatal: a per-file failure,
	// the run continues.
	//
	// It exists because it was measured being confused with CodePathDenied, which
	// is where every non-regular fetch target used to be reported. The two are
	// genuinely different causes that shared one code. CodePathDenied means the
	// caller asked for a location this broker will not serve — outside the
	// allowlist, spelled in a rejected form, off the pinned volume — which is a
	// configuration error, so it ends that whole source: continuing would produce
	// a backup silently missing a tree. This code means the caller asked for
	// something it is entirely entitled to ask for and that is not a thing to
	// transfer, which ends one file.
	//
	// The distinction is not academic, because of where the case comes from. A
	// consumer fetches the paths a listing gave it, and a listing emits regular
	// files only — so a fetch target that is not a regular file is a path whose
	// kind CHANGED between the listing and the transfer. That is a per-file race,
	// and reporting it as a configuration error made the first consumer to read
	// this contract abort an entire source over one racing file.
	//
	// Nothing about what is refused changed, including for a symlink: the kind
	// check still refuses one before any RECV, which is the whole reason the
	// preflight uses LST2 rather than STA2. What changed is the scope a consumer
	// reads off it, and a per-file scope is the consistent answer — the listing
	// side already omits a symlink as a refused entry rather than as a failure of
	// the source containing it.
	//
	// It is distinguished from CodeNotADirectory by which operation asked. Both
	// report a path whose kind is wrong for what was attempted, and they are
	// deliberately kept apart rather than merged into one "wrong kind" code:
	// not_a_directory is a listing ROOT, and a root that is a file ends that
	// source, while this is one FETCH target and ends one file. One code for both
	// would put a per-source and a per-file failure behind a single value and
	// force a consumer to recover the difference from which subcommand it
	// happened to be running.
	CodeNotARegularFile Code = "not_a_regular_file"

	// CodePermissionDenied means one path under a root could not be read.
	// Not fatal: the consumer warns and continues; this never ends a run.
	CodePermissionDenied Code = "permission_denied"

	// CodePathNotFound means one file disappeared between listing and
	// transfer. Not fatal: a per-file failure, the run continues.
	CodePathNotFound Code = "path_not_found"

	// CodeTransferFailed means one file's transfer failed. Not fatal: a
	// per-file failure, the run continues.
	CodeTransferFailed Code = "transfer_failed"

	// CodeDeviceDisconnected means the device went away mid-run. Fatal: the
	// consumer aborts.
	CodeDeviceDisconnected Code = "device_disconnected"

	// CodeUnsupported means the device or adb version is not supported.
	// Fatal: the consumer aborts, reporting the version.
	CodeUnsupported Code = "unsupported"

	// CodeInternal means the broker itself failed in a way not attributable
	// to the device or configuration. Fatal: the consumer aborts. This is
	// also the safe degradation target for a code this consumer does not
	// recognize.
	CodeInternal Code = "internal"
)

// ParseCode maps a raw string to a Code. An unrecognized string degrades to
// CodeInternal rather than an error, because the taxonomy may grow: a
// consumer that has not been updated with a new code must still fail safe
// (abort) rather than misparse an unknown failure as something benign.
func ParseCode(s string) Code {
	switch Code(s) {
	case CodeNoDevice, CodeUnauthorized, CodeOffline, CodeMultipleDevices,
		CodeNoADBServer, CodePathDenied, CodeAuditUnavailable,
		CodeVolumeUnresolved, CodeRootNotFound, CodeNotADirectory,
		CodeNotARegularFile, CodePermissionDenied, CodePathNotFound,
		CodeTransferFailed, CodeDeviceDisconnected, CodeUnsupported, CodeInternal:
		return Code(s)
	default:
		return CodeInternal
	}
}

// String returns the code's raw string form.
func (c Code) String() string {
	return string(c)
}

// Fatal reports whether a consumer must abort the entire run on this code,
// rather than skipping the affected source or path and continuing.
//
// CodeVolumeUnresolved is fatal even though a single unresolved volume sounds
// like it should only end that one source: a remount fails every remaining
// source the same way, on the same device, for the same reason, so treating
// it as per-source just moves the abort one level up — a source-by-source
// storm of volume_unresolved failures instead of one. Aborting the run here
// is what actually solves the problem this taxonomy exists to solve.
func (c Code) Fatal() bool {
	switch c {
	case CodeNoDevice, CodeUnauthorized, CodeOffline, CodeMultipleDevices,
		CodeNoADBServer, CodeAuditUnavailable, CodeDeviceDisconnected,
		CodeUnsupported, CodeInternal, CodeVolumeUnresolved:
		return true
	default:
		return false
	}
}

// Coder is implemented by an error that carries a classification from this
// taxonomy.
//
// It lives here, in the package that owns the taxonomy, rather than in whichever
// package happens to produce such an error. Two layers independently needed to
// ask "what code is this failure?" — a store deciding what to report, and the
// audit extension deciding what to record — and each had begun growing its own
// answer. A second, slightly different mapping is exactly how the broker's whole
// reason for existing gets undone: the CLI adapter this replaces classified
// failures by matching English in two places that drifted apart.
//
// A producer satisfies it by defining an unexported error type with an exported
// Code method. Nothing needs to import the producer.
type Coder interface {
	Code() Code
}

// From extracts the code an error carries, or CodeInternal if it carries none.
//
// CodeInternal is the safe direction: it is Fatal, so an unclassified failure
// aborts rather than being quietly skipped. A nil error yields the empty Code,
// which is not a classification and is never written to a record — callers report
// success explicitly rather than treating "no code" as "ok".
func From(err error) Code {
	if err == nil {
		return ""
	}

	var coded Coder
	if errors.As(err, &coded) {
		return coded.Code()
	}

	return CodeInternal
}
