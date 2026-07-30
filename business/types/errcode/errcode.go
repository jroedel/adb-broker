// Package errcode is the broker's complete error taxonomy.
//
// Every failure the broker reports to a consumer is classified into one of
// these sixteen codes. The taxonomy exists so a consumer can decide, from the
// code alone, whether a failure ends the whole run, ends one source, or is a
// per-path warning to log and continue past — without parsing an error
// message to guess.
package errcode

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
	// a device path. Not fatal: the consumer aborts that source.
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
		CodePermissionDenied, CodePathNotFound, CodeTransferFailed,
		CodeDeviceDisconnected, CodeUnsupported, CodeInternal:
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
func (c Code) Fatal() bool {
	switch c {
	case CodeNoDevice, CodeUnauthorized, CodeOffline, CodeMultipleDevices,
		CodeNoADBServer, CodeAuditUnavailable, CodeDeviceDisconnected,
		CodeUnsupported, CodeInternal:
		return true
	default:
		return false
	}
}
