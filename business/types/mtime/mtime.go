// Package mtime holds a device modification time exactly as the device
// reported it, in whole Unix seconds.
//
// This type exists because "fixing" an mtime is the single most tempting and
// most destructive mistake available to this broker. Measured on the target
// device, mtime means different things for different files: for 10,593 camera
// files the value, rendered in UTC, equals the filename's local wall clock —
// so it sits a whole UTC offset away from the true capture instant — while for
// 3,189 screenshots it is a correct epoch value. The producing application
// decided what the number means, not the transport, and this broker is the
// transport. It has no way to tell a mis-zoned camera timestamp from a correct
// screenshot timestamp, and guessing wrong for one class silently corrupts the
// other.
//
// The one thing the consumer relies on is that the same file reports the same
// value on two runs, so it can skip a file whose mtime has not changed. Any
// helpful normalization — inferring a timezone, reconciling with a filename,
// converting to a time.Time and back — breaks that comparison for every file
// on the device the moment the "fix" disagrees with itself across runs. The
// only symptom is that the incremental fast path silently stops working and
// every run re-transfers everything.
//
// To make that mistake impossible to write, not just inadvisable, this type
// exposes no conversion to time.Time, no timezone handling, and no
// arithmetic. It does not import the standard library time package at all,
// deliberately: there is nothing here to reach for.
package mtime

import "strconv"

// Mtime is a device modification time, in whole Unix seconds, reported
// exactly as the device sent it.
type Mtime struct {
	sec int64
}

// ParseMtime wraps a raw Unix-seconds value exactly as reported by the
// device. It returns a single value rather than the house (T, error) shape
// because every int64 is a valid Mtime — a negative value (a pre-1970 mtime)
// or zero is unusual but not invalid, and the rule is to report what the
// device said. A vestigial always-nil error would only invite every call
// site to check it out of habit.
func ParseMtime(sec int64) Mtime {
	return Mtime{sec: sec}
}

// Seconds returns the raw Unix-seconds value, unmodified.
func (m Mtime) Seconds() int64 {
	return m.sec
}

// String formats the value as plain decimal seconds, e.g. "1709828653". It is
// not a timestamp rendering: there is no timezone applied, because none is
// known.
func (m Mtime) String() string {
	return strconv.FormatInt(m.sec, 10)
}

// IsZero reports whether the value is exactly 0.
func (m Mtime) IsZero() bool {
	return m.sec == 0
}
