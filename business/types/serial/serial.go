// Package serial identifies an adb device by its serial number.
//
// The serial is the only durable handle for a device this broker has.
// Measured across a USB port change, a device's serial stayed the same while
// its "usb:" locator went from usb:1-1 to usb:1-2 and its transport_id went
// from 2 to 3. transport_id is a monotonic per-connection counter that
// advances on re-enumeration, so a cached transport_id identifies nothing
// after a reconnect, and after enough churn it could address a different
// phone entirely. usb: paths and transport_id must never be used as device
// identity — only the serial may be.
package serial

import "errors"

// ErrInvalidSerial is returned by ParseSerial when the input is not a valid
// adb device serial.
var ErrInvalidSerial = errors.New("serial: invalid device serial")

const (
	minLen = 1
	maxLen = 64
)

// Serial is a validated adb device serial.
type Serial struct {
	value string
}

// ParseSerial validates s as an adb device serial: 1-64 characters, each one
// a letter, digit, colon, dot, underscore, or hyphen. A colon is allowed
// because network-attached devices are spelled host:port, even though this
// broker never enables ADB-over-network. Anything else — including an empty
// string, whitespace, control characters, and NUL — is rejected with
// ErrInvalidSerial.
func ParseSerial(s string) (Serial, error) {
	if len(s) < minLen || len(s) > maxLen {
		return Serial{}, ErrInvalidSerial
	}

	for _, r := range s {
		if !isValidSerialRune(r) {
			return Serial{}, ErrInvalidSerial
		}
	}

	return Serial{value: s}, nil
}

func isValidSerialRune(r rune) bool {
	switch {
	case r >= 'A' && r <= 'Z':
		return true
	case r >= 'a' && r <= 'z':
		return true
	case r >= '0' && r <= '9':
		return true
	case r == ':' || r == '.' || r == '_' || r == '-':
		return true
	default:
		return false
	}
}

// MustParseSerial parses s and panics if it is invalid. It exists for tests
// and package-level variables built from known-good constants — never for
// request-derived data.
func MustParseSerial(s string) Serial {
	ser, err := ParseSerial(s)
	if err != nil {
		panic(err)
	}

	return ser
}

// String returns the serial's raw value.
func (s Serial) String() string {
	return s.value
}

// IsZero reports whether s is the zero value.
func (s Serial) IsZero() bool {
	return s == Serial{}
}
