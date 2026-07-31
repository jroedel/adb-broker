package errcode_test

import (
	"testing"

	"github.com/jroedel/adb-broker/business/types/errcode"
)

func TestParseCodeRoundTripsAllSixteen(t *testing.T) {
	codes := []errcode.Code{
		errcode.CodeNoDevice,
		errcode.CodeUnauthorized,
		errcode.CodeOffline,
		errcode.CodeMultipleDevices,
		errcode.CodeNoADBServer,
		errcode.CodePathDenied,
		errcode.CodeAuditUnavailable,
		errcode.CodeVolumeUnresolved,
		errcode.CodeRootNotFound,
		errcode.CodeNotADirectory,
		errcode.CodePermissionDenied,
		errcode.CodePathNotFound,
		errcode.CodeTransferFailed,
		errcode.CodeDeviceDisconnected,
		errcode.CodeUnsupported,
		errcode.CodeInternal,
	}

	if len(codes) != 16 {
		t.Fatalf("test lists %d codes, want 16", len(codes))
	}

	for _, c := range codes {
		got := errcode.ParseCode(c.String())
		if got != c {
			t.Fatalf("ParseCode(%q) = %q, want %q", c.String(), got, c)
		}
	}
}

func TestParseCodeUnknownDegradesToInternal(t *testing.T) {
	tests := []string{
		"",
		"totally_unknown_code",
		"NO_DEVICE", // wrong case is not a recognized code
	}

	for _, s := range tests {
		if got := errcode.ParseCode(s); got != errcode.CodeInternal {
			t.Fatalf("ParseCode(%q) = %q, want CodeInternal", s, got)
		}
	}
}

// TestFatalMatchesTheTable is deliberately exhaustive and explicit: listing
// every one of the sixteen codes means adding a seventeenth without deciding
// its fatality fails this test, rather than silently defaulting one way.
func TestFatalMatchesTheTable(t *testing.T) {
	tests := []struct {
		code  errcode.Code
		fatal bool
	}{
		{errcode.CodeNoDevice, true},
		{errcode.CodeUnauthorized, true},
		{errcode.CodeOffline, true},
		{errcode.CodeMultipleDevices, true},
		{errcode.CodeNoADBServer, true},
		{errcode.CodeAuditUnavailable, true},
		{errcode.CodeDeviceDisconnected, true},
		{errcode.CodeUnsupported, true},
		{errcode.CodeInternal, true},
		{errcode.CodeVolumeUnresolved, true},
		{errcode.CodePathDenied, false},
		{errcode.CodeRootNotFound, false},
		{errcode.CodeNotADirectory, false},
		{errcode.CodePermissionDenied, false},
		{errcode.CodePathNotFound, false},
		{errcode.CodeTransferFailed, false},
	}

	if len(tests) != 16 {
		t.Fatalf("test table lists %d codes, want 16", len(tests))
	}

	for _, tt := range tests {
		if got := tt.code.Fatal(); got != tt.fatal {
			t.Fatalf("%s.Fatal() = %v, want %v", tt.code, got, tt.fatal)
		}
	}
}

func TestStringReturnsRawValue(t *testing.T) {
	if got := errcode.CodeNoDevice.String(); got != "no_device" {
		t.Fatalf("CodeNoDevice.String() = %q, want %q", got, "no_device")
	}
}
