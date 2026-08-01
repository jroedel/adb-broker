package errcode_test

import (
	"errors"
	"fmt"
	"testing"

	"github.com/jroedel/adb-broker/business/types/errcode"
)

type coded struct{ code errcode.Code }

func (c coded) Error() string      { return "coded: " + string(c.code) }
func (c coded) Code() errcode.Code { return c.code }

func TestFromNilYieldsNoCode(t *testing.T) {
	// Deliberately not CodeInternal: a nil error is not a failure, and a caller must
	// report success explicitly rather than letting "no code" mean "ok".
	if got := errcode.From(nil); got != "" {
		t.Fatalf("From(nil) = %q, want the empty Code", got)
	}
}

func TestFromReadsTheCarriedCode(t *testing.T) {
	err := error(coded{code: errcode.CodePermissionDenied})

	if got := errcode.From(err); got != errcode.CodePermissionDenied {
		t.Fatalf("From = %q, want %q", got, errcode.CodePermissionDenied)
	}
}

// The App and audit layers see store errors through fmt.Errorf, so the contract is
// worthless if it does not survive wrapping.
func TestFromSeesThroughWrapping(t *testing.T) {
	base := error(coded{code: errcode.CodeTransferFailed})
	wrapped := fmt.Errorf("fetch %q: %w", "/sdcard/DCIM/x.jpg", base)
	twice := fmt.Errorf("list: %w", wrapped)

	if got := errcode.From(twice); got != errcode.CodeTransferFailed {
		t.Fatalf("From through two wraps = %q, want %q", got, errcode.CodeTransferFailed)
	}
}

// An unclassified error must become CodeInternal, which is Fatal, so that a failure
// nobody classified aborts rather than being quietly skipped.
func TestFromUnclassifiedIsInternalAndFatal(t *testing.T) {
	got := errcode.From(errors.New("something nobody classified"))

	if got != errcode.CodeInternal {
		t.Fatalf("From(unclassified) = %q, want %q", got, errcode.CodeInternal)
	}
	if !got.Fatal() {
		t.Fatal("CodeInternal is not Fatal; an unclassified failure would be skipped")
	}
}

func TestCoderIsSatisfiableWithoutImportingTheProducer(t *testing.T) {
	var c errcode.Coder = coded{code: errcode.CodeRootNotFound}

	if c.Code() != errcode.CodeRootNotFound {
		t.Fatalf("Coder.Code() = %q", c.Code())
	}
}

// Every code in the taxonomy must round-trip through the contract, so a code added
// later cannot be one From silently mishandles.
func TestFromRoundTripsEveryCode(t *testing.T) {
	for _, c := range []errcode.Code{
		errcode.CodeNoDevice, errcode.CodeUnauthorized, errcode.CodeOffline,
		errcode.CodeMultipleDevices, errcode.CodeNoADBServer, errcode.CodePathDenied,
		errcode.CodeAuditUnavailable, errcode.CodeVolumeUnresolved,
		errcode.CodeRootNotFound, errcode.CodeNotADirectory,
		errcode.CodeNotARegularFile,
		errcode.CodePermissionDenied, errcode.CodePathNotFound,
		errcode.CodeTransferFailed, errcode.CodeDeviceDisconnected,
		errcode.CodeUnsupported, errcode.CodeInternal,
	} {
		wrapped := fmt.Errorf("context: %w", error(coded{code: c}))
		if got := errcode.From(wrapped); got != c {
			t.Errorf("From for %q = %q", c, got)
		}
	}
}
