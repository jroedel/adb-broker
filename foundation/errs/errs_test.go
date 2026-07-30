package errs_test

import (
	"errors"
	"testing"

	"github.com/jroedel/adb-broker/foundation/errs"
)

var errSentinel = errors.New("sentinel")

func TestAddIgnoresNil(t *testing.T) {
	var fes errs.FieldErrors
	fes.Add("root", nil)

	if !fes.Empty() {
		t.Fatalf("Add(nil) recorded something: %v", fes)
	}
	if err := fes.ErrorOrNil(); err != nil {
		t.Fatalf("ErrorOrNil() = %v, want nil", err)
	}
}

// theMistake is what a converter must not do: return the accumulation itself
// from a function declared to return error. Even when empty, the result is a
// non-nil interface holding an empty slice, so every `if err != nil` upstream
// treats a successful validation as a failure.
func theMistake() error {
	var fes errs.FieldErrors
	return fes
}

// theFix is what converters must do instead.
func theFix() error {
	var fes errs.FieldErrors
	return fes.ErrorOrNil()
}

// The typed-nil trap, which is the entire reason ErrorOrNil exists. If the first
// assertion ever starts failing, Go's nil-interface semantics have changed and
// ErrorOrNil is no longer needed.
func TestErrorOrNilIsGenuinelyNil(t *testing.T) {
	if theMistake() == nil {
		t.Fatal("returning an empty FieldErrors as error produced a nil interface; ErrorOrNil may no longer be needed")
	}

	if err := theFix(); err != nil {
		t.Fatalf("ErrorOrNil() = %v, want a nil interface", err)
	}
}

func TestOrderIsInsertionOrder(t *testing.T) {
	var fes errs.FieldErrors
	fes.Add("root", errSentinel)
	fes.Addf("serial", "bad serial %q", "x")
	fes.Add("path", errSentinel)

	want := []string{"root", "serial", "path"}
	got := fes.Fields()

	if len(got) != len(want) {
		t.Fatalf("Fields() = %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("Fields() = %v, want %v", got, want)
		}
	}

	const wantMsg = `root: sentinel; serial: bad serial "x"; path: sentinel`
	if fes.Error() != wantMsg {
		t.Fatalf("Error() = %q, want %q", fes.Error(), wantMsg)
	}
}

// The point of carrying the underlying error rather than a string: the App layer
// maps a validation failure to an error code by matching the cause, never by
// matching text.
func TestErrorsIsMatchesThroughAccumulation(t *testing.T) {
	var fes errs.FieldErrors
	fes.Addf("serial", "not a serial")
	fes.Add("root", errSentinel)

	err := fes.ErrorOrNil()

	if !errors.Is(err, errSentinel) {
		t.Fatal("errors.Is did not match a cause held in the accumulation")
	}
	if errors.Is(err, errors.New("unrelated")) {
		t.Fatal("errors.Is matched an unrelated error")
	}
}

func TestErrorsAsTypeFindsFieldError(t *testing.T) {
	var fes errs.FieldErrors
	fes.Add("root", errSentinel)

	fe, ok := errors.AsType[errs.FieldError](fes.ErrorOrNil())
	if !ok {
		t.Fatal("errors.AsType did not find a FieldError")
	}
	if fe.Field != "root" {
		t.Fatalf("FieldError.Field = %q, want %q", fe.Field, "root")
	}
}

func TestIsFieldErrors(t *testing.T) {
	var fes errs.FieldErrors
	fes.Add("root", errSentinel)

	got, ok := errs.IsFieldErrors(fes.ErrorOrNil())
	if !ok {
		t.Fatal("IsFieldErrors did not recognize its own type")
	}
	if len(got) != 1 || got[0].Field != "root" {
		t.Fatalf("IsFieldErrors returned %v", got)
	}

	if _, ok := errs.IsFieldErrors(errSentinel); ok {
		t.Fatal("IsFieldErrors matched an unrelated error")
	}

	// Wrapped, since the App layer sees converter errors through fmt.Errorf.
	wrapped := errors.Join(errors.New("outer"), fes.ErrorOrNil())
	if _, ok := errs.IsFieldErrors(wrapped); !ok {
		t.Fatal("IsFieldErrors did not see through a wrapping error")
	}
}
