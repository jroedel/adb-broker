// Package errs accumulates field-level validation errors.
//
// The house rule is that all parsing and validation happens in App-layer
// toBus* converters. Those converters report every invalid field at once
// rather than the first one they reach: a caller that passed three bad flags
// should learn about three bad flags in one run, not discover them one
// invocation at a time.
//
// This is a deliberately small package. It exists so converter signatures can
// say what they mean, not to be a general error framework.
package errs

import (
	"errors"
	"fmt"
	"strings"
)

// FieldError is one field's failure, retaining the underlying error so callers
// can match on it with errors.Is and errors.AsType rather than on its text.
type FieldError struct {
	Field string
	Err   error
}

func (fe FieldError) Error() string {
	return fe.Field + ": " + fe.Err.Error()
}

// Unwrap exposes the underlying cause to errors.Is and errors.As.
func (fe FieldError) Unwrap() error { return fe.Err }

// FieldErrors is an accumulation of per-field failures, in the order they were
// added. Order is insertion order and is stable, because a caller reading an
// error message should see its fields in the order the converter checked them.
type FieldErrors []FieldError

// Add records a failure for one field. A nil err is ignored, so a converter can
// call Add unconditionally with the result of a parse.
func (fes *FieldErrors) Add(field string, err error) {
	if err == nil {
		return
	}

	*fes = append(*fes, FieldError{Field: field, Err: err})
}

// Addf records a failure described by a format string, for the cases where
// there is no underlying error value to carry.
func (fes *FieldErrors) Addf(field, format string, args ...any) {
	*fes = append(*fes, FieldError{Field: field, Err: fmt.Errorf(format, args...)})
}

// Empty reports whether anything has been accumulated.
func (fes FieldErrors) Empty() bool { return len(fes) == 0 }

// Fields lists the field names that failed, in insertion order. A field that
// failed more than once appears more than once.
func (fes FieldErrors) Fields() []string {
	fields := make([]string, len(fes))
	for i, fe := range fes {
		fields[i] = fe.Field
	}

	return fields
}

func (fes FieldErrors) Error() string {
	parts := make([]string, len(fes))
	for i, fe := range fes {
		parts[i] = fe.Error()
	}

	return strings.Join(parts, "; ")
}

// Unwrap returns the accumulated errors so that errors.Is and errors.AsType
// match against any of them. This is what lets an App-layer caller ask whether
// a validation failure was, say, a denied path — without reparsing a message.
func (fes FieldErrors) Unwrap() []error {
	errs := make([]error, len(fes))
	for i, fe := range fes {
		errs[i] = fe
	}

	return errs
}

// ErrorOrNil returns the accumulation as an error, or a genuinely nil error if
// nothing was accumulated.
//
// This method exists because returning a FieldErrors value directly from a
// function declared to return error produces a non-nil interface holding an
// empty slice, which every `if err != nil` in the codebase would then treat as
// a failure. Converters must return fes.ErrorOrNil(), never fes.
func (fes FieldErrors) ErrorOrNil() error {
	if fes.Empty() {
		return nil
	}

	return fes
}

// IsFieldErrors reports whether err is or wraps a FieldErrors, and returns it.
// The App layer uses this to decide that a failure is a caller's input problem
// rather than a device or transport condition.
func IsFieldErrors(err error) (FieldErrors, bool) {
	var fes FieldErrors
	if errors.As(err, &fes) {
		return fes, true
	}

	return nil, false
}
