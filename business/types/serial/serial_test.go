package serial_test

import (
	"errors"
	"strings"
	"testing"

	"github.com/jroedel/adb-broker/business/types/serial"
)

func TestParseSerialAccepts(t *testing.T) {
	tests := []string{
		"EXAMPLESERIAL1",
		"emulator-5554",
		"192.168.1.5:5555",
	}

	for _, s := range tests {
		got, err := serial.ParseSerial(s)
		if err != nil {
			t.Fatalf("ParseSerial(%q) error = %v, want nil", s, err)
		}
		if got.String() != s {
			t.Fatalf("ParseSerial(%q).String() = %q, want %q", s, got.String(), s)
		}
		if got.IsZero() {
			t.Fatalf("ParseSerial(%q).IsZero() = true, want false", s)
		}
	}
}

func TestParseSerialRejects(t *testing.T) {
	tests := []struct {
		name string
		in   string
	}{
		{"empty", ""},
		{"65 characters", strings.Repeat("a", 65)},
		{"embedded space", "bad serial"},
		{"embedded NUL", "serial\x00"},
		{"non-ASCII letter", "sérial"},
	}

	for _, tt := range tests {
		got, err := serial.ParseSerial(tt.in)
		if !errors.Is(err, serial.ErrInvalidSerial) {
			t.Fatalf("%s: ParseSerial(%q) error = %v, want ErrInvalidSerial", tt.name, tt.in, err)
		}
		if !got.IsZero() {
			t.Fatalf("%s: ParseSerial(%q) returned non-zero Serial on error", tt.name, tt.in)
		}
	}
}

func TestParseSerial64CharactersAccepted(t *testing.T) {
	s64 := strings.Repeat("a", 64)

	got, err := serial.ParseSerial(s64)
	if err != nil {
		t.Fatalf("ParseSerial(64 chars) error = %v, want nil", err)
	}
	if got.String() != s64 {
		t.Fatalf("ParseSerial(64 chars).String() = %q, want %q", got.String(), s64)
	}
}

func TestMustParseSerialPanicsOnInvalid(t *testing.T) {
	defer func() {
		if recover() == nil {
			t.Fatal("MustParseSerial did not panic on an invalid serial")
		}
	}()

	serial.MustParseSerial("bad serial")
}

func TestMustParseSerialOnValid(t *testing.T) {
	got := serial.MustParseSerial("emulator-5554")
	if got.String() != "emulator-5554" {
		t.Fatalf("MustParseSerial(%q).String() = %q, want %q", "emulator-5554", got.String(), "emulator-5554")
	}
}

func TestZeroValueIsZero(t *testing.T) {
	var s serial.Serial

	if !s.IsZero() {
		t.Fatal("zero Serial.IsZero() = false, want true")
	}
	if got := s.String(); got != "" {
		t.Fatalf("zero Serial.String() = %q, want empty", got)
	}
}
