package mtime_test

import (
	"math"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"testing"

	"github.com/jroedel/adb-broker/business/types/mtime"
)

func TestParseMtimeZero(t *testing.T) {
	m := mtime.ParseMtime(0)

	if !m.IsZero() {
		t.Fatal("ParseMtime(0).IsZero() = false, want true")
	}
	if got := m.Seconds(); got != 0 {
		t.Fatalf("Seconds() = %d, want 0", got)
	}
	if got := m.String(); got != "0" {
		t.Fatalf("String() = %q, want %q", got, "0")
	}
}

func TestParseMtimePositiveMeasuredValue(t *testing.T) {
	const measured = 1709828653

	m := mtime.ParseMtime(measured)

	if m.IsZero() {
		t.Fatal("IsZero() = true for a measured non-zero value")
	}
	if got := m.Seconds(); got != measured {
		t.Fatalf("Seconds() = %d, want %d", got, measured)
	}
	if got := m.String(); got != "1709828653" {
		t.Fatalf("String() = %q, want %q", got, "1709828653")
	}
}

func TestParseMtimeNegative(t *testing.T) {
	m := mtime.ParseMtime(-42)

	if m.IsZero() {
		t.Fatal("IsZero() = true for -42")
	}
	if got := m.Seconds(); got != -42 {
		t.Fatalf("Seconds() = %d, want -42", got)
	}
	if got := m.String(); got != "-42" {
		t.Fatalf("String() = %q, want %q", got, "-42")
	}
}

func TestParseMtimeMaxInt64(t *testing.T) {
	m := mtime.ParseMtime(math.MaxInt64)

	if got := m.Seconds(); got != math.MaxInt64 {
		t.Fatalf("Seconds() = %d, want %d", got, int64(math.MaxInt64))
	}
	if got := m.String(); got != strconv.FormatInt(math.MaxInt64, 10) {
		t.Fatalf("String() = %q, want %q", got, strconv.FormatInt(math.MaxInt64, 10))
	}
}

func TestStringIsPlainDecimal(t *testing.T) {
	tests := []struct {
		sec  int64
		want string
	}{
		{0, "0"},
		{1709828653, "1709828653"},
		{-1, "-1"},
	}

	for _, tt := range tests {
		if got := mtime.ParseMtime(tt.sec).String(); got != tt.want {
			t.Fatalf("ParseMtime(%d).String() = %q, want %q", tt.sec, got, tt.want)
		}
	}
}

// TestPackageDoesNotImportTime is the load-bearing test in this package: the
// whole point of Mtime is that a "helpful" timezone fix must not be available
// to write. If time is ever imported into mtime.go, that guarantee is gone.
func TestPackageDoesNotImportTime(t *testing.T) {
	_, thisFile, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("runtime.Caller(0) failed to report this test file's path")
	}

	srcPath := filepath.Join(filepath.Dir(thisFile), "mtime.go")

	src, err := os.ReadFile(srcPath)
	if err != nil {
		t.Fatalf("os.ReadFile(%q) = %v", srcPath, err)
	}

	if strings.Contains(string(src), `"time"`) {
		t.Fatal(`mtime.go imports "time"; Mtime must not expose any timezone or time.Time conversion`)
	}
}
