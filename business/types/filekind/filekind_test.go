package filekind_test

import (
	"testing"

	"github.com/jroedel/adb-broker/business/types/filekind"
)

func TestParseKindRegular(t *testing.T) {
	modes := []uint32{0o100644, 0o100600}

	for _, mode := range modes {
		k := filekind.ParseKind(mode)
		if k != filekind.KindRegular {
			t.Fatalf("ParseKind(0o%o) = %v, want KindRegular", mode, k)
		}
		if !k.IsRegular() {
			t.Fatalf("ParseKind(0o%o).IsRegular() = false", mode)
		}
		if k.IsDir() {
			t.Fatalf("ParseKind(0o%o).IsDir() = true", mode)
		}
		if got := k.String(); got != "regular" {
			t.Fatalf("String() = %q, want %q", got, "regular")
		}
	}
}

func TestParseKindDir(t *testing.T) {
	modes := []uint32{
		0o40755,
		0o42770,
		0o040000 | 0o02770, // setgid directory, S_IFDIR mask applied explicitly
	}

	for _, mode := range modes {
		k := filekind.ParseKind(mode)
		if k != filekind.KindDir {
			t.Fatalf("ParseKind(0o%o) = %v, want KindDir", mode, k)
		}
		if !k.IsDir() {
			t.Fatalf("ParseKind(0o%o).IsDir() = false", mode)
		}
		if k.IsRegular() {
			t.Fatalf("ParseKind(0o%o).IsRegular() = true", mode)
		}
		if got := k.String(); got != "dir" {
			t.Fatalf("String() = %q, want %q", got, "dir")
		}
	}
}

func TestParseKindSymlink(t *testing.T) {
	// /sdcard and /storage/self/primary, both real measured symlinks.
	modes := []uint32{0o120644, 0o120777}

	for _, mode := range modes {
		k := filekind.ParseKind(mode)
		if k != filekind.KindSymlink {
			t.Fatalf("ParseKind(0o%o) = %v, want KindSymlink", mode, k)
		}
		if k.IsRegular() || k.IsDir() {
			t.Fatalf("ParseKind(0o%o) reported IsRegular=%v IsDir=%v, want both false", mode, k.IsRegular(), k.IsDir())
		}
		if got := k.String(); got != "symlink" {
			t.Fatalf("String() = %q, want %q", got, "symlink")
		}
	}
}

func TestParseKindOther(t *testing.T) {
	tests := []struct {
		name string
		mode uint32
	}{
		{"socket", 0o140000},
		{"fifo", 0o010000},
	}

	for _, tt := range tests {
		k := filekind.ParseKind(tt.mode)
		if k != filekind.KindOther {
			t.Fatalf("%s: ParseKind(0o%o) = %v, want KindOther", tt.name, tt.mode, k)
		}
		if k.IsRegular() || k.IsDir() {
			t.Fatalf("%s: ParseKind(0o%o) reported IsRegular=%v IsDir=%v, want both false", tt.name, tt.mode, k.IsRegular(), k.IsDir())
		}
		if got := k.String(); got != "other" {
			t.Fatalf("%s: String() = %q, want %q", tt.name, got, "other")
		}
	}
}

func TestZeroKindIsUnknown(t *testing.T) {
	var k filekind.Kind

	if got := k.String(); got != "unknown" {
		t.Fatalf("zero Kind.String() = %q, want %q", got, "unknown")
	}
	if k.IsRegular() {
		t.Fatal("zero Kind.IsRegular() = true")
	}
	if k.IsDir() {
		t.Fatal("zero Kind.IsDir() = true")
	}
}
