package devicepath_test

import (
	"errors"
	"testing"

	"github.com/jroedel/adb-broker/business/types/devicepath"
	"github.com/jroedel/adb-broker/business/types/errcode"
)

// The sentinels carry their own classification so that no consumer needs a private
// table mapping them to codes. Two layers already needed one — a store deciding what
// to report and the audit extension deciding what to record — and two mappings that
// drift apart is the failure this whole broker exists to remove.
func TestSentinelsCarryTheirOwnCode(t *testing.T) {
	for _, tc := range []struct {
		name string
		err  error
		want errcode.Code
	}{
		{"path denied", devicepath.ErrPathDenied, errcode.CodePathDenied},
		{"volume unresolved", devicepath.ErrVolumeUnresolved, errcode.CodeVolumeUnresolved},
	} {
		if got := errcode.From(tc.err); got != tc.want {
			t.Errorf("%s: errcode.From = %q, want %q", tc.name, got, tc.want)
		}
	}
}

// Carrying a code must not have cost the sentinels their identity: every rejection in
// this package wraps them with %w, and every consumer matches with errors.Is.
func TestSentinelIdentityIsPreserved(t *testing.T) {
	_, err := devicepath.ParseAuthorizedPath("/data/data")
	if err == nil {
		t.Fatal("/data/data was accepted")
	}
	if !errors.Is(err, devicepath.ErrPathDenied) {
		t.Fatal("errors.Is no longer matches ErrPathDenied through a wrapped rejection")
	}
	if got := errcode.From(err); got != errcode.CodePathDenied {
		t.Fatalf("errcode.From through a wrapped rejection = %q", got)
	}

	_, err = devicepath.ResolveVolume(func(string) (int64, int64, uint32, error) {
		return 65034, 48, 0o120644, nil // the measured /sdcard symlink: not a directory
	})
	if !errors.Is(err, devicepath.ErrVolumeUnresolved) {
		t.Fatal("errors.Is no longer matches ErrVolumeUnresolved")
	}
	if got := errcode.From(err); got != errcode.CodeVolumeUnresolved {
		t.Fatalf("errcode.From on an unresolved volume = %q", got)
	}
}

// The messages are part of what an operator reads, so changing the sentinels' dynamic
// type must not have changed what they say.
func TestSentinelMessagesUnchanged(t *testing.T) {
	if got := devicepath.ErrPathDenied.Error(); got != "path denied" {
		t.Errorf("ErrPathDenied.Error() = %q", got)
	}
	if got := devicepath.ErrVolumeUnresolved.Error(); got != "volume unresolved" {
		t.Errorf("ErrVolumeUnresolved.Error() = %q", got)
	}
}
