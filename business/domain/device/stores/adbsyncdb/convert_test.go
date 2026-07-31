package adbsyncdb

import (
	"slices"
	"strings"
	"testing"

	"github.com/jroedel/adb-broker/business/types/devicepath"
	"github.com/jroedel/adb-broker/business/types/filekind"
	"github.com/jroedel/adb-broker/foundation/adbwire"
)

func TestToSyncPath(t *testing.T) {
	t.Run("raw bytes go on the wire unchanged", func(t *testing.T) {
		p := devicepath.MustParseAuthorizedPath(testRoot + "/IMG_0001.jpg")

		if got := toSyncPath(p); got != testRoot+"/IMG_0001.jpg" {
			t.Errorf("toSyncPath = %q, want the path unchanged", got)
		}
	})

	t.Run("invalid UTF-8 is not coerced", func(t *testing.T) {
		// Coercing this to UTF-8 would produce a name the device cannot resolve, so the
		// broker would ask for a file that does not exist and report one that does.
		name := []byte{0xff, 0xfe, 'x'}

		p, err := devicepath.MustParseAuthorizedPath(testRoot).Child(name)
		if err != nil {
			t.Fatalf("Child: %v", err)
		}

		want := append([]byte(testRoot+"/"), name...)
		if got := []byte(toSyncPath(p)); !slices.Equal(got, want) {
			t.Errorf("toSyncPath bytes = %v, want %v", got, want)
		}
	})

	t.Run("the zero path renders empty", func(t *testing.T) {
		if got := toSyncPath(devicepath.AuthorizedPath{}); got != "" {
			t.Errorf("toSyncPath = %q, want empty", got)
		}
	})
}

func TestToBusFileRecord(t *testing.T) {
	p := devicepath.MustParseAuthorizedPath(testRoot + "/IMG_0001.jpg")

	t.Run("natives become strong types", func(t *testing.T) {
		st := adbwire.Stat{Mode: modeRegular, Dev: devMedia, Size: 27190943, Mtime: 1709828653}

		rec, err := toBusFileRecord(p, st)
		if err != nil {
			t.Fatalf("toBusFileRecord: %v", err)
		}

		switch {
		case rec.Path.String() != p.String():
			t.Errorf("Path = %q, want %q", rec.Path, p)
		case rec.Size != 27190943:
			t.Errorf("Size = %d, want 27190943", rec.Size)
		case rec.Kind != filekind.KindRegular:
			t.Errorf("Kind = %s, want regular", rec.Kind)
		case rec.Mtime.Seconds() != 1709828653:
			t.Errorf("Mtime = %d, want the device's own value", rec.Mtime.Seconds())
		}
	})

	t.Run("the mtime is not repaired", func(t *testing.T) {
		// Measured, mtime means different things for different producers on the same
		// device, and this broker is the transport. Whatever the device said is what the
		// record carries — including zero and including a pre-1970 value.
		for _, sec := range []int64{0, -1, 1709828653} {
			rec, err := toBusFileRecord(p, adbwire.Stat{Mode: modeRegular, Mtime: sec})
			if err != nil {
				t.Fatalf("toBusFileRecord: %v", err)
			}

			if rec.Mtime.Seconds() != sec {
				t.Errorf("Mtime = %d, want %d", rec.Mtime.Seconds(), sec)
			}
		}
	})

	t.Run("kinds are classified, not filtered", func(t *testing.T) {
		// The converter reports what the mode says; refusing a kind is the walk's job, and
		// keeping those two separate is what lets the walk count refusals.
		for mode, want := range map[uint32]filekind.Kind{
			modeRegular: filekind.KindRegular,
			modeDir:     filekind.KindDir,
			modeSymlink: filekind.KindSymlink,
			modeSocket:  filekind.KindOther,
		} {
			rec, err := toBusFileRecord(p, adbwire.Stat{Mode: mode})
			if err != nil {
				t.Fatalf("toBusFileRecord: %v", err)
			}

			if rec.Kind != want {
				t.Errorf("mode 0o%o gave %s, want %s", mode, rec.Kind, want)
			}
		}
	})

	t.Run("the zero path is refused", func(t *testing.T) {
		if _, err := toBusFileRecord(devicepath.AuthorizedPath{}, adbwire.Stat{Mode: modeRegular}); err == nil {
			t.Error("the zero path was accepted")
		}
	})

	t.Run("a negative size is refused", func(t *testing.T) {
		// adbwire refuses a size whose high bit is set, so this cannot arrive off the wire.
		// It is an error rather than a repaired zero: a wrong byte count presented as a
		// measurement is worse than a failure.
		if _, err := toBusFileRecord(p, adbwire.Stat{Mode: modeRegular, Size: -1}); err == nil {
			t.Error("a negative size was accepted")
		}
	})
}

func TestToBusDevice(t *testing.T) {
	row := deviceRow{
		serial:          testSerial,
		state:           "device",
		serverVersion:   testServerVer,
		brokerVersion:   testBrokerVer,
		features:        []string{"stat_v2", "ls_v2", "sendrecv_v2"},
		attachedDevices: 2,
	}

	t.Run("natives become the model", func(t *testing.T) {
		dev, err := toBusDevice(row)
		if err != nil {
			t.Fatalf("toBusDevice: %v", err)
		}

		switch {
		case dev.Serial.String() != testSerial:
			t.Errorf("Serial = %q, want %q", dev.Serial, testSerial)
		case dev.State != "device":
			t.Errorf("State = %q, want the token verbatim", dev.State)
		case dev.ServerVersion != testServerVer:
			t.Errorf("ServerVersion = %q, want %q", dev.ServerVersion, testServerVer)
		case dev.BrokerVersion != testBrokerVer:
			t.Errorf("BrokerVersion = %q, want %q", dev.BrokerVersion, testBrokerVer)
		case dev.Model != "":
			t.Errorf("Model = %q, want empty: reading it needs a shell, and there is none", dev.Model)
		case !slices.Equal(dev.Features, row.features):
			t.Errorf("Features = %v, want %v", dev.Features, row.features)
		}
	})

	t.Run("the attached-device count crosses unchanged", func(t *testing.T) {
		// Copied, never recomputed: this converter has no device list, and the row's count
		// came from the one the session had already read. It is also not clamped to 1 for a
		// row whose serial is the selected device's — the count is of the list, not of the
		// selection.
		for _, n := range []int{1, 2, 7} {
			r := row
			r.attachedDevices = n

			dev, err := toBusDevice(r)
			if err != nil {
				t.Fatalf("toBusDevice: %v", err)
			}

			if dev.AttachedDevices != n {
				t.Errorf("AttachedDevices = %d, want %d", dev.AttachedDevices, n)
			}
		}
	})

	t.Run("the state token is carried verbatim", func(t *testing.T) {
		// Not normalised and not mapped: adb's FAIL prose is measured to be identical for
		// several different failures, so the token is the only structured signal there is.
		for _, state := range []string{"device", "unauthorized", "offline", "bootloader", "no permissions"} {
			r := row
			r.state = state

			dev, err := toBusDevice(r)
			if err != nil {
				t.Fatalf("toBusDevice: %v", err)
			}

			if dev.State != state {
				t.Errorf("State = %q, want %q", dev.State, state)
			}
		}
	})

	t.Run("the feature slice is copied", func(t *testing.T) {
		r := row
		r.features = slices.Clone(row.features)

		dev, err := toBusDevice(r)
		if err != nil {
			t.Fatalf("toBusDevice: %v", err)
		}

		dev.Features[0] = "tampered"

		if r.features[0] != "stat_v2" {
			t.Error("a caller mutated what the store believes the device reported")
		}
	})

	t.Run("an unparseable serial is an error", func(t *testing.T) {
		for _, bad := range []string{"", "has space", "tab\there", strings.Repeat("x", 65)} {
			r := row
			r.serial = bad

			if _, err := toBusDevice(r); err == nil {
				t.Errorf("serial %q was accepted", bad)
			}
		}
	})
}
