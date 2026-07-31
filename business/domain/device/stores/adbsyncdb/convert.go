package adbsyncdb

import (
	"fmt"

	"github.com/jroedel/adb-broker/business/domain/device/devicebus"
	"github.com/jroedel/adb-broker/business/types/devicepath"
	"github.com/jroedel/adb-broker/business/types/filekind"
	"github.com/jroedel/adb-broker/business/types/mtime"
	"github.com/jroedel/adb-broker/business/types/serial"
	"github.com/jroedel/adb-broker/foundation/adbwire"
)

// The converters at this store's boundary. The house names for a storage layer are
// toDB<Type> outbound and toBus<Type> inbound; outbound here is toSync<Type> instead,
// because the storage behind this boundary is a wire protocol rather than a database — the
// direction and the contract are the same, only the medium differs.
//
// Natives live on this side of the line: adbwire.Stat and adbwire.DeviceEntry hold the
// device's own uint32 modes, int64 devs and raw name bytes, exactly as they arrived, and
// nothing strongly typed crosses outward. The strong types (devicepath.AuthorizedPath,
// filekind.Kind, mtime.Mtime, serial.Serial) appear only in what toBus* returns.

// deviceRow is the row this store assembles for one probe: natives only, as the transport
// reported them, with no parsing and no interpretation.
//
// state is the host:devices token verbatim. Anything other than "device" is fatal to the
// caller, and it needs the raw token to say why, so it is carried rather than mapped: adb's
// FAIL prose is measured to be identical for several different failures, which makes the
// state token the only structured signal about device state the protocol offers.
type deviceRow struct {
	serial        string
	state         string
	serverVersion string
	brokerVersion string
	features      []string
}

// toSyncPath renders an AuthorizedPath as the sync protocol carries it: the raw device
// bytes, unchanged.
//
// The bytes are not coerced to UTF-8 here or anywhere below devicepath. A filename on the
// device is a byte string, and round-tripping an invalid one through Go's replacement
// character would produce a name that cannot be fetched — so the broker would report a
// file it can never read.
func toSyncPath(p devicepath.AuthorizedPath) string {
	return p.String()
}

// toBusFileRecord parses one sync stat reply into the Business record for a path that has
// already been authorised.
//
// It parses natives into strong types and returns an error, per the storage-layer
// contract. p is an AuthorizedPath rather than a string because the only way to obtain one
// for a device-supplied name is AuthorizedPath.Child, which revalidates the whole joined
// path — so nothing downstream re-checks a record's path, and nothing needs to.
func toBusFileRecord(p devicepath.AuthorizedPath, st adbwire.Stat) (devicebus.FileRecord, error) {
	if p.IsZero() {
		return devicebus.FileRecord{}, fmt.Errorf("the zero path names nothing")
	}

	if st.Size < 0 {
		// adbwire refuses a size whose high bit is set, so this cannot come off the wire.
		// It stays an error rather than an assumption: a negative size reaching a consumer
		// as a byte count would be a wrong number presented as a measurement.
		return devicebus.FileRecord{}, fmt.Errorf("size %d is negative", st.Size)
	}

	return devicebus.FileRecord{
		Path:  p,
		Size:  st.Size,
		Mtime: mtime.ParseMtime(st.Mtime),
		Kind:  filekind.ParseKind(st.Mode),
	}, nil
}

// toBusDevice parses a probe's natives into the Business Device.
//
// Model is left empty. It is not obtainable over this transport — reading it needs a
// shell, and there is no shell in this binary — so the field stays empty rather than being
// filled from an invented source that the audit record would then carry as fact.
func toBusDevice(row deviceRow) (devicebus.Device, error) {
	ser, err := serial.ParseSerial(row.serial)
	if err != nil {
		return devicebus.Device{}, fmt.Errorf("parse device serial %q: %w", row.serial, err)
	}

	// The feature slice is copied: a caller must not be able to alter what this store
	// believes the device reported, and the Device outlives the probe that built it.
	features := make([]string, len(row.features))
	copy(features, row.features)

	return devicebus.Device{
		Serial:        ser,
		State:         row.state,
		Model:         "",
		BrokerVersion: row.brokerVersion,
		ServerVersion: row.serverVersion,
		Features:      features,
	}, nil
}
