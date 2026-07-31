package broker

import "context"

// runProbe answers one question — is a device reachable, and is it one this broker can serve
// — and writes exactly one object to stdout.
//
// It is called once before a run: a disconnected phone makes every configured source
// unreachable, and saying so once up front is clearer than eleven identical per-source
// failures. Probe is also where the device's storage volume is pinned, so a phone whose
// storage is not in the expected shape is discovered here rather than during a listing.
func runProbe(e env, args []string) int {
	var req ProbeRequest

	fs := newFlagSet("probe", e.stderr)
	serialFlag(fs, &req.Serial)
	clientFlag(fs, &req.Client)

	if exit, ok := e.bindFlags(fs, args); !ok {
		return exit
	}

	in, err := toBusProbeRequest(req)
	if err != nil {
		return e.failCode(requestCode(err), "", err)
	}

	dev, err := e.bus(in.client).Probe(context.Background(), in.serial)
	if err != nil {
		// The code comes off the error, through errcode.Coder. Nothing here inspects the
		// message, and nothing here decides between no_device, unauthorized, offline,
		// multiple_devices, unsupported and volume_unresolved — the layer that discovered
		// the condition already did.
		return e.fail("", err)
	}

	return e.emit(fromBusDeviceResponse(dev))
}
