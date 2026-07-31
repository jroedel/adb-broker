package broker

import "context"

// runProbe answers one question — is a device reachable, and is it one this broker can serve
// — and writes exactly one object to stdout.
//
// It is called once before a run: a disconnected phone makes every configured source
// unreachable, and saying so once up front is clearer than eleven identical per-source
// failures. Probe is also where the device's storage volume is pinned, so a phone whose
// storage is not in the expected shape is discovered here rather than during a listing.
//
// Two members of the response exist so that a consumer can settle at startup what it would
// otherwise have to discover per source or per file. Both are on ProbeResponse rather than
// here, and neither is anything this function decides:
//
//   - allowlist, the compiled roots this binary can reach, read from devicepath by the
//     response converter. Without it a root configured outside the allowlist is only
//     discoverable by connecting to the phone and being refused, once per source, and a
//     path_denied for a misconfigured source is a configuration error reported far too
//     late. Reporting it widens nothing — the allowlist is compiled in and no runtime
//     input can add to it.
//   - attached_devices, the number of phones the transport reported, which the Storer
//     counted. A consumer that sees 1 can omit --serial on every fetch, and so avoids the
//     probe-per-fetch that honouring a pinned serial otherwise costs — see the comment in
//     fetch.go. This is deliberately reported here instead of adding a serial to
//     ExtBusiness.Fetch, which would hand every caller the capability that seam exists to
//     withhold.
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
		// Recorded even though it never reached the bus: a refusal is the kind of event
		// the audit log most needs, and no decorator on the bus can see this one.
		return e.denyBeforeBus("probe", "", req.Client, err)
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
