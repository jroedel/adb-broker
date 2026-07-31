package broker

import (
	"context"
	"fmt"

	"github.com/jroedel/adb-broker/business/domain/device/devicebus"
)

// runFetch streams one file to stdout, framed as a header line, the raw bytes, and a trailer
// line.
//
// The framing is what makes a truncated transfer detectable: a consumer reads exactly the
// header's size bytes and then REQUIRES a trailer, so a stream that ends without one is a
// failure whatever the byte count said. A zero-byte file is a success with no bytes between
// the two lines and the empty-input digest in the trailer — an implementation that treated
// "no bytes received" as a failure would break on the empty file that exists on the target
// device.
//
// Nothing is written to the local filesystem: no temp file, no spool, no cache. The consumer
// creates its own staging file, with O_EXCL, which is where the refuse-to-overwrite guarantee
// lives. The audit log is the sole exception and it is append-only.
func runFetch(e env, args []string) int {
	var req FetchRequest

	fs := newFlagSet("fetch", e.stderr)
	fs.StringVar(&req.Path, "path", "", "the file to transfer; must lie within the compiled allowlist")
	serialFlag(fs, &req.Serial)
	clientFlag(fs, &req.Client)

	if exit, ok := e.bindFlags(fs, args); !ok {
		return exit
	}

	in, err := toBusFetchRequest(req)
	if err != nil {
		return e.failCode(requestCode(err), displayBytes(req.Path), err)
	}

	bus := e.bus(in.client)
	ctx := context.Background()

	// ExtBusiness.Fetch identifies only a path — unlike Probe and List it takes no serial —
	// so the only way to honour --serial is to select the device first, which Probe does.
	// Without this, a fetch with two phones attached would fail with multiple_devices even
	// though the caller named one.
	//
	// It is done ONLY when a serial was given. The transport a Probe establishes is the one
	// the Fetch below reuses, so this costs no extra connection; what it does cost is one
	// extra audit record per fetch, and adding twenty thousand probe records to a first run
	// that did not ask for a device to be pinned would be a worse trade.
	if !in.serial.IsZero() {
		if _, err := bus.Probe(ctx, in.serial); err != nil {
			return e.fail(displayBytes(req.Path), err)
		}
	}

	// The payload streams straight to stdout and is never held in memory. The header has
	// to state the exact size before the first byte — that is what makes a truncated
	// transfer detectable, since a consumer reads exactly that many bytes and then requires
	// a trailer — so the size arrives through the seam's FetchInfo callback, which the
	// Storer invokes after its LST2 and before its RECV.
	//
	// Buffering instead would make the peak memory of a fetch the size of the file, on a
	// device whose >4 GiB videos are the entire reason STAT_V2 is mandatory. The two
	// alternatives are worse and are deliberately not taken: a temp file would break the
	// "never write to the local filesystem" rule, and transferring twice to measure first
	// could see a different file the second time, leaving the header describing something
	// the trailer does not.
	//
	// A write failure inside the callback aborts the transfer before any byte moves, which
	// is why the error is returned rather than recorded and ignored.
	var headerErr error

	writeHeader := func(info devicebus.FetchInfo) error {
		header := FetchHeader{Proto: proto, Op: "fetch", Size: info.Size}
		if err := writeJSON(e.stdout, header); err != nil {
			headerErr = err

			return err
		}

		return nil
	}

	result, err := bus.Fetch(ctx, in.path, e.stdout, writeHeader)
	switch {
	case headerErr != nil:
		return e.writeFailed(headerErr)

	case err != nil:
		// The header may already be on stdout with no payload behind it. That is exactly
		// the shape a consumer is required to treat as a failed transfer: it reads fewer
		// than size bytes, or finds no trailer, and rejects the stream.
		return e.fail(displayBytes(req.Path), err)
	}

	if werr := flush(e.stdout); werr != nil {
		return e.writeFailed(werr)
	}

	// The trailer is written last and unconditionally on success. A consumer that does not
	// find it treats the transfer as failed, so it must never be skipped on a path where the
	// bytes did go out.
	return e.emit(fromBusFetchResultResponse(result))
}

// writeFailed reports a failure to put the fetch framing or payload on stdout.
//
// It writes nothing further to stdout: the stream is already part-written, so an error object
// appended to it would be indistinguishable from a trailer that arrived late, and the one
// thing a consumer must be able to conclude from a missing trailer is that the transfer
// failed.
func (e env) writeFailed(err error) int {
	fmt.Fprintf(e.stderr, "adb-broker: write the transfer to stdout: %v\n", err)

	return exitError
}
