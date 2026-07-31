package broker

import (
	"bytes"
	"context"
	"fmt"
	"io"
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

	// The header must state the exact size BEFORE the first byte, and the Business seam
	// offers no way to learn a file's size without transferring it: ExtBusiness has Probe,
	// List and Fetch, FetchResult reports the byte count only after the fact, and List
	// refuses a regular file as a listing root. So the payload is held in memory for the
	// length of one transfer.
	//
	// This is the one place in the package that is worse than it reads. It is not a
	// filesystem write, so the "never write to the local filesystem" rule is intact, but the
	// peak memory of a fetch is the size of the file — and this device holds video files
	// large enough for that to matter. The fix is a size on the seam (a Stat on Storer and
	// ExtBusiness, or a Size on FetchResult populated before the RECV, which the store
	// already learns from its LST2), at which point this becomes an io.Copy straight to
	// stdout. Do not "fix" it by writing a temp file, and do not fix it by transferring
	// twice: a second read could see a different file, and the header would then be a
	// measurement of something the trailer does not describe.
	var payload bytes.Buffer

	result, err := bus.Fetch(ctx, in.path, &payload)
	if err != nil {
		return e.fail(displayBytes(req.Path), err)
	}

	header := FetchHeader{Proto: proto, Op: "fetch", Size: result.Bytes}
	if werr := writeJSON(e.stdout, header); werr != nil {
		return e.writeFailed(werr)
	}

	if _, werr := io.Copy(e.stdout, &payload); werr != nil {
		return e.writeFailed(werr)
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
