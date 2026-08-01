package broker

import (
	"context"
	"fmt"

	"github.com/jroedel/adb-broker/business/domain/device/devicebus"
	"github.com/jroedel/adb-broker/business/types/errcode"
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
		// Refused before the bus exists, so recorded here — see denyBeforeBus.
		return e.denyBeforeBus("fetch", req.Path, req.Client, err)
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
			return e.fail(req.Path, err)
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
	var (
		headerErr     error
		headerWritten bool
	)

	writeHeader := func(info devicebus.FetchInfo) error {
		header := FetchHeader{Proto: proto, Op: "fetch", Size: info.Size}
		if err := writeJSON(e.stdout, header); err != nil {
			headerErr = err

			return err
		}
		headerWritten = true

		return nil
	}

	result, err := bus.Fetch(ctx, in.path, e.stdout, writeHeader)
	switch {
	case headerErr != nil:
		return e.writeFailed(headerErr)

	// Once the header is on stdout, NOTHING further may be written there except a
	// trailer. An earlier version wrote a full error object here, and it corrupted the
	// transfer rather than merely failing it: the header promises `size` bytes, so a
	// consumer reads exactly that many — and if the transfer stopped short, those bytes
	// are the payload's prefix followed by the first bytes of the JSON error object.
	// Measured with `--fail-after 5` on a 42-byte file, a consumer would have written
	// `hello` plus 37 bytes of `{"proto":1,"status":"error",…` into its staging file.
	//
	// So the stream simply ends. A missing trailer is already the contract's signal for a
	// failed transfer — "a stream that ends without one is a failure whatever the byte
	// count said" — and it is the only signal that cannot be confused with content.
	//
	// The classification goes to stderr and the exit code, not to stdout. A consumer that
	// needs to know whether the device is still there runs `probe`, which answers exactly
	// that; the alternative, encoding a code into a stream whose length is already
	// committed, cannot be done without a framing change.
	case err != nil && headerWritten:
		return e.transferFailedMidStream(displayBytes(req.Path), err)

	case err != nil:
		// Nothing has been written to stdout yet, so a normal error object is safe and is
		// what a consumer can branch on: no byte count has been committed to, which is the
		// one condition that makes an object on stdout unreadable as payload. This is the
		// contract's pre-header failure, and a consumer tells it from a header by the
		// presence of a status member — the same discriminator a list terminator uses. See
		// FetchHeader, where the trap for a consumer that assumes a header is recorded.
		//
		// The RAW path goes to fail: the error object now carries path_b64 as well as path,
		// and only the raw bytes can produce an authoritative one — see fromBusErrorResponse.
		return e.fail(req.Path, err)
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

// transferFailedMidStream reports a fetch that failed after its header reached stdout.
//
// It writes NOTHING to stdout. The header has already committed to a byte count, so any
// further object there would be read as content by a consumer counting bytes — see the
// comment at the call site for the measured shape of that corruption.
//
// The classification is put on stderr in a single machine-greppable line as well as in prose,
// because a consumer that wants it has nowhere else to look: the code cannot go into a stream
// whose length is already promised. A consumer's practical question after a truncated transfer
// is "is the device still there", and `probe` answers that in one further invocation.
//
// ONLY the code= token on that line is parseable, and the specification says so rather than
// pretending otherwise. The path is unquoted, may contain spaces, is already coerced to valid
// UTF-8 by displayBytes, and — since a device filename may contain a newline — can even forge
// what looks like a second code= line, which is why a consumer must take the FIRST match. A
// path_b64= token was considered and deliberately not added: a fetch names exactly one path,
// supplied by the caller as --path, so the path here is never news to the process reading it,
// while the classification is the one thing it cannot learn anywhere else.
func (e env) transferFailedMidStream(path string, err error) int {
	code := errcode.From(err)
	if code == "" {
		code = errcode.CodeTransferFailed
	}

	fmt.Fprintf(e.stderr, "adb-broker: transfer failed after the header was sent; the stream ends without a trailer\n")
	fmt.Fprintf(e.stderr, "adb-broker: code=%s path=%s: %v\n", code, path, err)

	return exitError
}
