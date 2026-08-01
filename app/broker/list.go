package broker

import (
	"context"
	"errors"
	"fmt"

	"github.com/jroedel/adb-broker/business/domain/device/devicebus"
)

// errStdout marks a failure to write the protocol to stdout, so a listing that stopped
// because its output went away is not reported as a device condition — and so the code does
// not then try to explain the failure on the stream that just failed.
var errStdout = errors.New("write a record to stdout")

// runList enumerates a tree, writing one NDJSON record per regular file AS IT IS DISCOVERED
// and exactly one terminating object.
//
// Nothing buffers the listing. The record callback handed to the Business layer writes and
// flushes immediately, because a twenty-thousand-file listing has to be parseable
// incrementally: a consumer that must wait for the last record to see the first cannot
// report progress, and a consumer that runs out of memory holding one cannot run at all.
//
// The stream is always terminated by exactly one object carrying a status member — a
// summary when the walk finished (status ok or partial), an error object when it did not.
// status, not the absence of a path, is the discriminator: a terminating error object MAY
// carry a path (a denied root does, for one), so a consumer that decoded "no path member"
// as "this must be a file record" would read that error object as a record with an empty
// path and a zero size and mtime, silently losing its code. FileRecordResponse never
// carries status, so a consumer checks for that member's presence rather than path's
// absence, and then tells the two terminator kinds apart from each other by status's value.
func runList(e env, args []string) int {
	var req ListRequest

	fs := newFlagSet("list", e.stderr)
	fs.StringVar(&req.Root, "root", "", "the tree to enumerate; must lie within the compiled allowlist")
	fs.IntVar(&req.MaxDepth, "max-depth", 0, "0 enumerates the whole tree, 1 immediate children only")
	serialFlag(fs, &req.Serial)
	clientFlag(fs, &req.Client)

	if exit, ok := e.bindFlags(fs, args); !ok {
		return exit
	}

	// A denied root fails here, with path_denied, before a bus exists and therefore before
	// any transport connection is attempted. That ordering is the point: the allowlist is
	// enforced against the caller, and a caller asking for a location this binary will not
	// serve must not cause a phone to be touched at all.
	in, err := toBusListRequest(req)
	if err != nil {
		// A --root outside the allowlist is refused here, before any transport exists, so
		// the audit extension never sees it. Recorded here instead: a caller probing trees
		// it has no business reading is exactly what the log is for.
		return e.denyBeforeBus("list", req.Root, req.Client, err)
	}

	emit := func(rec devicebus.FileRecord) error {
		if werr := writeJSON(e.stdout, fromBusFileRecordResponse(rec)); werr != nil {
			return fmt.Errorf("%w: %w", errStdout, werr)
		}

		return nil
	}

	summary, err := e.bus(in.client).List(context.Background(), in.list, emit)

	switch {
	case errors.Is(err, errStdout):
		// stdout is gone. There is nowhere to put an error object, and the records already
		// written are all the consumer will ever get; the operation is in the audit log
		// either way.
		fmt.Fprintf(e.stderr, "adb-broker: %v\n", err)

		return exitError

	case err != nil:
		// A walk that failed part way has already written records. The error object
		// terminates the stream in place of a summary, which is what tells a consumer that
		// what it received is not the whole tree — the alternative, a summary that counted
		// only what happened to arrive, would read as a complete listing of a smaller phone.
		// req.Root, not displayBytes(req.Root): fail's path parameter now has to reach
		// fromBusErrorResponse (convert.go) as raw bytes, because that is the one place
		// Path and PathB64 are both built from it. Coercing here would make the two
		// members disagree the moment root is not valid UTF-8 — see fromBusErrorResponse.
		return e.fail(req.Root, err)
	}

	return e.emit(fromBusListSummaryResponse(summary))
}
