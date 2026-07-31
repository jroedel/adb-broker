// Package deviceaudit is a devicebus business-layer extension: it decorates a
// devicebus.ExtBusiness so that every Probe, List and Fetch call — success or
// failure alike — appends exactly one record to a hash-chained audit.Log and
// then publishes a best-effort anchor of the log's tail.
//
// # Why a denial is recorded with the same weight as a success
//
// The whole point of this package is to answer, after the fact, "what did
// this run touch and what did it refuse." An audit trail that only writes
// down the operations that succeeded is not a trail of what happened — it is
// a highlight reel that a caller can curate by choosing which errors are
// "worth" recording, and the record that would show a caller repeatedly
// probing paths it has no business reading is precisely the one such
// curation would omit. So every call to Probe, List or Fetch produces one
// record, with Decision "deny" on any error and "allow" on success, before
// this package returns the delegate's result — including its error — exactly
// as received.
//
// # Where each recorded field comes from
//
// Op, CallerUID, ClientAsserted, Decision and Result are this package's own.
// PathB64 is the AuthorizedPath's base64 — never a raw path string, because
// Android filenames are byte strings that need not be valid UTF-8 and a log that
// cannot faithfully record what it read is not evidence of anything.
//
// Serial and Volume travel OUTWARD on the returned Device, ListSummary and
// FetchResult. That is deliberate: the ExtBusiness seam takes no Volume as input,
// so no caller can express an operation on an unpinned volume — which also means
// this extension cannot learn either fact from the call arguments. Fetch in
// particular identifies only a path, so its device comes from FetchResult.Serial.
//
// Seq, Prev, Hash and TS belong to foundation/audit. This package does not compute
// them, so a record cannot claim a position in the chain it does not hold.
package deviceaudit

import (
	"context"
	"encoding/hex"
	"io"
	"time"

	"github.com/jroedel/adb-broker/business/domain/device/devicebus"
	"github.com/jroedel/adb-broker/business/types/devicepath"
	"github.com/jroedel/adb-broker/business/types/errcode"
	"github.com/jroedel/adb-broker/business/types/serial"
	"github.com/jroedel/adb-broker/foundation/audit"
)

// writeAnchor is audit.WriteAnchor, indirected through a package variable so
// this package's own tests can substitute a failing implementation and prove
// that an anchor failure does not affect the audited operation. This is the
// only seam available for that: foundation/audit's journalSocketPath variable
// is unexported and the package is frozen, so a test outside it has no other
// way to point an anchor at an unreachable socket.
var writeAnchor = audit.WriteAnchor

// Extension decorates a devicebus.ExtBusiness, appending one audit.Record for
// every Probe, List and Fetch call it delegates.
type Extension struct {
	bus            devicebus.ExtBusiness
	log            *audit.Log
	callerUID      int
	clientAsserted string
}

// NewExtension returns a devicebus.Extension that appends one audit.Record to
// log for every ExtBusiness call the wrapped bus performs, tagging each
// record with callerUID and clientAsserted. log must already be open (see
// audit.Open); this package never creates or closes it.
func NewExtension(log *audit.Log, callerUID int, clientAsserted string) devicebus.Extension {
	return func(bus devicebus.ExtBusiness) devicebus.ExtBusiness {
		return &Extension{
			bus:            bus,
			log:            log,
			callerUID:      callerUID,
			clientAsserted: clientAsserted,
		}
	}
}

// Probe delegates to the wrapped bus, then records the outcome — the pinned
// volume on success, the zero volume on failure — before returning the
// delegate's Device and error unchanged.
func (ext *Extension) Probe(ctx context.Context, s serial.Serial) (devicebus.Device, error) {
	dev, err := ext.bus.Probe(ctx, s)

	ext.append(entry{
		op:     "probe",
		serial: s.String(),
		vol:    dev.Volume,
		err:    err,
	})

	return dev, err
}

// List delegates to the wrapped bus, passing fn through unmodified so the
// walk keeps streaming rather than buffering behind this extension. It then
// records the outcome using the root's path and the returned ListSummary's
// Volume — never by counting fn invocations itself, so a caller-injected
// callback cannot skew what gets recorded. A listing transfers no file
// bytes, so Bytes is always 0 and SHA256 is always empty for this op —
// inventing a digest for a directory walk would misrepresent it.
func (ext *Extension) List(ctx context.Context, in devicebus.ListInput, fn func(devicebus.FileRecord) error) (devicebus.ListSummary, error) {
	summary, err := ext.bus.List(ctx, in, fn)

	ext.append(entry{
		op:      "list",
		serial:  in.Serial.String(),
		pathB64: in.Root.Base64(),
		vol:     summary.Volume,
		err:     err,
	})

	return summary, err
}

// Fetch delegates to the wrapped bus, then records the outcome, using p's path and
// the returned result's Serial, Bytes, SHA256 and Volume.
//
// ExtBusiness.Fetch takes no serial — unlike Probe and List, a fetch identifies
// only a path — so the device comes from FetchResult.Serial, which the Storer
// populates for exactly this purpose. Fetches are the majority of records on a
// first run, and a record that cannot say which phone the bytes came from is not
// evidence of much.
func (ext *Extension) Fetch(ctx context.Context, p devicepath.AuthorizedPath, w io.Writer, before func(devicebus.FetchInfo) error) (devicebus.FetchResult, error) {
	// before is passed through untouched: it is the caller's framing hook and this
	// extension must not observe or delay it, or the header would no longer precede
	// the bytes it describes.
	result, err := ext.bus.Fetch(ctx, p, w, before)

	ext.append(entry{
		op:      "fetch",
		serial:  result.Serial.String(),
		pathB64: p.Base64(),
		vol:     result.Volume,
		bytes:   result.Bytes,
		sha256:  result.SHA256,
		err:     err,
	})

	return result, err
}

// entry is this package's internal shorthand for the handful of fields that
// vary per operation, so the three ExtBusiness methods above do not each
// repeat a seven-field audit.Record literal.
type entry struct {
	op      string
	serial  string
	pathB64 string
	vol     devicepath.Volume
	bytes   int64
	sha256  string
	err     error
}

// append builds and writes one audit.Record for e, then publishes a
// best-effort anchor of the log's new tail.
//
// Neither an Append failure nor a WriteAnchor failure is surfaced to the
// caller of Probe, List or Fetch — those methods always return exactly what
// the wrapped bus returned. For the anchor this is a deliberate design
// choice, explained on the WriteAnchor call below. For Append itself, the
// alternative — inventing a synthetic error when the log write fails —would
// mean an operation's returned error no longer reflects what the delegate
// actually did, which is the one thing this extension promises never to
// alter. A host where audit.Log.Append is failing (e.g. disk full after
// audit.Open already validated the tail) has a serious problem, but it is
// one for out-of-band monitoring of the log and its journal anchors to
// surface, not one this seam can report without breaking its own contract.
func (ext *Extension) append(e entry) {
	rec := audit.Record{
		TS:             time.Now(),
		Op:             e.op,
		CallerUID:      ext.callerUID,
		ClientAsserted: ext.clientAsserted,
		Serial:         e.serial,
		PathB64:        e.pathB64,
		Decision:       decision(e.err),
		Result:         resultCode(e.err),
		Bytes:          e.bytes,
		SHA256:         e.sha256,
		Volume:         audit.VolumeRef{Dev: e.vol.Dev(), Ino: e.vol.Ino()},
	}

	if _, err := ext.log.Append(rec); err != nil {
		return
	}

	ext.anchor()
}

// anchor publishes a best-effort anchor of the log's current tail.
//
// Anchoring frequency: every operation anchors here, rather than only the
// last one before process exit, or a sampled subset. ExtBusiness has no
// shutdown/close hook this extension could hang a "final anchor" off of —
// Probe, List and Fetch are all it is ever called through — so the only way
// to guarantee the documented invariant "the LAST operation of a process
// always anchors" is to make every operation a candidate for being the last
// one. A first-ever run of roughly 20,000 operations therefore costs roughly
// 20,000 small unixgram datagrams to a local, best-effort socket; that is
// negligible next to the device I/O each operation already performs, and it
// is simpler and more obviously correct than inventing lifecycle plumbing
// that nothing in the frozen seam calls.
//
// A failure here — no journald socket (a non-systemd host), a full socket
// buffer, or an anchor field this run's log path happens to violate — is
// deliberately ignored, with no fallback and no retry: the record it would
// describe is already durably written to the hash-chained log above by
// append. Refusing, or retroactively failing, an operation that has already
// completed and already been recorded because a detectability aid for TAIL
// TRUNCATION could not be published would make the anchor more load-bearing
// than foundation/audit's own doc comment says it is.
func (ext *Extension) anchor() {
	head := ext.log.Head()

	_ = writeAnchor(audit.Anchor{
		Seq:  ext.log.Seq(),
		Hash: hex.EncodeToString(head[:]),
		// An anchor names the log it describes. The whole point of publishing one
		// is that it can be compared against a specific file afterwards, and on a
		// host with more than one install "some log had this head" answers nothing.
		LogPath: ext.log.Path(),
	})
}

// decision reports "allow" for a nil error and "deny" for any error.
// audit.Record.Decision has exactly two values, so this is not a
// classification of which errors count as "real" refusals — any error means
// the operation did not complete as the caller asked, which is what "deny"
// records.
func decision(err error) string {
	result := "allow"
	if err != nil {
		result = "deny"
	}

	return result
}

// resultCode classifies err into the audit record's Result field: "ok" for
// success, or else the errcode.Code the error unwraps to.
//
// The classification is read through errcode.Coder, which is the contract the
// taxonomy package owns, so this extension neither imports nor knows about
// whichever Storer implementation produced the failure. It deliberately does not
// reclassify: a second mapping, subtly different from the store's, is exactly how
// the broker's reason for existing gets undone — the CLI adapter this replaces
// classified failures by matching English in two places, and they drifted apart.
//
// An error carrying no classification becomes errcode.CodeInternal, which mirrors
// errcode.ParseCode's fail-safe default for an unrecognised code and is Fatal, so
// an unclassified failure aborts rather than being quietly skipped.
func resultCode(err error) string {
	switch {
	case err == nil:
		return "ok"

	// errcode.From reads the classification the failing layer already decided on,
	// through the errcode.Coder contract. This package deliberately does not
	// reclassify: a second mapping, slightly different from the store's, is how the
	// broker's whole reason for existing gets undone — the CLI adapter it replaces
	// classified failures in two places that drifted apart. An unclassified error
	// becomes CodeInternal, which is Fatal, so it aborts rather than being skipped.
	default:
		if code := errcode.From(err); code != "" {
			return code.String()
		}

		// Reached only if From says an error carries no code at all, which it does
		// not do for a non-nil error. Kept as a belt-and-braces default rather than
		// letting an empty Result reach the log, where it would read as "no failure".
		return errcode.CodeInternal.String()
	}
}
