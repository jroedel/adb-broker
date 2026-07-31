// Package broker is the adb broker's App layer: it turns one argv into one Business call
// and one wire-format response on stdout.
//
// # The four rules this package exists to hold
//
//   - stdout carries the protocol and nothing else. No banners, no progress, no warnings.
//     stderr is for humans. Every byte this package writes to stdout goes through writeJSON
//     or the fetch payload copy, so the rule is enforced in two places rather than
//     everywhere.
//   - Primitives at the edge. Every request and response struct in wire.go holds strings
//     and ints; the strong types from business/types live on the far side of a toBus* or
//     fromBus*Response converter in convert.go, and all parsing and validation happens
//     there, reported as errs.FieldErrors.
//   - Fail closed before anything else. Main opens the audit log before a bus exists and
//     before any device is contacted. Wiring the audit extension is not what makes the log
//     exist; the log is opened unconditionally here, and the extension is only what writes
//     to it, so a wiring mistake cannot disable it.
//   - The environment is not read, at all. See auditLogPath below, and
//     TestPackageSourceReadsNoEnvironment, which fails if any non-test file in this package
//     or in cmd/adb-broker mentions os.Getenv, os.LookupEnv or os.Environ.
//
// # Error classification
//
// Every code on the wire comes from errcode.From, which reads the classification the
// failing layer already attached through the errcode.Coder contract. This package builds no
// error-to-code table of its own and never inspects a message: two mappings for one
// taxonomy, drifting apart, is the exact failure the broker exists to remove from the CLI
// adapter it replaces.
package broker

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"time"

	"github.com/jroedel/adb-broker/business/domain/device/devicebus"
	"github.com/jroedel/adb-broker/business/domain/device/devicebus/extensions/deviceaudit"
	"github.com/jroedel/adb-broker/business/domain/device/stores/adbsyncdb"
	"github.com/jroedel/adb-broker/business/types/errcode"
	"github.com/jroedel/adb-broker/foundation/audit"
)

// auditLogPath is the ONE place the audit log's location is written down, and it is a
// compiled-in constant on purpose.
//
// No flag, environment variable or configuration file may change it. The guarantee the log
// provides is that an operation the caller cannot reach was recorded before it happened; a
// caller that can redirect the log to a file it owns has removed that guarantee without
// removing the appearance of it. The installer creates this file owned by the broker's own
// uid with the append-only attribute set, and the broker is given no way to bring a log
// into existence — a process that can create its own audit log can also delete the real one
// and start a fresh chain.
//
// This is also why THIS BINARY IS SETUID AND IGNORES ITS ENVIRONMENT ENTIRELY. A setuid
// binary inherits the caller's environment and Go's runtime does not sanitize it, so there
// is no environment read anywhere in this package: no ADB_* variable, no proxy variable, no
// path override. The compiled-in constant and the absent environment reads are the same
// decision looked at from two sides.
const auditLogPath = "/var/log/adb-broker/audit.log"

// version is this binary's own version, reported as the broker member of a probe response
// and recorded on the Device the audit log sees. It is not read from the device and it is
// not read from the environment.
//
// It is a var rather than a const only so the fixture build can mark itself: a fixture
// binary reports a version with a suffix, so one sitting in a production path is visible in
// the first probe response rather than being indistinguishable from the real thing.
var version = "0.1.0"

// The process exit statuses. The exit code is a COARSE signal and the JSON status member is
// authoritative — a consumer that branches on the exit code alone cannot tell a partial
// listing from a complete one, which is why both exist.
const (
	// exitOK covers status "ok" and status "partial". A partial listing produced usable
	// output, so it is a success.
	exitOK = 0

	// exitError means an error object was written and no usable output was produced.
	exitError = 1

	// exitUsage means this binary could not interpret the invocation at all: no
	// subcommand, an unknown one, or flags it could not parse. An error object is still
	// written, so a consumer never has to parse usage text.
	exitUsage = 2
)

// The seams this package is tested through. All of them are unexported package variables, so
// nothing outside the package — and nothing at runtime — can move them: they are visible to
// this package's own tests and to the fixture build, and to nothing else.
var (
	// openAuditLog opens the audit log at the compiled-in path. The indirection exists so
	// tests can point the fail-closed check at a t.TempDir() file instead of needing root
	// and instead of touching /var/log/adb-broker. The PATH stays a constant; only the act
	// of opening is replaceable, and only from inside this package.
	openAuditLog = func() (*audit.Log, error) { return audit.Open(auditLogPath) }

	// globalFlags consumes any arguments that appear before the subcommand and returns the
	// remainder. The release build takes none; see Main.
	globalFlags = func(args []string) ([]string, error) { return args, nil }

	// newStorer builds the transport this invocation will read the device through. Tests
	// substitute a fake so no phone is needed, and the fixture build substitutes a store
	// that serves a local directory.
	newStorer = func(brokerVersion string) devicebus.Storer { return adbsyncdb.NewStore(brokerVersion) }

	// publishAnchor publishes an anchor of the audit log's tail. It is the ONE place this
	// binary anchors from — the audit extension is handed it, and denyBeforeBus calls it —
	// so a run cannot advance the chain head down one path and anchor down another.
	//
	// It is a seam because without one this package's tests publish real anchors into the
	// host's journal: 3,321 entries stamped _EXE=…/broker.test are permanently in this
	// host's, claiming chain heads for logs in temporary directories that no longer exist.
	// Journal entries cannot be removed, so every one of them is noise a future verify has
	// to discard forever. The narrower alternative was considered and rejected — see
	// foundation/audit's journalSocketPath, which stays unexported precisely so that no
	// production caller can aim the broker's anchors anywhere.
	publishAnchor deviceaudit.AnchorFunc = audit.AnchorTail

	// stdinReader is this process's standard input, read only by verify's --anchors - form.
	// Main's signature carries the two OUTPUT streams, so this is what makes the stdin path
	// testable in process.
	stdinReader io.Reader = os.Stdin
)

// Main runs one subcommand and returns the process exit status.
//
// It takes argv without the program name, and the two output streams, rather than reading
// os.Args and calling os.Exit, so that every subcommand is testable in process. That is
// most of how this package is tested.
//
// The order of operations is load bearing:
//
//  1. The subcommand name is resolved. A help request and an unknown subcommand are
//     answered here, without opening the audit log, because printing usage is not an
//     operation and must work on a host where the audit identity has not been installed.
//  2. The audit log is opened and its tail verified. If that fails, an audit_unavailable
//     error object is written and the invocation ends, having done nothing else.
//  3. Only then are flags parsed, a bus constructed, and a device contacted.
//
// Step 2 precedes step 3 deliberately: a caller must not be able to learn whether its flags
// were acceptable on a host where the operation could not have been recorded. One consequence
// is that "<subcommand> --help" is answered only after the log opens, while the top-level
// "help" is answered before — the check is what decides whether this binary interprets flags
// at all, so it cannot come second.
//
// Step 2 applies to verify as well, which is worth being explicit about because verify touches
// no device. The tension is real: verify exists partly to diagnose a damaged log, and a log
// whose TAIL will not verify now refuses to be diagnosed. What that costs is bounded — audit
// Open validates only the tail record, so verify still reports an edit anywhere else in the
// chain and still reports a truncation the anchors expose — but if this ordering is ever
// relaxed, verify is the one subcommand where relaxing it would be defensible.
func Main(args []string, stdout, stderr io.Writer) int {
	e := env{stdout: stdout, stderr: stderr}

	if len(args) == 0 {
		usage(stderr)

		// An error object as well as the usage text, for the same reason an unknown
		// subcommand gets one: a consumer that invoked this binary wrongly must be able to
		// tell that from a device failure without parsing prose.
		return e.failUsage(errors.New("no subcommand given"))
	}

	// Arguments that precede the subcommand. The release build accepts none, and that is
	// deliberate: every global flag that could change what this binary reads is a flag that
	// could widen its authority, and the allowlist rule is that no runtime input can. The
	// fixture build replaces this to accept --fixture DIR, which is exactly such a flag —
	// which is why fixture mode is a separate binary behind a build tag.
	args, gerr := globalFlags(args)
	if gerr != nil {
		usage(stderr)

		return e.failUsage(gerr)
	}

	if len(args) == 0 {
		usage(stderr)

		return e.failUsage(errors.New("no subcommand given"))
	}

	name, rest := args[0], args[1:]

	switch name {
	case "help", "-h", "--help":
		// Usage goes to stderr. stdout carries the protocol and nothing else, and a
		// consumer that captured stdout expecting JSON must not find prose in it.
		usage(stderr)

		return exitOK
	}

	run, ok := subcommandFor(name)
	if !ok {
		// Reported through the taxonomy as well as in prose, so a consumer that mis-spells
		// a subcommand can tell that from a device failure without reading English.
		return e.failUsage(fmt.Errorf("unknown subcommand %q; run \"adb-broker help\" for the list", name))
	}

	// verify is exempt from the fail-closed check, and this is the one exemption.
	//
	// audit.Open validates the log's tail and refuses to proceed if it does not verify.
	// Gating verify on that makes the tool that exists to diagnose a damaged log unable to
	// open one — the diagnostic refuses precisely when it is needed. verify also never
	// appends: it reads a log named by --log and journal anchors, touches no device and
	// opens nothing for writing, so there is no unauditable read for the check to prevent.
	//
	// Every other subcommand reads the phone, so every other subcommand is gated.
	if name == "verify" {
		return run(e, rest)
	}

	log, err := openAuditLog()
	if err != nil {
		// Every failure audit.Open reports wraps ErrAuditUnavailable. Anything else would
		// be a bug in this seam, and internal — which is fatal — is the safe reading of it.
		code := errcode.CodeInternal
		if errors.Is(err, audit.ErrAuditUnavailable) {
			code = errcode.CodeAuditUnavailable
		}

		return e.failCode(code, "", err)
	}
	defer func() { _ = log.Close() }()

	e.log = log

	return run(e, rest)
}

// runFunc is one subcommand. It receives the already-validated audit log, so no subcommand
// can run before the fail-closed check has passed.
type runFunc func(e env, args []string) int

// subcommandFor resolves a subcommand name. There are four, matching the Business port plus
// the operator-run verify, and there is no alias table: a name this binary does not know is
// an error rather than a guess.
func subcommandFor(name string) (runFunc, bool) {
	switch name {
	case "probe":
		return runProbe, true
	case "list":
		return runList, true
	case "fetch":
		return runFetch, true
	case "verify":
		return runVerify, true
	default:
		return nil, false
	}
}

// env is everything a subcommand needs from Main: the two streams and the audit log whose
// tail has already been verified.
type env struct {
	stdout io.Writer
	stderr io.Writer
	log    *audit.Log
}

// bus wires the Business core with the audit extension.
//
// callerUID is os.Getuid() — the REAL uid. Under setuid the real uid is the caller's while
// the effective uid is the broker's, and the kernel supplies it, so a caller cannot forge
// it. It is the field in the audit record to trust; clientAsserted, from --client, is a
// caller-controlled label and is evidence of nothing, which is why it is recorded under a
// name nobody can mistake for a verified identity.
//
// The extension is handed publishAnchor and this invocation's stderr. It anchors after every
// record it writes and reports the first failure to publish one on stderr; it never reports
// an anchor failure on stdout, in the exit status, or in the error a subcommand returns.
func (e env) bus(clientAsserted string) devicebus.ExtBusiness {
	return devicebus.NewBusiness(
		newStorer(version),
		deviceaudit.NewExtension(e.log, os.Getuid(), clientAsserted, publishAnchor, e.stderr),
	)
}

// emit writes one protocol object to stdout and reports the exit status for it.
func (e env) emit(v any) int {
	if err := writeJSON(e.stdout, v); err != nil {
		// stdout is gone, so there is nowhere to report this in the protocol. The operation
		// itself already happened and is already in the audit log.
		fmt.Fprintf(e.stderr, "adb-broker: write the response to stdout: %v\n", err)

		return exitError
	}

	return exitOK
}

// validClientLabel returns raw if it is an acceptable --client label, and empty otherwise.
//
// Used only when recording a refusal, where the label may be the very thing that was
// rejected.
func validClientLabel(raw string) string {
	label, err := toClientLabel(raw)
	if err != nil {
		return ""
	}

	return label
}

// anchor publishes an anchor of the audit log's tail and reports a failure to do so on
// stderr, without changing what this invocation reports to its caller.
//
// It exists for the one record this binary appends outside the audit extension — see
// denyBeforeBus — and it deliberately reads exactly like the extension's own anchoring,
// because it must: both advance the same chain head, and the invariant the extension
// documents is that the LAST operation of a process always anchors. Both route through
// publishAnchor, so the anchor is built in one place (audit.AnchorTail) and neither path
// can drift into publishing a differently shaped claim about the same log.
//
// A failure is reported and nothing more. stderr, never stdout, and never the exit status
// or the error object: the refusal happened and was recorded either way, and an anchor is a
// detectability aid for a truncated tail, not a precondition for the record it describes.
func (e env) anchor() {
	if err := publishAnchor(e.log); err != nil {
		fmt.Fprintf(e.stderr, "adb-broker: %v\n", err)
	}
}

// denyBeforeBus records a refusal that never reached the Business layer, then reports it.
//
// A denial at the flag boundary — a --root outside the allowlist, a --client label that is
// not a valid label — is refused by a converter before any bus exists, so the audit
// extension never sees it and would never write a record. That is precisely the case the
// log exists for: a caller repeatedly asking for paths it has no business reading is the
// pattern an audit trail is supposed to make visible, and it is the one a decorator on the
// bus structurally cannot capture.
//
// The record is written here rather than by widening the extension, because the extension
// decorates operations and this is the refusal of one. op names the attempted subcommand;
// pathB64 is the base64 of the raw requested bytes when there was a path, so an
// unparseable or non-UTF-8 request is still recorded faithfully.
//
// A failure to write the record does not change what is reported to the caller. The
// operation was refused either way, and inventing a different outcome because the log
// write failed would misreport the refusal. The same is true of a failure to anchor it.
//
// The anchor is not optional here, and the first version of this method left it out. A run
// consisting only of a flag-boundary denial appended a record — advancing the log's chain
// head — and published nothing, which breaks the invariant deviceaudit.anchor documents:
// the LAST operation of a process always anchors. The effect was precisely inverted from
// the intent. A caller repeatedly probing paths it has no business reading is the pattern
// this record type exists to catch, and it was the one record type whose tail no anchor
// covered, so a truncation that removed exactly those records could not be detected.
func (e env) denyBeforeBus(op, rawPath, clientAsserted string, err error) int {
	if e.log != nil {
		_, appendErr := e.log.Append(audit.Record{
			TS:        time.Now(),
			Op:        op,
			CallerUID: os.Getuid(),
			// Only a label that passes validation is recorded. The field has documented
			// bounds — at most maxClientBytes, a restricted charset — and writing
			// arbitrary caller bytes into it would break the contract a reader relies on
			// even while treating the value as untrusted. When the label itself is what
			// was rejected, Result already says so.
			ClientAsserted: validClientLabel(clientAsserted),
			PathB64:        base64.StdEncoding.EncodeToString([]byte(rawPath)),
			Decision:       "deny",
			// requestCode, not errcode.From: a validation failure that carries no
			// classification is unsupported — the caller asked for something this
			// binary does not do — and the record must say the same thing the wire
			// object says, or the log and the consumer would disagree about one event.
			Result: requestCode(err).String(),
		})

		// Only a record that actually landed is anchored. A failed Append left the chain
		// head where it was, and anchoring the unchanged head would publish a claim about
		// a record this run did not write.
		if appendErr == nil {
			e.anchor()
		}
	}

	// The RAW bytes, not a display rendering: the error object carries path_b64 as well as
	// path, and a refused path is exactly the case where the raw bytes may not be valid
	// UTF-8. fromBusErrorResponse does the one coercion.
	return e.failCode(requestCode(err), rawPath, err)
}

// fail writes the error object for err, classified by whatever code err carries, and
// reports exitError.
//
// path is the caller's RAW path bytes for the operation, or "" when the failure names none.
// See writeError for why it must not be coerced on the way in.
func (e env) fail(path string, err error) int {
	return e.failCode(errcode.From(err), path, err)
}

// failCode writes an error object with an explicit classification, for the two failures
// that are not carried on an error: the audit log being unavailable, and an invocation this
// binary could not interpret.
func (e env) failCode(code errcode.Code, path string, err error) int {
	e.writeError(code, path, err)

	return exitError
}

// failUsage reports an invocation this binary could not interpret. It is classified
// unsupported — the taxonomy's code for an operation or flag that is not implemented — and
// exits with exitUsage so a script can tell "I called this wrongly" from "the device said
// no" without parsing anything.
func (e env) failUsage(err error) int {
	e.writeError(errcode.CodeUnsupported, "", err)

	return exitUsage
}

// writeError puts one error object on stdout and one human line on stderr.
//
// Message is free-form and for humans only. A consumer branches on Code and logs Message;
// nothing anywhere parses it.
//
// path is the caller's RAW path bytes, not a display string. The error object carries both
// path and path_b64, and only the raw bytes can produce an authoritative path_b64 — so the
// UTF-8 coercion happens once, inside fromBusErrorResponse, rather than at each call site.
// Coercing first and base64-ing the result would publish the base64 of a string full of
// U+FFFD under a member name that promises the opposite.
func (e env) writeError(code errcode.Code, path string, err error) {
	fmt.Fprintf(e.stderr, "adb-broker: %v\n", err)

	res := fromBusErrorResponse(code, path, err)

	if werr := writeJSON(e.stdout, res); werr != nil {
		fmt.Fprintf(e.stderr, "adb-broker: write the error object to stdout: %v\n", werr)
	}
}

// bindFlags parses one subcommand's flags and reports whether the caller may proceed.
//
// A parse failure is the caller's input problem and flag has already described it on
// stderr, so the returned exit status carries the error object and nothing is printed
// twice. flag.ErrHelp is a successful request to explain the subcommand, not a failure.
func (e env) bindFlags(fs *flag.FlagSet, args []string) (int, bool) {
	err := fs.Parse(args)

	switch {
	case err == nil && fs.NArg() > 0:
		// Every subcommand takes flags only. A stray positional argument is far more often
		// a quoting mistake than an intention, and acting on the flags while ignoring it
		// would do something the caller did not ask for.
		return e.failUsage(fmt.Errorf("unexpected argument %q: %s takes flags only", fs.Arg(0), fs.Name())), false

	case err == nil:
		return exitOK, true

	case errors.Is(err, flag.ErrHelp):
		return exitOK, false

	default:
		return e.failUsage(err), false
	}
}

// newFlagSet builds a subcommand's flag set with its output on stderr, because usage text
// and flag errors are for humans and stdout carries the protocol.
func newFlagSet(name string, stderr io.Writer) *flag.FlagSet {
	fs := flag.NewFlagSet("adb-broker "+name, flag.ContinueOnError)
	fs.SetOutput(stderr)

	return fs
}

// serialFlag and clientFlag register the two flags every device-facing subcommand accepts,
// so the help text and the accepted spelling cannot drift between them.
func serialFlag(fs *flag.FlagSet, into *string) {
	fs.StringVar(into, "serial", "", "pin this device serial; required when more than one device is attached")
}

func clientFlag(fs *flag.FlagSet, into *string) {
	fs.StringVar(into, "client", "", "caller-asserted label recorded in the audit log; at most 64 bytes of [A-Za-z0-9._-]")
}

// writeJSON writes v as one compact JSON line, then flushes.
//
// HTML escaping is off. A device path may legitimately contain '<', '>' or '&', and
// encoding/json escapes all three by default — so a path would arrive with a six-character
// escape where one byte belongs, inside a member a consumer compares byte for byte against
// what it asked for.
func writeJSON(w io.Writer, v any) error {
	enc := json.NewEncoder(w)
	enc.SetEscapeHTML(false)

	if err := enc.Encode(v); err != nil {
		return err
	}

	return flush(w)
}

// flush pushes what has been written out of any buffering the caller wrapped stdout in, so
// that a twenty-thousand-file listing is parseable as it arrives rather than at exit.
//
// It is a capability test rather than a requirement because os.Stdout is unbuffered and has
// no Flush: the production path needs nothing here, and a caller that does wrap stdout must
// not silently lose the streaming guarantee.
func flush(w io.Writer) error {
	if f, ok := w.(interface{ Flush() error }); ok {
		return f.Flush()
	}

	return nil
}

// usage describes the four subcommands. It goes to stderr, always.
//
// The journalctl line interpolates audit.MessageID rather than spelling it out. An operator
// copies that command verbatim, so a hard-coded copy that drifted from the constant would
// hand them a filter matching no anchors at all — and "no anchors found" is what a truncated
// tail also looks like.
func usage(w io.Writer) {
	fmt.Fprintf(w, `adb-broker — read-only, audited access to a phone's media over the adb sync protocol

usage:
  adb-broker probe  [--serial <id>] [--client <name>]
  adb-broker list   --root <path> [--max-depth <n>] [--serial <id>] [--client <name>]
  adb-broker fetch  --path <path> [--serial <id>] [--client <name>]
  adb-broker verify [--log <path>] --anchors -

verify compares the audit log against the anchors published to the journal, which is the only
check that detects a truncated tail. It reads them from stdin, because this binary runs at the
broker's own uid and that uid deliberately cannot read the journal files:

  journalctl -o json MESSAGE_ID=%s | adb-broker verify --anchors -

--anchors also accepts a journal file or glob, for a host where this process can read one.

stdout carries the protocol (JSON) and nothing else; this text and every other human-facing
message go to stderr. The audit log's location is compiled in and cannot be changed by a
flag, an environment variable or a configuration file, and no environment variable is read
for any purpose.
`, audit.MessageID)
}
