//go:build fixture

package broker

import (
	"errors"
	"fmt"
	"path/filepath"
	"strconv"

	"github.com/jroedel/adb-broker/business/domain/device/devicebus"
	"github.com/jroedel/adb-broker/business/domain/device/stores/fixturedb"
	"github.com/jroedel/adb-broker/business/types/errcode"
	"github.com/jroedel/adb-broker/foundation/audit"
)

// This file wires fixture mode, and it exists only under the fixture build tag.
//
// # Why the tag is a security control rather than a convenience
//
// --fixture DIR remaps /sdcard/… onto an arbitrary local directory. That is an allowlist
// bypass by construction: the compiled six roots still apply, but they apply to virtual
// paths whose real location the caller chose. A release binary carrying this flag would be
// a bypass an attacker could use without building anything, so the flag does not exist
// there — not disabled, not guarded by a check, absent from the compiled program.
//
// Two things make a fixture binary in a production path visible rather than
// indistinguishable: it is named adb-broker-fixture, and it reports a broker version with a
// +fixture suffix, which appears in the first probe response and in the version subcommand's
// output.
//
// An earlier version of this comment said the suffix also appeared "in every audit record it
// writes". It does not, and no audit record carries a broker version at all — audit.Record has
// no such field. What keeps fixture traffic out of a real chain is the next section, not the
// suffix.
//
// # Why the audit log moves
//
// The release audit log is the invoking user's own, at ~/.local/state/adb-broker/audit.log.
// A developer running the fixture binary would otherwise append fixture traffic to their real
// chain and anchor it under their real uid, so fixture mode keeps its log inside the fixture
// directory instead. That is a real hash-chained log with a real fail-closed check on its tail
// — the mechanism is exercised, not stubbed — it simply lives somewhere disposable.
//
// This mattered for a different reason before 2026-08-01: the release log was owned by a
// service account the developer was not, so fixture mode could not have opened it at all. The
// separation is now a choice rather than a necessity, which makes it more important to state,
// not less — nothing but this code keeps fixture records out of a real chain.
//
// How the release path is derived stays in broker.go and is unreachable from here.
func init() {
	// The +fixture suffix is NOT applied to version here. fixturedb.NewStore already
	// appends it to the broker version it reports, and that value is the one that reaches
	// probe's response. Adding it in both places produced "0.1.0+fixture+fixture".
	//
	// versionSuffix is the one exception, and it is not a second application of the same
	// mark: the version subcommand answers without building a Store, so nothing appends
	// anything for it, and a fixture binary asked what it is would otherwise answer with
	// the plain release version. It reads versionSuffix and no other path does, so the two
	// cannot both fire on one string. The constant is fixturedb's either way.
	globalFlags = parseFixtureFlag
	versionSuffix = fixturedb.VersionSuffix

	// All three read their package vars at call time, because none is known until the
	// flags are parsed.
	newStorer = func(brokerVersion string) devicebus.Storer {
		var opts []fixturedb.Option

		if failAfter >= 0 {
			opts = append(opts, fixturedb.WithFailAfter(failAfter))
		}
		if injectError != "" {
			opts = append(opts, fixturedb.WithInjectError(injectError))
		}

		return fixturedb.NewStore(fixtureDir, brokerVersion, opts...)
	}

	openAuditLog = openFixtureAuditLog
}

// The fixture build's global flags.
//
// These exist so a CONSUMER's error handling can be tested against the real binary rather
// than against its own fakes. A consumer's branching on the taxonomy's codes is the difference
// between skipping one file and aborting a run, and without injection each branch is
// reachable only by contriving a matching device fault. The spec asks for both hooks for
// exactly that reason.
var (
	// fixtureDir is the directory served as the device, set by --fixture.
	fixtureDir string

	// failAfter truncates a fetch after n bytes; -1 disables it. Zero is meaningful —
	// truncate before the first byte — so the disabled value cannot be zero.
	failAfter int64 = -1

	// injectError makes every operation fail with this code.
	injectError errcode.Code
)

// parseFixtureFlag consumes a leading --fixture DIR (or --fixture=DIR) and returns the rest
// of the arguments.
//
// It is hand-rolled rather than a flag.FlagSet because it has to stop at the subcommand:
// flag would treat "list" as a positional and refuse the flags that follow it.
func parseFixtureFlag(args []string) ([]string, error) {
	for len(args) > 0 {
		arg := args[0]

		switch {
		case arg == "--fixture", arg == "-fixture":
			if len(args) < 2 {
				return nil, errors.New("--fixture needs a directory")
			}
			fixtureDir = args[1]
			args = args[2:]

		case len(arg) > 10 && arg[:10] == "--fixture=":
			fixtureDir = arg[10:]
			args = args[1:]

		case arg == "--fail-after", arg == "-fail-after":
			if len(args) < 2 {
				return nil, errors.New("--fail-after needs a byte count")
			}

			n, err := strconv.ParseInt(args[1], 10, 64)
			if err != nil || n < 0 {
				return nil, fmt.Errorf("--fail-after wants a non-negative byte count, got %q", args[1])
			}
			failAfter = n
			args = args[2:]

		case arg == "--inject-error", arg == "-inject-error":
			if len(args) < 2 {
				return nil, errors.New("--inject-error needs an error code")
			}

			// ParseCode degrades an unknown string to internal, which would silently
			// inject the wrong code. A typo here must be an error, not a surprise.
			code := errcode.ParseCode(args[1])
			if code == errcode.CodeInternal && args[1] != errcode.CodeInternal.String() {
				return nil, fmt.Errorf("--inject-error does not recognize the code %q", args[1])
			}
			injectError = code
			args = args[2:]

		default:
			// Not a global flag, so the subcommand starts here.
			//
			// A missing --fixture is NOT rejected here. Requiring it at the argument
			// boundary would also reject this package's own tests, which replace the
			// newStorer and openAuditLog seams and never intend to reach fixturedb at
			// all. The requirement therefore lives in those seams, which tests replace
			// and a real invocation does not — so the binary still refuses clearly and
			// the tests are unaffected.
			return args, nil
		}
	}

	return args, nil
}

// openFixtureAuditLog opens, creating if needed, a real hash-chained audit log inside the
// fixture directory.
//
// Creating it here is the one difference from the release path, which deliberately never
// creates its log: there, a process that could create its own audit log could also recreate
// it, so the installer makes it. In fixture mode there is no installer and no adversary to
// defend against — the point is to exercise the chain and the fail-closed check, both of
// which behave exactly as they do in production once the file exists.
func openFixtureAuditLog() (*audit.Log, bool, error) {
	if fixtureDir == "" {
		return nil, false, fmt.Errorf("%w: the fixture binary needs --fixture DIR before the subcommand", audit.ErrAuditUnavailable)
	}

	// The same open-or-create the release build performs, at a path under the fixture
	// directory. This used to hand-roll creation, because audit.Open refused to create and
	// only the installer was allowed to; audit.Create exists now, so there is one
	// implementation and fixture mode exercises it rather than a lookalike.
	return openOrCreateLogAt(filepath.Join(fixtureDir, "var", "log", "adb-broker", "audit.log"))
}
