//go:build fixture

package broker

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"github.com/jroedel/adb-broker/business/domain/device/devicebus"
	"github.com/jroedel/adb-broker/business/domain/device/stores/fixturedb"
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
// +fixture suffix, which appears in the first probe response and in every audit record it
// writes.
//
// # Why the audit log moves
//
// The release audit log is /var/log/adb-broker/audit.log, owned by the broker's own uid with
// chattr +a, created by the installer. A developer running the fixture binary is not that
// uid and cannot open it, so fixture mode keeps its log inside the fixture directory. That
// is a real hash-chained log with a real fail-closed check on its tail — the mechanism is
// exercised, not stubbed — it simply lives somewhere a test can create.
//
// The release path stays a const in broker.go and is unreachable from here.
func init() {
	// The +fixture suffix is NOT applied here. fixturedb.NewStore already appends it to the
	// broker version it reports, and that value is the one that reaches probe's response and
	// every audit record. Adding it in both places produced "0.1.0+fixture+fixture".
	globalFlags = parseFixtureFlag

	// Both read fixtureDir at call time, because it is not known until the flag is parsed.
	newStorer = func(brokerVersion string) devicebus.Storer {
		return fixturedb.NewStore(fixtureDir, brokerVersion)
	}

	openAuditLog = func() (*audit.Log, error) { return openFixtureAuditLog() }
}

// fixtureDir is the directory served as the device, set by --fixture.
var fixtureDir string

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
func openFixtureAuditLog() (*audit.Log, error) {
	if fixtureDir == "" {
		return nil, fmt.Errorf("%w: the fixture binary needs --fixture DIR before the subcommand", audit.ErrAuditUnavailable)
	}

	dir := filepath.Join(fixtureDir, "var", "log", "adb-broker")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return nil, fmt.Errorf("%w: create %s: %w", audit.ErrAuditUnavailable, dir, err)
	}

	path := filepath.Join(dir, "audit.log")
	if _, err := os.Stat(path); errors.Is(err, os.ErrNotExist) {
		f, cerr := os.OpenFile(path, os.O_CREATE|os.O_WRONLY, 0o640)
		if cerr != nil {
			return nil, fmt.Errorf("%w: create %s: %w", audit.ErrAuditUnavailable, path, cerr)
		}
		_ = f.Close()
	}

	return audit.Open(path)
}
