package broker

import (
	"bytes"
	"runtime/debug"
	"testing"

	"github.com/jroedel/adb-broker/foundation/audit"
)

// version's contract is small and every part of it is load bearing somewhere else: an
// installer reads the object to decide whether to overwrite the binary already in place, and
// it has to be able to do that on a host where the audit log is missing, unreadable or
// corrupt. These tests are written against those two readers.

// runVersionCmd drives Main's version subcommand with the suffix pinned to the release build's.
//
// The suffix is pinned rather than inherited because this file has no build tag and therefore
// runs in BOTH configurations: `make test-fixture` compiles it with -tags=fixture, where
// fixture.go's init has already set versionSuffix, and an assertion on exact bytes would then
// pass in one configuration and fail in the other. version_fixture_test.go covers the suffix
// itself, in the only build where it is real.
func runVersionCmd(t *testing.T, logPath string, args ...string) result {
	t.Helper()

	swap(t, &versionSuffix, "")
	swap(t, &openAuditLog, func() (*audit.Log, bool, error) {
		log, err := audit.Open(logPath)

		return log, false, err
	})

	var stdout, stderr bytes.Buffer

	exit := Main(args, &stdout, &stderr)

	return result{exit: exit, stdout: stdout.String(), stderr: stderr.String()}
}

// TestVersionWritesTheStampedIdentity asserts the whole object, byte for byte.
//
// The revision is empty and modified is false because a binary produced by `go test` carries no
// vcs settings — measured, not assumed. That makes this simultaneously the assertion on the
// no-VCS-stamp case: both members are PRESENT and empty, never absent, so a reader never has to
// tell "this build had no commit" from "this broker forgot to say". vcsStamp's own test covers
// the populated case, which no test binary can produce.
func TestVersionWritesTheStampedIdentity(t *testing.T) {
	swap(t, &version, "9.9.9")

	got := runVersionCmd(t, newAuditLog(t), "version")

	want := `{"proto":1,"status":"ok","broker":"9.9.9","revision":"","modified":false}` + "\n"

	switch {
	case got.exit != exitOK:
		t.Errorf("exit = %d, want %d; stderr: %s", got.exit, exitOK, got.stderr)

	case got.stdout != want:
		t.Errorf("stdout =\n\t%s\nwant\n\t%s", got.stdout, want)

	case got.stderr != "":
		// stdout carries the protocol; version reports nothing a human needs told.
		t.Errorf("stderr = %q, want it empty", got.stderr)
	}
}

// TestVersionAnswersWhenTheAuditLogCannotBeOpened is the property the subcommand exists for.
//
// An installer runs this against a binary some other consumer put at the canonical path, on a
// host where that binary's account may never have run it, and it must still learn the version.
// Every other subcommand but verify refuses when the fail-closed check fails; this one is
// outside that check rather than exempt from it, because it reads no log and records nothing.
//
// The log path here is a directory, which audit.Open cannot open as a chain — the same failure
// the other subcommands turn into audit_unavailable and a non-zero exit.
func TestVersionAnswersWhenTheAuditLogCannotBeOpened(t *testing.T) {
	got := runVersionCmd(t, t.TempDir(), "version")

	if got.exit != exitOK {
		t.Fatalf("exit = %d, want %d; stderr: %s", got.exit, exitOK, got.stderr)
	}

	obj := decode(t, lines(t, got.stdout)[0])

	if obj["status"] != statusOK {
		t.Errorf("status = %v, want %q", obj["status"], statusOK)
	}
}

// TestVersionOpensNoAuditLogAtAll goes one step further than the test above: not only does a
// broken log not stop it, no log is opened on the way. A version request that created a chain,
// or anchored one, would write to a log on a host that had only asked what the binary was.
func TestVersionOpensNoAuditLogAtAll(t *testing.T) {
	opened := false

	swap(t, &openAuditLog, func() (*audit.Log, bool, error) {
		opened = true

		return nil, false, nil
	})
	swap(t, &publishAnchor, func(*audit.Log) error {
		t.Error("version published an anchor; it records nothing and must publish nothing")

		return nil
	})

	var stdout, stderr bytes.Buffer

	if exit := Main([]string{"version"}, &stdout, &stderr); exit != exitOK {
		t.Fatalf("exit = %d, want %d; stderr: %s", exit, exitOK, stderr.String())
	}

	if opened {
		t.Error("version opened the audit log; it must answer before the fail-closed check")
	}
}

// TestVersionTakesNoArguments covers both the flag-shaped and the positional form. Neither is
// silently ignored: acting on a request this binary did not understand is the failure the
// usage exit exists to prevent, and a consumer gets an error object rather than prose.
func TestVersionTakesNoArguments(t *testing.T) {
	for _, arg := range []string{"--verbose", "-v", "extra", "--"} {
		t.Run(arg, func(t *testing.T) {
			got := runVersionCmd(t, newAuditLog(t), "version", arg)

			if got.exit != exitUsage {
				t.Fatalf("exit = %d, want %d; stdout: %s", got.exit, exitUsage, got.stdout)
			}

			obj := decode(t, lines(t, got.stdout)[0])

			switch {
			case obj["status"] != statusError:
				t.Errorf("status = %v, want %q", obj["status"], statusError)

			case obj["code"] != "unsupported":
				t.Errorf("code = %v, want %q", obj["code"], "unsupported")
			}
		})
	}
}

// TestVCSStamp covers the reader against settings a test binary cannot produce.
//
// The populated case is the one that matters and the one runVersion can never reach under
// `go test`, which is why vcsStamp takes the slice rather than calling debug.ReadBuildInfo.
func TestVCSStamp(t *testing.T) {
	const commit = "f40a47b715ef8fbd6215b70293210d8b3147d554"

	tests := map[string]struct {
		settings     []debug.BuildSetting
		wantRevision string
		wantModified bool
	}{
		"a clean checkout": {
			settings: []debug.BuildSetting{
				{Key: "-trimpath", Value: "true"},
				{Key: "vcs", Value: "git"},
				{Key: "vcs.revision", Value: commit},
				{Key: "vcs.modified", Value: "false"},
			},
			wantRevision: commit,
		},
		"a dirty tree": {
			settings: []debug.BuildSetting{
				{Key: "vcs.revision", Value: commit},
				{Key: "vcs.modified", Value: "true"},
			},
			wantRevision: commit,
			wantModified: true,
		},
		"no vcs settings, as in a build from an archive": {
			settings: []debug.BuildSetting{{Key: "-trimpath", Value: "true"}},
		},
		"nothing at all": {},
		// Not a value the toolchain emits. It reads as false rather than as a third
		// state, because the flag is a diagnostic and the wire format carries a bool.
		"an unrecognised modified value": {
			settings: []debug.BuildSetting{
				{Key: "vcs.revision", Value: commit},
				{Key: "vcs.modified", Value: "yes"},
			},
			wantRevision: commit,
		},
	}

	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			revision, modified := vcsStamp(test.settings)

			switch {
			case revision != test.wantRevision:
				t.Errorf("revision = %q, want %q", revision, test.wantRevision)

			case modified != test.wantModified:
				t.Errorf("modified = %v, want %v", modified, test.wantModified)
			}
		})
	}
}

// TestVersionIsListedInUsage keeps the help text from going stale. A subcommand a consumer
// cannot discover is one they will not use, and the installer contract in README.md tells
// people to run it.
func TestVersionIsListedInUsage(t *testing.T) {
	var out bytes.Buffer

	usage(&out)

	if !bytes.Contains(out.Bytes(), []byte("adb-broker version")) {
		t.Errorf("usage does not mention the version subcommand:\n%s", out.String())
	}
}
