package broker

import (
	"errors"
	"runtime/debug"
)

// runVersion states this binary's identity and writes exactly one object to stdout.
//
// It is the only subcommand that reads nothing: no device, no audit log, no file. Everything
// it reports was fixed when the binary was linked.
//
// # Why it exists
//
// Two readers need it and neither can use probe.
//
// An installer maintaining the one canonical ~/.local/bin/adb-broker has to decide whether the
// binary already there is older than the one it carries, and refuse to move backwards.
// Comparing digests cannot answer that — a digest mismatch says "different" and never "older"
// — so the installed binary has to be able to say what it is. It may have been put there by a
// different consumer, on a host with no phone attached and no adb server running, which is
// exactly the condition under which probe reports an error object instead of a version.
//
// A human debugging an install needs the same answer for the same reason, and cannot get it
// from the outside: `go version -m` reports vcs.revision, vcs.time, vcs.modified and
// -trimpath, but NOT -ldflags, so the version stamped with -X is unreadable by anything except
// this process.
//
// # Arguments
//
// It takes none, and says so rather than routing through bindFlags. The four operations all
// take flags, so "takes flags only" is the right refusal for a stray positional there; here
// there are no flags to take, and reporting an argument as unexpected because it is not a flag
// would describe a rule this subcommand does not have.
func runVersion(e env, args []string) int {
	if len(args) > 0 {
		return e.failUsage(errors.New("version takes no arguments"))
	}

	// The stamp, plus whatever this build marks itself with. A release build appends
	// nothing; see versionSuffix.
	res := VersionResponse{
		Proto:  proto,
		Status: statusOK,
		Broker: version + versionSuffix,
	}

	if info, ok := debug.ReadBuildInfo(); ok {
		res.Revision, res.Modified = vcsStamp(info.Settings)
	}

	return e.emit(res)
}

// vcsStamp reads the commit and the dirty flag out of a build's settings.
//
// It takes the settings rather than calling debug.ReadBuildInfo itself because the absent case
// is otherwise untestable from inside the package: a binary produced by `go test` carries no
// vcs settings at all, so a test driving runVersion can only ever observe that case and never
// the populated one. Passing the slice in makes both reachable.
//
// The zero return — no commit, not modified — is what a build with no VCS stamp reports, and it
// is not a failure. A binary built from an extracted archive rather than from a checkout has no
// commit to name, and so does every test binary in this package.
func vcsStamp(settings []debug.BuildSetting) (revision string, modified bool) {
	for _, setting := range settings {
		switch setting.Key {
		case "vcs.revision":
			revision = setting.Value

		case "vcs.modified":
			// The toolchain records this as the string "true" or "false" and nothing
			// else. The flag is a diagnostic about the build, not a control anything
			// refuses on, so an unrecognised value reads as false rather than becoming
			// a third state the wire format would have to carry.
			modified = setting.Value == "true"
		}
	}

	return revision, modified
}
