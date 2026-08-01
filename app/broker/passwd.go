package broker

import (
	"bufio"
	"fmt"
	"os"
	"strconv"
	"strings"
)

// This file resolves a uid's home directory by reading the passwd database directly, because
// os/user cannot be trusted to do it in the configuration this binary ships in.
//
// # Why not os/user
//
// Under CGO_ENABLED=0 — the configuration a portable release artifact is built in — os/user
// compiles lookup_stubs.go, whose current() attempts the passwd lookup and, WHEN IT FAILS,
// builds a User from os.UserHomeDir() and $USER and returns it with a nil error. That much was
// known, and this package stopped calling user.Current because of it.
//
// What was missed is that user.LookupId is not a way around it:
//
//	func LookupId(uid string) (*User, error) {
//		if u, err := Current(); err == nil && u.Uid == uid {
//			return u, err        // <-- the fast path
//		}
//		return lookupUserId(uid)
//	}
//
// The derivation always asks for the CURRENT uid, so the fast path always fires, and LookupId
// inherits Current's $HOME fallback in full. The correction made on 2026-08-01 changed which
// function was called and not what happened. Measured 2026-08-01 against the published
// v0.1.0-rc1 artifact: running as a uid absent from the passwd file it reads, with $HOME
// pointing elsewhere, it created and used an audit log under $HOME. See
// docs/phase3a_security_walkback.md.
//
// # Why reading the file is the right answer rather than a workaround
//
// A CGO_ENABLED=0 binary cannot consult NSS at all. It has no way to reach LDAP, SSSD or AD —
// os/user's own pure-Go path reads /etc/passwd and nothing else. So for the binary that ships,
// this file IS the passwd database, and reading it directly is exactly what os/user would do
// minus the poisoned shortcut.
//
// Doing it in both build configurations rather than only the one that needs it is deliberate.
// It means a cgo build resolves the account the same way the release does, so the behaviour
// under test is the behaviour that ships — the same argument that put make test-nocgo in the
// gate. The cost is real and accepted: a cgo build on a host where the invoking account lives
// only in LDAP now refuses, where getpwuid_r would have answered. That account is refused by
// the release binary regardless, and audit_unavailable is the direction every control here
// fails in.
//
// The parsing rules below mirror os/user's matchUserIndexValue so that this agrees with the
// standard library on every line either of them would accept.

// passwdFile is the passwd database. It is a var solely so tests can point the derivation at a
// fixture: the fallback this file exists to prevent is unreachable on any host whose uid
// resolves, which is every host that runs the suite, so without a seam the failure could only
// ever be asserted statically. That was the previous state of affairs and it is what let a
// correction that changed nothing pass for four months.
//
// It is unexported, so nothing outside this package — and nothing at runtime — can move it. No
// flag, environment variable or configuration file reaches it.
var passwdFile = "/etc/passwd"

// homeDirForUID returns the home directory recorded for uid in the passwd database.
//
// A uid with no entry is an error, never a guess. That is the whole point: the environment is
// not consulted, so there is nothing for $HOME to influence.
func homeDirForUID(uid int) (string, error) {
	want := strconv.Itoa(uid)

	f, err := os.Open(passwdFile)
	if err != nil {
		return "", fmt.Errorf("open %s: %w", passwdFile, err)
	}
	defer func() { _ = f.Close() }()

	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		home, ok := homeDirFromPasswdLine(scanner.Text(), want)
		if ok {
			return home, nil
		}
	}

	if err := scanner.Err(); err != nil {
		return "", fmt.Errorf("read %s: %w", passwdFile, err)
	}

	return "", fmt.Errorf("uid %s has no entry in %s", want, passwdFile)
}

// homeDirFromPasswdLine reports the home directory on line if it describes uid, following
// os/user's own acceptance rules so the two cannot disagree about which lines count:
//
//	kevin:x:1005:1006::/home/kevin:/usr/bin/zsh
//	  0   1   2    3   4     5            6
//
// A line is skipped when it has too few fields, when its name is empty or begins with '+' or
// '-' (the NIS/compat forms, which are directives rather than accounts), or when either id is
// not a number.
func homeDirFromPasswdLine(line, uid string) (string, bool) {
	// Comments and blanks. os/user skips these via the field checks below; doing it up
	// front costs nothing and says so.
	if line == "" || strings.HasPrefix(line, "#") {
		return "", false
	}

	parts := strings.SplitN(line, ":", 7)

	switch {
	case len(parts) < 6:
		return "", false

	case parts[0] == "", parts[0][0] == '+', parts[0][0] == '-':
		return "", false

	case parts[2] != uid:
		return "", false
	}

	// Both ids must be numeric, matching os/user. A line whose gid is junk is a malformed
	// entry, and honouring its home directory would mean trusting a line the standard
	// library would have discarded.
	if _, err := strconv.Atoi(parts[2]); err != nil {
		return "", false
	}
	if _, err := strconv.Atoi(parts[3]); err != nil {
		return "", false
	}

	return parts[5], true
}
