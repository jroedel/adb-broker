module github.com/jroedel/adb-broker

go 1.26

// v0.1.0-rc1 derives the audit log path from $HOME on any host whose uid has no passwd entry
// (LDAP, SSSD, AD, or a container started with an unmapped uid), defeating the documented rule
// that no environment variable can move the audit log. Reproduced against the published
// artifact; see docs/phase3a_security_walkback.md and zarf/repro-passwd-fallback.sh. Use
// v0.1.0-rc2 or later.
//
// Deleting the release and its binaries was not enough on its own. proxy.golang.org is an
// immutable cache and had already fetched the version, so `go install …@v0.1.0-rc1` went on
// working and building the defective source; deleting the tag would not have changed that
// either. This directive is the mechanism that does, and it is honoured from the go.mod of the
// LATEST version — so it only takes effect once a later tag carries it.
//
// Note that there is still no require block, and `make deps-check` keeps it that way: the build
// graph is the standard library and nothing else.
retract v0.1.0-rc1
