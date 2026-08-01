#!/usr/bin/env sh
#
# Asserts that the artifacts in dist/ are the ones the release claims to be
# publishing, before anything is published.
#
# usage: check-artifact.sh <version> <commit>
#
# Runnable outside CI, which is the point of it being a file rather than
# fifteen lines inlined twice into release.yml:
#
#   make dist VERSION=1.2.0 && .github/scripts/check-artifact.sh 1.2.0 "$(git rev-parse HEAD)"
#
# Three things are checked, and each one has failed somewhere in this project's
# history or is a documented way for the build to go quietly wrong:
#
#  1. The binary reports the version the tag asked for. The stamp is a linker
#     flag in a Makefile variable; a typo produces a perfectly good binary that
#     lies about what it is, and nothing else in the pipeline would notice.
#     `go version -m` cannot check this — it records the commit but not
#     -ldflags — so the only reader that can is the binary itself.
#
#  2. The tree was clean and is the commit being released. A build made in a
#     linked git worktree carries no revision at all (measured: same commit,
#     "" from a worktree and the real sha from a clone), so an empty revision
#     here means the build did not come from where it was supposed to.
#
#  3. SHA256SUMS actually matches the bytes beside it. It is the file a
#     consumer verifies against, and it is generated, so it should be checked
#     rather than trusted.
#
# Only the amd64 artifact is executed: this runs on an amd64 runner and there
# is no emulator here. The arm64 binary is covered by 3 and by the compile
# itself. Do not "fix" that with qemu — it would test the emulator.
set -eu

version="${1:?usage: check-artifact.sh <version> <commit>}"
commit="${2:?usage: check-artifact.sh <version> <commit>}"

cd "$(dirname "$0")/../.."

chmod +x dist/adb-broker-linux-amd64
got=$(./dist/adb-broker-linux-amd64 version)

echo "version reports: $got"

fail() {
	echo "::error::$1"
	exit 1
}

case "$got" in
*"\"broker\":\"$version\""*) ;;
*) fail "the binary reports a broker version that is not \"$version\": $got" ;;
esac

case "$got" in
*'"modified":false'*) ;;
*) fail "the binary was built from a modified tree; a release must come from a clean checkout" ;;
esac

case "$got" in
*"\"revision\":\"$commit\""*) ;;
*) fail "the binary reports a revision that is not $commit; it was not built from this commit" ;;
esac

cd dist && sha256sum -c SHA256SUMS

echo "artifacts check out: $version at $commit"
