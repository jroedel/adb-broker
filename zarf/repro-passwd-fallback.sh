#!/usr/bin/env bash
#
# Reproduces the $HOME fallback at runtime, and demonstrates that the current code refuses it.
#
# usage: zarf/repro-passwd-fallback.sh [path-to-binary-under-test]
#
# The finding: on a host whose uid has no passwd entry — LDAP, SSSD, AD, or a container started
# with an unmapped uid — a CGO_ENABLED=0 build of this binary derived its audit log path from
# $HOME and reported success, defeating the documented rule that no environment variable can
# move the log. It was found by reading os/user's source and went unreproduced for months,
# during which a correction was written that did not correct it. Hence this script.
#
# # Why it needs a harness at all
#
# The fallback is unreachable on any host whose uid resolves, and every development machine and
# CI runner is such a host. Something has to make the lookup fail.
#
# The obvious routes do not work in a restricted environment, and it is worth recording why so
# the next person does not spend the time again:
#
#   - `unshare -U` SUCCEEDS, but writing /proc/self/uid_map then fails with EPERM. On Ubuntu
#     24.04, kernel.apparmor_restrict_unprivileged_userns=1 hands back a namespace with no
#     CAP_SETUID, so nothing can be mapped. bwrap fails at the same step. The plan file recorded
#     this as "user namespaces were denied", which is the right conclusion and the wrong reason.
#   - Docker needs membership of the docker group, which is equivalent to root.
#
# What works needs no privilege: proot, which uses ptrace, binding a copy of /etc/passwd with
# the invoking uid's line removed. Nothing about the process is faked — the uid is genuinely the
# real one, and the kernel is told nothing untrue. The process simply reads a passwd file that
# does not list it, which is precisely what a directory-backed host looks like to a static
# binary, since a CGO_ENABLED=0 build cannot consult NSS at all.
#
# # What it asserts
#
# Three runs, and the middle one is the finding:
#
#   1. Control, normal /etc/passwd, $HOME redirected  -> nothing written under $HOME.
#   2. Unresolvable uid, $HOME redirected             -> MUST refuse with audit_unavailable.
#   3. The same as 2 against a binary built before the fix, for contrast, if one is supplied.
#
# Measured 2026-08-01: the published v0.1.0-rc1 artifact FAILS check 2 — it creates
# $HOME/.local/state/adb-broker/audit.log and carries on.
set -euo pipefail

cd "$(dirname "$0")/.."

work="${TMPDIR:-/tmp}/adb-broker-repro.$$"
mkdir -p "$work"
trap 'rm -rf "$work"' EXIT

bin="${1:-}"
if [ -z "$bin" ]; then
	echo "building the binary under test in the release configuration"
	make --no-print-directory build-release VERSION=0.0.0-repro OUT="$work/adb-broker" >/dev/null
	bin="$work/adb-broker"
fi
bin=$(readlink -f "$bin")

# proot, without installing it. Downloading the .deb and unpacking it needs no privilege, and
# keeps this script from depending on what happens to be installed.
if command -v proot >/dev/null; then
	proot=$(command -v proot)
else
	echo "fetching proot"
	(cd "$work" && apt-get download proot >/dev/null 2>&1)
	dpkg-deb -x "$work"/proot_*.deb "$work/proot-root"
	proot="$work/proot-root/usr/bin/proot"
fi

uid=$(id -u)
grep -v ":x:${uid}:" /etc/passwd > "$work/passwd-without-us"

if [ "$(wc -l < "$work/passwd-without-us")" -eq "$(wc -l < /etc/passwd)" ]; then
	echo "uid $uid is not in /etc/passwd to begin with; this host cannot show the contrast" >&2
	exit 1
fi

fail=0

# 1. Control. A redirected $HOME must change nothing, because the passwd entry still resolves.
control="$work/home-control"
mkdir -p "$control"
HOME="$control" "$bin" probe >/dev/null 2>&1 || true

if [ "$(find "$control" -type f | wc -l)" -ne 0 ]; then
	echo "FAIL control: \$HOME moved the audit log on a host where the uid resolves"
	fail=1
else
	echo "ok   control: \$HOME ignored, nothing written under it"
fi

# 2. The finding. The uid is real; the passwd file it reads has no line for it.
subject="$work/home-subject"
mkdir -p "$subject"
out=$(HOME="$subject" "$proot" -b "$work/passwd-without-us:/etc/passwd" "$bin" probe 2>&1 || true)
written=$(find "$subject" -type f | wc -l)

echo "     unresolvable uid says: $(printf '%s' "$out" | tail -1)"

case "$out:$written" in
*audit_unavailable*:0)
	echo "ok   unresolvable uid: refused with audit_unavailable, nothing written under \$HOME"
	;;
*)
	echo "FAIL unresolvable uid: wrote $written file(s) under \$HOME instead of refusing"
	find "$subject" -type f
	fail=1
	;;
esac

exit "$fail"
