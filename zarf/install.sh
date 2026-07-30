#!/usr/bin/env bash
#
# Install and verify adb-broker's audit identity.
#
# The audit log's protection is two controls that fail independently:
#
#   consumer (uid A) --exec--> broker (uid B) --append--> audit.log (owned B, +a)
#
#   * A compromised consumer cannot open the log for writing at all — wrong owner.
#   * A compromised broker can only append — chattr +a, and clearing that needs
#     CAP_LINUX_IMMUTABLE, which the broker does not have.
#   * Neither can unlink it, because the parent directory is root:root.
#
# None of that is establishable by the broker itself: a process that can create
# its own audit log can also recreate it. So this runs as root, at install time,
# and verifies each property afterwards rather than assuming the commands worked.
#
# Re-running is safe. Nothing here can truncate or remove an existing log.
#
# Usage:
#   zarf/install.sh [--client USER|UID]... [--binary PATH] [--verify-only]
#
set -euo pipefail

readonly BROKER_USER="adb-broker"
readonly BROKER_GROUP="adb-broker"
readonly CLIENT_GROUP="adb-broker-clients"
readonly LOG_DIR="/var/log/adb-broker"
readonly LOG_FILE="${LOG_DIR}/audit.log"
readonly BIN_DIR="/usr/local/bin"
readonly BINARY_NAME="adb-broker"

# The setuid bit is what makes uid B happen at all: a 0755 binary exec'd by a
# consumer runs as the *consumer's* uid, which cannot open a log owned by B, and
# the two-control property would silently collapse to chattr +a alone.
#
# 4550, not 4750. setuid takes the uid from the file's *owner*, so the binary must
# be owned by the broker — and any owner-write bit would then let the broker
# replace its own setuid binary while keeping the uid. Root performs installs, so
# the owner never needs write. Group is the client group, whose r-x is what lets
# permitted consumers exec it and nobody else.
readonly BINARY_MODE="4550"

SCRIPT_PATH="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)/$(basename -- "${BASH_SOURCE[0]}")"
readonly SCRIPT_PATH
REPO_ROOT="$(cd -- "$(dirname -- "${SCRIPT_PATH}")/.." && pwd)"
readonly REPO_ROOT

VERIFY_ONLY=false
BINARY_SRC="${REPO_ROOT}/bin/${BINARY_NAME}"
CLIENTS=()

failures=0
replica_dir=""

usage() {
	cat <<EOF
Install and verify adb-broker's audit identity.

  --client USER|UID   Grant this uid permission to exec the broker, by adding it
                      to ${CLIENT_GROUP}. Repeatable. Each consumer of the
                      broker needs one, including a developer running it by hand.
  --binary PATH       Broker binary to install (default: ${BINARY_SRC}).
                      Skipped with a note if it does not exist yet.
  --verify-only       Change nothing; only check and report. This is the body of
                      \`make verify-install\` and is worth running from monitoring.
  -h, --help          This text.

Escalates with sudo if not already root.
EOF
}

note() { printf '  %s\n' "$*"; }
step() { printf '\n%s\n' "$*"; }
pass() { printf '  ok      %s\n' "$*"; }
fail() {
	printf '  FAILED  %s\n' "$*"
	failures=$((failures + 1))
}
die() {
	printf 'error: %s\n' "$*" >&2
	exit 1
}

# ---------------------------------------------------------------------------
# Argument parsing and escalation
# ---------------------------------------------------------------------------

for arg in "$@"; do
	case "${arg}" in
	-h | --help)
		usage
		exit 0
		;;
	esac
done

if [[ ${EUID} -ne 0 ]]; then
	command -v sudo >/dev/null 2>&1 || die "not running as root and sudo is not installed"
	printf 'Not root — re-running under sudo.\n' >&2
	exec sudo -- "${SCRIPT_PATH}" "$@"
fi

while [[ $# -gt 0 ]]; do
	case "$1" in
	--client)
		[[ $# -ge 2 ]] || die "--client needs a user name or uid"
		CLIENTS+=("$2")
		shift 2
		;;
	--binary)
		[[ $# -ge 2 ]] || die "--binary needs a path"
		BINARY_SRC="$2"
		shift 2
		;;
	--verify-only)
		VERIFY_ONLY=true
		shift
		;;
	*)
		die "unknown argument: $1 (try --help)"
		;;
	esac
done

# Run a command as the broker uid. Its shell is nologin, so both forms below
# invoke the command directly rather than through a login shell.
as_broker() {
	if command -v runuser >/dev/null 2>&1; then
		runuser -u "${BROKER_USER}" -- "$@"
	else
		sudo -u "${BROKER_USER}" -- "$@"
	fi
}

# A check whose PASS condition is that the command is refused. Stderr is captured
# so an expected refusal doesn't print alarming noise in a clean run — and is
# then inspected, so a failure for some *other* reason does not silently count as
# a pass. A check that cannot fail is worse than no check at all.
expect_refusal() {
	local what="$1"
	shift

	local out status
	out="$(as_broker "$@" 2>&1)" && status=0 || status=$?

	if [[ ${status} -eq 0 ]]; then
		fail "${what} was PERMITTED"
		return
	fi

	case "${out}" in
	*"not permitted"* | *"Permission denied"* | *"Read-only file system"*)
		pass "${what} is refused"
		;;
	*)
		fail "${what} failed, but not with a permission error: ${out}"
		;;
	esac
}

cleanup() {
	if [[ -n ${replica_dir} && -d ${replica_dir} ]]; then
		chattr -a "${replica_dir}/audit.log" 2>/dev/null || true
		rm -rf -- "${replica_dir}"
	fi
}
trap cleanup EXIT

# ---------------------------------------------------------------------------
# Install
# ---------------------------------------------------------------------------

install_account() {
	step "Service account"

	if getent passwd "${BROKER_USER}" >/dev/null; then
		note "${BROKER_USER} already exists, leaving it alone"
	else
		useradd --system --user-group \
			--no-create-home --home-dir /nonexistent \
			--shell /usr/sbin/nologin \
			--comment 'adb broker audit identity' \
			"${BROKER_USER}"
		note "created ${BROKER_USER} (system uid, own group, nologin, no home)"
	fi

	if getent group "${CLIENT_GROUP}" >/dev/null; then
		note "${CLIENT_GROUP} already exists"
	else
		groupadd --system "${CLIENT_GROUP}"
		note "created ${CLIENT_GROUP}"
	fi

	# Deduplicated by resolved name, since a uid and a user name for the same
	# account are the same grant and reporting it twice reads as a mistake.
	local client name seen=" "
	for client in "${CLIENTS[@]:-}"; do
		[[ -n ${client} ]] || continue
		name="$(getent passwd "${client}" | cut -d: -f1)" ||
			die "no such user: ${client}"
		[[ -n ${name} ]] || die "no such user: ${client}"
		[[ ${name} != "${BROKER_USER}" ]] ||
			die "refusing to add ${BROKER_USER} to ${CLIENT_GROUP}: it must not be able to exec itself as a client"
		[[ ${seen} != *" ${name} "* ]] || continue
		seen+="${name} "
		usermod -aG "${CLIENT_GROUP}" "${name}"
		note "added ${name} to ${CLIENT_GROUP}"
	done
}

install_log() {
	step "Audit log"

	# Root-owned directory: the broker can append to the file inside it but can
	# never unlink or replace it.
	install -d -o root -g root -m 0755 "${LOG_DIR}"
	note "${LOG_DIR} is root:root 0755"

	if [[ -e ${LOG_FILE} ]]; then
		note "${LOG_FILE} already exists, leaving its contents untouched"
	else
		install -o "${BROKER_USER}" -g "${BROKER_GROUP}" -m 0640 \
			/dev/null "${LOG_FILE}"
		note "created ${LOG_FILE} owned by ${BROKER_USER}, mode 0640"
	fi

	# Idempotent: setting +a on a file that already has it is a no-op.
	chattr +a "${LOG_FILE}" ||
		die "chattr +a failed on ${LOG_FILE} — does $(findmnt -no FSTYPE --target "${LOG_DIR}") support the append-only attribute?"
	note "append-only attribute set"
}

install_binary() {
	step "Binary"

	if [[ ! -e ${BINARY_SRC} ]]; then
		note "${BINARY_SRC} does not exist yet — skipping."
		note "Build it and re-run, or run with --binary PATH."
		return 0
	fi

	install -o "${BROKER_USER}" -g "${CLIENT_GROUP}" -m "${BINARY_MODE}" \
		"${BINARY_SRC}" "${BIN_DIR}/${BINARY_NAME}"

	# Some install builds drop the setuid bit when copying, so set it explicitly
	# rather than trusting -m to have carried it.
	chmod "${BINARY_MODE}" "${BIN_DIR}/${BINARY_NAME}"
	note "installed ${BIN_DIR}/${BINARY_NAME} as ${BROKER_USER}:${CLIENT_GROUP} ${BINARY_MODE}"
}

# ---------------------------------------------------------------------------
# Verify
#
# Everything here is non-destructive. The real audit log is only inspected and
# opened append-only; the tests that would destroy a misconfigured log run
# against a throwaway replica on the same filesystem instead.
# ---------------------------------------------------------------------------

verify_account() {
	step "Verifying service account"

	local shell home uid
	if ! getent passwd "${BROKER_USER}" >/dev/null; then
		fail "${BROKER_USER} does not exist"
		return
	fi
	pass "${BROKER_USER} exists"

	uid="$(id -u "${BROKER_USER}")"
	shell="$(getent passwd "${BROKER_USER}" | cut -d: -f7)"
	home="$(getent passwd "${BROKER_USER}" | cut -d: -f6)"

	case "${shell}" in
	*/nologin | */false) pass "login shell is ${shell}" ;;
	*) fail "login shell is ${shell}, expected nologin" ;;
	esac

	if [[ -d ${home} ]]; then
		fail "home directory ${home} exists"
	else
		pass "no home directory (${home})"
	fi

	# The broker must not be able to exec itself as a permitted caller.
	if id -nG "${BROKER_USER}" | tr ' ' '\n' | grep -qx "${CLIENT_GROUP}"; then
		fail "${BROKER_USER} is a member of ${CLIENT_GROUP}"
	else
		pass "${BROKER_USER} is not a member of ${CLIENT_GROUP}"
	fi

	if ! getent group "${CLIENT_GROUP}" >/dev/null; then
		fail "${CLIENT_GROUP} does not exist"
		return
	fi
	pass "${CLIENT_GROUP} exists"

	# This is the property the second control rests on, and the one most likely
	# to be quietly undone by a later packaging change.
	local members member member_uid
	members="$(getent group "${CLIENT_GROUP}" | cut -d: -f4 | tr ',' ' ')"
	if [[ -z ${members// /} ]]; then
		note "warn    ${CLIENT_GROUP} has no members — nothing can exec the broker yet"
	fi
	for member in ${members}; do
		member_uid="$(id -u "${member}" 2>/dev/null || echo "")"
		if [[ -z ${member_uid} ]]; then
			fail "${CLIENT_GROUP} member '${member}' does not resolve to a uid"
		elif [[ ${member_uid} == "${uid}" ]]; then
			fail "${CLIENT_GROUP} member ${member} shares the broker's uid ${uid}"
		else
			pass "caller ${member} (uid ${member_uid}) differs from broker uid ${uid}"
		fi
	done
}

verify_log() {
	step "Verifying audit log"

	local got
	if [[ ! -d ${LOG_DIR} ]]; then
		fail "${LOG_DIR} does not exist"
		return
	fi
	got="$(stat -c '%U:%G %a' "${LOG_DIR}")"
	if [[ ${got} == "root:root 755" ]]; then
		pass "${LOG_DIR} is root:root 0755"
	else
		fail "${LOG_DIR} is ${got}, expected root:root 755"
	fi

	if [[ ! -f ${LOG_FILE} ]]; then
		fail "${LOG_FILE} does not exist"
		return
	fi
	got="$(stat -c '%U:%G %a' "${LOG_FILE}")"
	if [[ ${got} == "${BROKER_USER}:${BROKER_GROUP} 640" ]]; then
		pass "${LOG_FILE} is ${BROKER_USER}:${BROKER_GROUP} 0640"
	else
		fail "${LOG_FILE} is ${got}, expected ${BROKER_USER}:${BROKER_GROUP} 640"
	fi

	got="$(lsattr -- "${LOG_FILE}" | awk '{print $1}')"
	case "${got}" in
	*a*) pass "append-only attribute is set (${got})" ;;
	*) fail "append-only attribute is NOT set (${got})" ;;
	esac

	# Non-destructive: opens the file O_APPEND and writes zero bytes. A stray
	# byte here would poison the hash chain before record 1, and +a means it
	# could never be removed.
	if as_broker sh -c ": >> '${LOG_FILE}'"; then
		pass "${BROKER_USER} can open the log for append"
	else
		fail "${BROKER_USER} cannot open the log for append"
	fi

	# The broker must not be able to create or unlink entries in the directory,
	# which is what would let it replace the log wholesale. Checking the
	# directory's writability proves this without attempting a deletion.
	if as_broker sh -c "test -w '${LOG_DIR}'"; then
		fail "${BROKER_USER} can write to ${LOG_DIR} — it could unlink the log"
	else
		pass "${BROKER_USER} cannot write to ${LOG_DIR}"
	fi
}

# Prove the kernel actually enforces +a on this filesystem, using a replica
# rather than the real log. Doing this against the real log would truncate it
# precisely when the attribute is missing — i.e. exactly when the check matters.
verify_append_only_is_enforced() {
	step "Verifying the append-only attribute is enforced (on a replica)"

	replica_dir="$(mktemp -d -p "$(dirname -- "${LOG_DIR}")" adb-broker-verify.XXXXXX)"
	chown root:root "${replica_dir}"
	chmod 0755 "${replica_dir}"

	local replica="${replica_dir}/audit.log"
	install -o "${BROKER_USER}" -g "${BROKER_GROUP}" -m 0640 /dev/null "${replica}"
	if ! chattr +a "${replica}"; then
		fail "cannot set +a on a file beside ${LOG_DIR} — filesystem may not support it"
		return
	fi

	expect_refusal "truncation of a +a file by its owner" sh -c ": > '${replica}'"

	if as_broker sh -c "printf 'x' >> '${replica}'"; then
		pass "append is permitted on a +a file"
	else
		fail "append is refused on a +a file"
	fi

	expect_refusal "unlink from a root-owned directory" rm -f "${replica}"
}

verify_binary() {
	step "Verifying binary"

	local target="${BIN_DIR}/${BINARY_NAME}"
	if [[ ! -e ${target} ]]; then
		note "warn    ${target} is not installed yet"
		return
	fi

	local got
	got="$(stat -c '%U:%G %a' "${target}")"
	if [[ ${got} == "${BROKER_USER}:${CLIENT_GROUP} ${BINARY_MODE}" ]]; then
		pass "${target} is ${got}"
	else
		fail "${target} is ${got}, expected ${BROKER_USER}:${CLIENT_GROUP} ${BINARY_MODE}"
	fi

	if [[ -u ${target} ]]; then
		pass "setuid bit is set, so the broker runs as ${BROKER_USER}"
	else
		fail "setuid bit is NOT set — the broker would run as its caller's uid"
	fi

	# A setuid binary its own uid can rewrite is not a boundary: the broker could
	# replace itself with anything and keep the uid.
	if as_broker sh -c "test -w '${target}'"; then
		fail "${BROKER_USER} can write to its own setuid binary"
	else
		pass "${BROKER_USER} cannot write to its own setuid binary"
	fi
}

# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

if [[ ${VERIFY_ONLY} == false ]]; then
	install_account
	install_log
	install_binary
fi

verify_account
verify_log
verify_append_only_is_enforced
verify_binary

step "Summary"
if [[ ${failures} -eq 0 ]]; then
	note "all checks passed"
	if [[ ${VERIFY_ONLY} == false ]]; then
		note "a consumer already running will not pick up ${CLIENT_GROUP} until it restarts"
	fi
	exit 0
fi

note "${failures} check(s) failed"
exit 1
