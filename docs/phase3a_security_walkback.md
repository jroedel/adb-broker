# Phase 3a — The security walkback, and shipping a consumable binary

**Status as of 2026-08-01. This is the current working plan and it supersedes
`phase-3-verification-plan.md` entirely — see *What this replaces* below.**

Branch `feature/adb-broker-plan`, pushed through `9f59ce0`.

We used to have the pretension to protect the binary in another user account. In the end we have
developed this plan to walk back that design decision to make it more straightforward. We want
this software to be consumed and if it's too hard to get up and running we're failing our
primary objective. Also, the real wins weren't that great.

---

## What this replaces

**`docs/phase-3-verification-plan.md` is superseded in full. Nothing in it is still the plan.**
Read it only as a record of how the build was verified, never as a description of what to do
next. Concretely:

- Its **Stage 2 — Install and the real audit trail** specified the setuid binary, the
  `adb-broker` service account, the `adb-broker-clients` group, root-owned `/var/log/adb-broker`
  and `chattr +a`, all established by `zarf/install.sh` running as root. **That whole apparatus
  was withdrawn on 2026-08-01** and this document is the reason. Do not restore any of it
  without re-reading `ADB_BROKER.md` → **Installation** → *What was withdrawn, and why*.
- Its **Stages 1, 3, 4, 6 and 7** are done — hardware validation, the four confirmed defects,
  the `pr-review` run, the coverage gaps, CI, and the T7/T27 sign-offs. Their outcomes live in
  `phase3_device_findings.md`, `.reviews/phase3/`, and the git history, which are the durable
  records. The plan file adds nothing to them.
- Its **Stage 5 — Wire photos to the broker** is the one live thread it still described, and it
  is now **section D** here, changed by everything below: the consumer downloads a release
  rather than finding a locally built binary.
- Its **Context** section is stale in the way that matters most. "No device test has ever run",
  "the binary has never been installed", "nothing has ever consumed the wire format" — all three
  were true when it was written and none is true now.

---

## The shape of the change

The broker is a standalone binary that any number of consumers invoke. Making it *consumable*
means a consumer can install it without a privileged ritual, which is what the walkback bought,
and then that it can obtain it without the user building Go source — which is what the rest of
this plan is about: **publish tagged releases on GitHub; the consumer downloads a pinned version
and installs it to one canonical path.**

### Decisions already made — do not re-litigate

| Question | Decision |
|---|---|
| Platforms | **Linux only**, `amd64` + `arm64`. Windows does not compile (`syscall.SYS_FCNTL` in `foundation/audit/log.go`). macOS *does* compile, which is worse than not compiling — see below. |
| Install path | **One canonical `~/.local/bin/adb-broker`, shared by every consumer.** Never a per-app private copy. |
| Download verification | **Publish GitHub artifact attestations** *and* **embed the expected SHA-256 in the consumer** — see D for why both. |
| Does the consumer locate or ship `adb`? | **No.** It relies on the OS/user having the adb server running already. |
| Build configuration | `CGO_ENABLED=0`, static and portable, with the `LookupId` fix that makes it fail closed where it cannot resolve the account. |

**Why macOS is excluded rather than "not yet supported".** It compiles and runs, and there is no
journald, so the anchor write fails. That failure is by design non-fatal — reported once on
stderr, never changing an operation's outcome — so every read succeeds while the only remaining
tamper-evidence control is absent, and `verify` then reports `no anchors found` →
`"status":"partial"` → exit `0`, which is the result that reads as a pass. A macOS artifact would
ship a broker whose audit story is silently gone. If macOS is ever wanted it needs a decision on
purpose: a different anchor sink, or an explicit refusal to run where it cannot anchor.

---

## Status

| Step | State |
|---|---|
| **A** — the `$HOME` fallback fix | **Done**, `0733ba6` |
| Consumer-facing `README.md` | **Done**, `231f56e` |
| `foundation/adbwire` test flake | **Fixed**, `9f59ce0` — the gate is trustworthy, which C depends on |
| **B** — version identity | **Not started.** Do this first. |
| **C** — release workflow | Not started; depends on B |
| **D** — consumer install contract | Not started; depends on C |
| **E** — docs | Not started; do with D |

---

## A — the `$HOME` fallback. Done (`0733ba6`)

**The finding.** `auditLogPath` derived the audit log path from `user.Current()`. Under
`CGO_ENABLED=0` — the configuration a portable release artifact is built in — `os/user` compiles
`lookup_stubs.go` (build tag `(!cgo && !darwin && !windows && !plan9) || android || (osusergo &&
…)`), whose `current()` attempts the passwd lookup and, **when it fails**, builds a `User` from
`os.UserHomeDir()` and `$USER` and returns it **with a nil error**.

So a static release binary on a host whose uid is absent from `/etc/passwd` — LDAP, SSSD, AD, or
a container started with `docker run -u 4242` — would have derived the audit log path from
`$HOME` and reported success. That defeats the documented invariant that no environment variable
can move the log, silently. It mattered only because the binary stopped being something its
operator compiled.

**The fix.** `user.LookupId(strconv.Itoa(os.Getuid()))`. No env fallback in either build
configuration — NSS with cgo, `/etc/passwd` without it, an error rather than a guess in both — so
an unresolvable account is now `audit_unavailable`, the direction every other control here fails
in. The uid is the real uid, the same one the record carries as `caller_uid`.

**Why the guard is static, which is the part worth remembering.** Reverting the fix and running
the suite, the *behavioural* test still passed. On a host whose uid resolves, the fallback is
never reached, so no test that calls the derivation can see the bug — and every host that runs CI
is such a host. `TestPackageSourceNeverResolvesTheHomeDirectoryFromTheEnvironment` therefore walks
the package's syntax tree and refuses both `user.Current` and `os.UserHomeDir`. Both arms were
mutation-tested. `make test-nocgo` runs the suite at `CGO_ENABLED=0` and is in the gate and in CI,
because a control with two build modes gets tested in one of them and the shipped one was the
untested one.

**Unfinished business: the finding is source-derived, not reproduced.** A runtime demonstration
needs a host where the invoking uid has no passwd entry; user namespaces were denied in the
sandbox where it was found, so `unshare` and `bwrap` both refused. **Reproduce it before calling
the correction measured** — `docker run -u 4242` on a normal host is the cheapest way. This
caveat is also recorded in `ADB_BROKER.md` → **Where it lives**.

---

## B — version identity. Do this first

Every tagged release would currently report `"broker":"0.1.0"` — in probe responses and in every
audit record it writes. For binaries nobody built themselves, that is the gap to close first.

- Stamp at build time:
  `-ldflags "-X github.com/jroedel/adb-broker/app/broker.version=<tag>"`, plus `-trimpath`.
  The existing `0.1.0` assertions are on struct literals the tests set themselves, not on the
  package var, so stamping breaks nothing.
- Go already embeds the VCS revision automatically — verified: `vcs.revision=95876c30…`,
  `vcs.modified=false`, readable with `go version -m`. Nothing reads it in-process; that reader
  went out with `verify-install`, and `ADB_BROKER.md` §8.2 already flags re-reading it as
  reopened and cheap.
- Keep the fixture build's `+fixture` suffix behaviour intact (`fixturedb.NewStore` appends it;
  adding it twice previously produced `0.1.0+fixture+fixture`).

**Open decision:** does the VCS revision become a new `probe` member — additive, so compatible,
`proto` stays `1` — or stay in the audit record only?

---

## C — release workflow

A **new** workflow file, not an edit to `ci.yml`: the existing gate is `permissions: contents:
read` and should stay that way.

- Trigger on `v*` tags. Run the full `make test` gate first, so nothing is published from a tree
  that fails it. (This is why the flake in `9f59ce0` had to be fixed first — it would have failed
  releases at random.)
- Build `linux/amd64` and `linux/arm64`, `CGO_ENABLED=0`, `-trimpath`, stamped version from B.
- `actions/attest-build-provenance`, which needs `id-token: write` and `attestations: write`,
  plus `contents: write` to publish.
- Publish the two binaries, a `SHA256SUMS`, and the attestation.

---

## D — the consumer-side install contract

**Both verification mechanisms, because they do different jobs.** Attestations are the right
thing to *publish* but a poor fit for what a consumer does at runtime: verifying one means either
shelling out to `gh` (not on an end-user machine) or pulling in `sigstore-go`, and it needs
network access to the transparency log.

- **Publish the attestation** — it makes an artifact independently auditable by anyone, via
  `gh attestation verify <file> --repo jroedel/adb-broker`.
- **Embed the expected SHA-256 for the pinned version in the consumer** — that is what the
  consumer can actually enforce, offline, with nothing but `crypto/sha256`. The digest ships
  *inside* the consumer, never fetched alongside the binary.

If shipping broker releases faster than consumer releases ever becomes the constraint, the
stdlib-only alternative is an Ed25519 (minisign-style) signature with the public key compiled
into the consumer, verified with `crypto/ed25519` — at the cost of managing a signing key in
Actions secrets.

The rest of the contract:

- **Canonical path `~/.local/bin/adb-broker`, shared.** Never a per-app private copy. Anchors
  carry the publishing binary's journald-stamped `_EXE`, and `verify` accepts only anchors
  bearing the running binary's own path, so a second copy splits the trail in two and **nothing
  errors** — `verify` under either path just reports a log longer than that path's anchors claim,
  the one outcome the tool treats as unremarkable. `_EXE` is a path and not a hash, so upgrading
  in place at a stable path keeps one anchor identity across every version.
- **Pin an exact version.** Never float to `latest`; the consumer owns the `proto` check and
  pinning is what makes it mean anything.
- **Atomic install:** download to a temp file in the *same directory*, verify the digest,
  `chmod 0755`, then `rename(2)` into place. Never write the final path directly.
- **Refuse to downgrade**, so two consumers pinning different versions do not flip the binary
  under each other.
- **Run `probe` straight after installing** and surface `no_adb_server` / `unauthorized` with
  instructions. This one carries more weight than it looks: the consumer does **not** ship or
  locate `adb`, so the two host preconditions are entirely the user's to satisfy, and they are
  the ones that cost the most time when wrong — particularly that USB-debugging authorization is
  per *adb-server RSA key*, i.e. per account, and misreads as "USB debugging is off".

---

## E — docs

- `README.md`: an "Install from a release" section plus the consumer install contract.
- `docs/ADB_BROKER.md`: **Installation** currently says build it and put it on `PATH`; the
  release path needs adding, and **Discovery**'s one-path argument gains a second consumer.
- `docs/THREAT_MODEL.md`: a new adversary — **whoever controls the release artifact** — with what
  a digest and an attestation each buy, and explicitly what they do not: neither defends against
  the same-uid adversary overwriting the installed binary afterwards, which §5.5 already accepts.

---

## Findings from this phase worth keeping

**1. The `$HOME` fallback** — above. Source-derived, not yet reproduced.

**2. `foundation/adbwire`'s test peer could not model a closed socket.** Fixed in `9f59ce0`, and
the reasoning generalizes. `net.Pipe` is unbuffered and its `SetDeadline` methods return
`io.ErrClosedPipe` once either end closes; this package arms a deadline before every read,
because the spec requires one on every exchange. So a `net.Pipe` peer that closed raced the
reader's next `SetReadDeadline`. Measured at 7 failures in 300 runs under `-race`, 0 in 300
without it. Splitting the fixture so only the closing tests closed merely *relocated* the
failure — which is what proved there is no ordering in which a closed `net.Pipe` peer is safe
under a mandatory-deadline reader. The peer is now a real loopback socket that writes and closes
synchronously before the reader runs; the kernel holds the bytes and queues the FIN, so no
goroutine and no interleaving remain. Verified over 2,000 iterations under `-race`.

**Rule of thumb this leaves behind:** a fixture whose failure mode no real socket can produce is
a broken fixture, not a flaky test to retry.

---

## Open questions

1. **Reproduce the `$HOME` fallback** on a host with an unresolvable uid before calling A
   verified. (A)
2. **Does the VCS revision become a `probe` member, or stay in the audit record?** (B)
3. **`go fix` proposes one rewrite in `app/broker/wire_test.go`** (`typ.Fields()` over
   `typ.NumField()`), left unapplied — its output includes an awkward `field := field`. It
   belongs in its own commit if wanted.
4. Everything still open in `ADB_BROKER.md` → **Open questions** is unchanged by this phase.

---

## Picking this up cold

- The gate is `make test` and it is trustworthy as of `9f59ce0`; `make test-nocgo` is the
  release configuration and is part of it.
- `AGENTS.md` governs how to work here — mandatory skills for Go and `app/*` edits, and the git
  rules (feature branches only, never merge, never push to main, no `Co-Authored-By` trailer).
- The normative contract is `docs/ADB_BROKER.md`. `README.md` is the consumer-facing guide and
  was written by running the binary rather than transcribing the spec, so where it gives an
  example, that example was observed.
- Next action: **B**, then **C**.
