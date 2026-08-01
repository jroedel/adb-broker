# Phase 3a — The security walkback, and shipping a consumable binary

**Status as of 2026-08-01. This is the current working plan and it supersedes
`phase-3-verification-plan.md` entirely — see *What this replaces* below.**

Merged to `main` through `06c7ed2`. Current release `v0.1.0-rc3`.

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
  `DEVICE_FINDINGS.md`, `.reviews/phase3/`, and the git history, which are the durable
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
| Build configuration | `CGO_ENABLED=0`, static and portable. The account is resolved by reading the passwd database directly (`app/broker/passwd.go`), which fails closed where it cannot resolve one — see A, and note that the `os/user` route recorded here previously did not. |

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
| **A** — the `$HOME` fallback fix | **Done properly on 2026-08-01.** `0733ba6` did not fix it — see below. Now reproduced, refixed, and covered behaviourally |
| Consumer-facing `README.md` | **Done**, `231f56e` |
| `foundation/adbwire` test flake | **Fixed**, `9f59ce0` — the gate is trustworthy, which C depends on |
| **B** — version identity | **Done**, `7db15f7` |
| **C** — release workflow | **Done**, `2eeb8e2`. Rehearsed locally, then run for real on three tags; the dry run, the ancestry guard, the artifact check, the attestation and `gh release create` have all executed |
| **D** — consumer install contract | **Specified**, `ADB_BROKER.md` → *The consumer install contract*. Not implemented — the consumer is a separate repository, deliberately out of scope here |
| **E** — docs | **Done** — `README.md`, `ADB_BROKER.md`, `THREAT_MODEL.md` |

**Phase 3a is complete.** `v0.1.0-rc3` is the current release; see *Releases*. What is left is
listed under **What is not done** below — none of it is phase 3a work.

---

## A — the `$HOME` fallback. Reproduced and actually fixed, 2026-08-01

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

**The first fix, `0733ba6`, did not work.** It replaced `user.Current()` with
`user.LookupId(strconv.Itoa(os.Getuid()))`, on the stated grounds that `LookupId` "has no env
fallback in either build configuration". That sentence was the whole argument, it was in the
code comment, in the guard test's comment, in `ADB_BROKER.md` and in this file — and it is false:

```go
func LookupId(uid string) (*User, error) {
	if u, err := Current(); err == nil && u.Uid == uid { return u, err }
	return lookupUserId(uid)
}
```

The derivation asks for the *current* uid by construction, so the fast path always fires and
`LookupId` returns precisely what `Current` would have returned, `$HOME` fallback included. The
correction changed which function was called and not what happened.

**Reproduced 2026-08-01, against the published `v0.1.0-rc1` artifact.**

| Run | Result |
|---|---|
| Control — normal `/etc/passwd`, `$HOME` redirected | nothing written under `$HOME` |
| uid absent from the passwd file, `$HOME` redirected | `$HOME/.local/state/adb-broker/audit.log`, created, chained, with a real `probe` record |

So the documented invariant — *no environment variable can move the log* — was false for the
shipped binary, on exactly the hosts the original finding named, four months after it was
supposedly fixed.

**How, since this file said it could not be done.** It said "user namespaces were denied … so
`unshare` and `bwrap` both refused." Half right. `unshare -U` **succeeds**; the `uid_map` write
fails, because `kernel.apparmor_restrict_unprivileged_userns=1` hands back a namespace with no
`CAP_SETUID`. Docker needs the `docker` group, which is root-equivalent. What works needs no
privilege at all: `apt-get download proot`, unpack the `.deb` in place, and bind a copy of
`/etc/passwd` with the invoking uid's line removed. The uid stays genuinely real; the process
just reads a passwd file that does not list it — which is exactly what a directory-backed host
looks like to a static binary, since `CGO_ENABLED=0` cannot consult NSS at all. Committed as
`zarf/repro-passwd-fallback.sh`; it passes against the current tree and fails against
`v0.1.0-rc1`.

**The real fix.** `app/broker/passwd.go` reads the passwd database itself, mirroring `os/user`'s
own line-acceptance rules, with no shortcut to poison. `os/user` is not used at all. Both build
configurations behave identically, so the behaviour under test is the behaviour that ships — at
the accepted cost that a cgo build no longer resolves an account existing only in LDAP/SSSD/AD,
which the release binary cannot resolve either.

**Why the guard was static, and why that was the actual defect.** The old note here explained
that the fallback is unreachable on a host whose uid resolves, so no behavioural test could see
it, so the rule had to be enforced by walking the AST for `user.Current` and `os.UserHomeDir`.
That reasoning was correct and its conclusion was the trap: a guard that names the *safe members
of an unsafe package* has to stay ahead of every path through that package, and it did not —
`LookupId` was on the allowed side of the list and carried the bug. The guard now refuses the
`os/user` **import**. And because `passwd.go` takes its database path from a seam,
`TestAuditLogPathRefusesAUidWithNoPasswdEntry` asserts the failing case *behaviourally*, on any
host: it points the derivation at a fixture that omits the running uid and requires an error.
Mutation-tested by restoring `user.LookupId` — both guards fire.

**Rule of thumb this leaves behind:** when a control can only be enforced by spelling, the
spelling is load bearing and nobody checks it. Restructure until the thing can be tested, then
test it. "This cannot be tested behaviourally" is a statement about the current design, not
about the world.

---

## B — version identity. Done (`7db15f7`)

Every tagged release would have reported `"broker":"0.1.0"`. Stamping alone did not close that,
and two things found while doing it changed the shape of the step.

**The premise was wrong in one place.** This section used to say the version appeared "in probe
responses and in every audit record it writes". It has never been in an audit record.
`audit.Record` has fourteen fields and none is a version; `deviceaudit.append` never sets one.
Three comments in the tree said otherwise and are corrected. This matters beyond tidiness: it
made the audit record look like a cheap home for the VCS revision, and it is the one place the
revision cannot go — a new field changes the canonical form the hash chain is computed over, and
`decodeLine` rejects unknown members, so binaries either side of the change stop verifying each
other's logs.

**A stamp nobody can read is not identity.** `go version -m` records `vcs.revision`, `vcs.time`,
`vcs.modified` and `-trimpath` — measured — but **not** `-ldflags`. So the value passed to `-X`
is invisible to every reader except the process itself, and the only in-process reader was
`probe`, which needs a device. D's *refuse to downgrade* rule is unimplementable on that
footing: an installer cannot ask what is already at the canonical path, and digests answer
"different", never "older".

What shipped:

- **The stamp**, `-X …/app/broker.version=<version>` with `-trimpath`, driven by `VERSION` in
  the Makefile. The tag's leading `v` is stripped there, because `broker` has always been a bare
  semver on the wire.
- **`make build-release`**, the one definition of how a shipped binary is built — `CGO_ENABLED=0`,
  `-trimpath`, stamped, per `RELEASE_GOARCH`, to `OUT`. C calls this rather than restating it in
  YAML.
- **The unstamped default moved from `0.1.0` to `0.0.0+dev`**, so a hand-built binary cannot
  present itself as the release carrying that number.
- **An `adb-broker version` subcommand**, answered next to `help` — before the fail-closed check,
  not exempt from it — writing `{"proto":1,"status":"ok","broker":…,"revision":…,"modified":…}`.
  No log, no device, no flags. `ProbeResponse` is byte-identical and `proto` stays `1`.
- **`fixturedb.VersionSuffix` is exported**, for one caller. `version` builds no Store, so
  nothing appends `+fixture` for it the way `Probe` does. One constant, two readers, no path
  where both fire — the `0.1.0+fixture+fixture` bug stays fixed.

**Open decision, closed:** the VCS revision is reported by `version` and nowhere else. Not a
`probe` member — every consumer would parse a value none of them acts on — and not the audit
record, for the reason above.

**A build in a linked `git worktree` carries no revision.** Measured: the same commit reports
`7db15f76…` built from a clone and `""` built from `git worktree add --detach`. A worktree's
`.git` is a file rather than a directory and the toolchain's stamping does not follow it.
Harmless for C, since `actions/checkout` clones — but do not read an empty `revision` from a
worktree build as a defect.

---

## C — release workflow

`.github/workflows/release.yml`, a **new** file rather than an edit to `ci.yml`: that one is
`permissions: contents: read` at the top of the file and stays that way. The new file grants
nothing at the top either — each job asks for what it needs, so the job running the test suite
cannot write a release.

- Triggers on `v*` tags, and on `workflow_dispatch` for a dry run.
- The gate is the full `make test`, **including `vuln-check`**, which `ci.yml` deliberately
  leaves out of its required set. Not a contradiction: that argument is about not blocking
  merges on a moving target, and publishing an artifact is exactly when a live advisory should
  stop the run. (This is also why the flake in `9f59ce0` had to be fixed first — it would have
  failed releases at random.)
- **`make dist` is where a release is defined**, not the YAML: both architectures,
  `CGO_ENABLED=0`, `-trimpath`, the stamp, and the `SHA256SUMS` over them. So a rehearsal on a
  laptop produces the same set of artifacts a tag does, and there is one place to edit when that
  set changes.
- `actions/attest-build-provenance@v4` (`id-token: write`, `attestations: write`), then
  `gh release create` with `contents: write`. `gh` rather than a third-party action: this
  module's build graph is stdlib-only and the same instinct applies to the pipeline. A tag
  carrying a pre-release identifier publishes as a pre-release.

Three guards, because there are no tags in this repository yet and a first release is the worst
possible place to discover a mistake in the thing that makes releases:

1. **The dry run.** `workflow_dispatch` builds, checksums and checks exactly what a tag would,
   publishes nothing, and leaves the artifacts on the run. Run it before cutting a tag.
2. **A tag must descend from `main`**, or the run fails before anything is built. A tag on a
   feature branch would ship code that never went through a pull request.
3. **`.github/scripts/check-artifact.sh`** runs the built binary and refuses to publish unless
   it reports the tag's version, the commit being released, and a clean tree. This is the one
   with teeth. The stamp is a linker flag in a Makefile variable: a typo produces a perfectly
   good binary that lies about what it is, nothing else in the pipeline would notice, and
   `go version -m` cannot catch it — it records the commit but never `-ldflags`. The only reader
   that can is the binary itself, which is what B built.

### Releases

| Tag | Status |
|---|---|
| `v0.1.0-rc1` | **Withdrawn. Do not use.** Derives the audit log path from `$HOME` where the uid has no passwd entry — see A |
| `v0.1.0-rc2` | Verified good, and superseded only because rc3 carries the retraction. `8e80245`, checked from the published assets: sums, `{"broker":"0.1.0-rc2","revision":"8e80245c…","modified":false}`, attestation verifies, and `zarf/repro-passwd-fallback.sh` passes against the **downloaded** artifact |
| `v0.1.0-rc3` | **Current.** `06c7ed2` — rc2 plus `retract v0.1.0-rc1` in `go.mod`, no code difference. Verified from the published assets: sums, `{"broker":"0.1.0-rc3","revision":"06c7ed21…","modified":false}` |

**Withdrawing a version takes three steps and none of them is complete on its own.** Worth
writing down, because the first two look sufficient and are not:

1. **Delete the release.** Done — the binaries return 404. This is the step that matters most,
   since a downloaded binary is how anyone actually gets one.
2. **Delete the tag.** Optional, and it removes less than it appears to (below).
3. **`retract` it in `go.mod`.** This is the one that closes the real remaining hole.
   `proxy.golang.org` had already cached the version — measured, `@v/v0.1.0-rc1.info` returns
   200 — and that cache is **immutable**. So `go install …@v0.1.0-rc1` went on working and
   building the defective source after the release was deleted, and would have gone on working
   after the tag was deleted too. A retraction is honoured from the go.mod of the *latest*
   version, which is why rc3 exists at all and is its entire content.

**Verified, and note what the verification had to separate.** Against the repository directly,
`go list -m -versions` offers `v0.1.0-rc2 v0.1.0-rc3` and no longer offers rc1 — the directive
is correct and effective. Against `proxy.golang.org` at the same moment it still offered
`v0.1.0-rc1 v0.1.0-rc2`, because the proxy caches its version list and had not yet fetched rc3.
That is latency, not failure, and it is worth knowing before someone concludes the retraction
did not work: **check with `GOPROXY=direct` first.**

Two records cannot be withdrawn by any of it: the module proxy's copy of the source, and the
Sigstore provenance attestation in the public transparency log. Someone holding an rc1 binary
can still verify it genuinely came from this repository — which is precisely why the README says
plainly not to use it. **Provenance was never the problem; the binary was.**

The rc1 **tag** was deliberately left in place. Once the release is deleted and the version
retracted it carries nothing a user can reach, and deleting it would not remove the proxy's copy
of the source either — so it stays as a historical marker of what `a336b59` was published as.

### Run end to end, on `v0.1.0-rc1`

Tagged 2026-08-01 as a shakedown rather than a production release. Every step ran: the ancestry
guard passed, the gate passed, both artifacts built and were checked, the attestation was
signed, and `gh release create` published it as a pre-release, so it did not become `latest`.

Verified from the **published assets**, not from the run's own report:

- `sha256sum -c SHA256SUMS` passes for both.
- The binary reports `{"broker":"0.1.0-rc1","revision":"a336b590…","modified":false}`.
- `gh attestation verify <file> --repo jroedel/adb-broker` exits 0 for both. SLSA v1 provenance,
  signed via `token.actions.githubusercontent.com`, naming `.github/workflows/release.yml @
  refs/tags/v0.1.0-rc1` at `a336b59`. Both binaries are subjects of the one statement.

**The build is reproducible, which is worth more than either mechanism D plans.** A fresh clone,
`git checkout v0.1.0-rc1`, `make dist VERSION=0.1.0-rc1` — byte-identical to the published
artifacts, both architectures, on a different machine from the one that built them. Anyone can
therefore confirm a release's digest from source without trusting GitHub, the attestation, or
this project. See D, where it becomes a third lever.

**A dry run can never reproduce the tagged build's bytes, and that is not a defect.** The
rehearsal's amd64 binary was 8 bytes smaller than the release's, with a different digest, at the
same commit with the same flags. The whole difference is one line of build info:

```
dry run:  mod github.com/jroedel/adb-broker v0.0.0-20260801151438-a336b590ff9c
release:  mod github.com/jroedel/adb-broker v0.1.0-rc1
```

Go derives the main module's version from a VCS tag pointing at HEAD. At rehearsal time no tag
existed, so it embedded a pseudo-version; the tag is what changes it. **So the dry run validates
the pipeline, not the digest.** Anyone pre-computing a consumer's embedded SHA-256 from a
rehearsal gets a value that will never match. Take it from the release.

Before this, verified locally from a clean clone at `2eeb8e2`, including both failure arms of the
check script — a version that does not match, and a build from a dirty tree.

---

## D — the consumer-side install contract. Specified; not implemented

**The contract now lives in `docs/ADB_BROKER.md` → *The consumer install contract*, which is
the normative copy.** What follows is the reasoning that produced it, kept here rather than
duplicated there.

**Scope, decided 2026-08-01:** the contract is written down in this repository and implemented
in none. The consumer is `photos`, a separate repository, whose `foundation/source/adbbroker`
adapter today runs a broker it locates via `broker_path` or `PATH` and installs nothing. Writing
the contract here first is deliberate: it binds *any* consumer, and a rule that exists only as
one implementation is not a contract. Implementing it in `photos` is its own piece of work.

**Both verification mechanisms, because they do different jobs.** Attestations are the right
thing to *publish* but a poor fit for what a consumer does at runtime: verifying one means either
shelling out to `gh` (not on an end-user machine) or pulling in `sigstore-go`, and it needs
network access to the transparency log.

- **Publish the attestation** — it makes an artifact independently auditable by anyone, via
  `gh attestation verify <file> --repo jroedel/adb-broker`.
- **Embed the expected SHA-256 for the pinned version in the consumer** — that is what the
  consumer can actually enforce, offline, with nothing but `crypto/sha256`. The digest ships
  *inside* the consumer, never fetched alongside the binary.
- **A third lever, free, discovered in C's rehearsal: the build is reproducible.** A clean clone
  at the tag plus `make dist VERSION=<tag without v>` produces the published bytes exactly —
  verified on `v0.1.0-rc1`, both architectures, on a machine other than the one that built them.
  That is a stronger statement than either mechanism above, because it needs no trust at all:
  not in GitHub, not in the signing infrastructure, not in this project. It is not something the
  consumer can do at install time — it needs a Go toolchain and a checkout — so it does not
  replace the embedded digest. What it does is let anyone establish, once, that the digest the
  consumer embeds corresponds to this source. **Where the embedded digest comes from is
  therefore a settled question: read it from the published `SHA256SUMS`, or reproduce it from
  the tag. Never from a dry run** — see C for why that can never match.

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
  under each other. Read the installed binary's version with `adb-broker version`, which B added
  for this: it answers with no device and no audit log, which is what makes it usable against a
  copy some other consumer installed. A digest comparison cannot substitute — it reports
  "different", never "older".
- **Run `probe` straight after installing** and surface `no_adb_server` / `unauthorized` with
  instructions. This one carries more weight than it looks: the consumer does **not** ship or
  locate `adb`, so the two host preconditions are entirely the user's to satisfy, and they are
  the ones that cost the most time when wrong — particularly that USB-debugging authorization is
  per *adb-server RSA key*, i.e. per account, and misreads as "USB debugging is off".

---

## E — docs. Done

- `README.md`: an **Install → From a release** section, with the commands and their output as
  observed against `v0.1.0-rc1`, and a pointer to the contract for consumers that install the
  broker themselves.
- `docs/ADB_BROKER.md`: **Installation** gained *Installing from a release* and *The consumer
  install contract* — the normative copy of D. **Discovery**'s one-path argument gained its
  second consumer, and it is a different argument: discovery is about not stumbling on a second
  copy, installation is about not *creating* one.
- `docs/THREAT_MODEL.md`: **A5 — whoever controls the release artifact**, a fifth trust
  boundary, and **§4.4 The binary itself** with T32–T34. The asset there is the code that
  enforces every other control, so a threat landing on it defeats §4.1–§4.3 at once.

**§6.6 had to be rewritten rather than extended, and that is the part worth remembering.** It
read: "Nothing in the design verifies that the installed binary was built from reviewed source —
no signature, no reproducible build, no attestation." All three clauses became false the moment
C shipped. It was not wrong when written — until releases existed, every operator compiled from
a checkout they could read, and there was nothing for a supply-chain control to protect. A
threat model has out-of-scope sections that quietly expire when the software changes shape, and
this one expired without anyone editing it. The rewrite quotes the old text rather than deleting
it, and states the narrower truth: a release can be tied to a commit and a workflow and
independently rebuilt, nothing forces anyone to check either, and nothing vouches for the commit.

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

**3. `go version -m` does not record `-ldflags`.** Measured on a `-trimpath` build: the build
settings carry `-buildmode`, `-compiler`, `-trimpath`, `CGO_ENABLED`, `GOOS`/`GOARCH` and the
`vcs.*` trio, and nothing about link flags. A version stamped with `-X` is therefore readable by
exactly one program — the one it was stamped into. The plan assumed otherwise, and the
assumption survives easily because `go version -m` *does* show the commit, which is the value
people usually check.

**Rule of thumb this leaves behind:** if a build stamp is meant to be read by anything other
than the binary itself, the binary has to be able to say it out loud. Otherwise the stamp is
only a comment.

**4. A fail-closed test was passing for the wrong reason, on every machine.**
`TestAnUnopenableAuditLogEndsEverySubcommand` drives four subcommands against a log path that
cannot be opened. Three of them go through the `openAuditLog` seam the test swaps. The fourth,
`verify`, is the one subcommand exempt from the fail-closed check — so it never calls that seam,
the swap is invisible to it, and it resolved `auditLogPath()` and read **the log of whoever was
running the suite**. The case asserted nothing about this binary. It passed because
`~/.local/state/adb-broker/audit.log` does not exist on a machine that has never run a release
build, which is every CI runner and was every development host.

Installing `v0.1.0-rc1` and running `probe` created one, and the test failed immediately —
`"partial"`, exit 0, over the host's real log. Fixed by passing `--log` explicitly, and
mutation-tested by removing it again. No other test invokes `verify` without `--log`.

**Rule of thumb this leaves behind:** a test that substitutes a seam proves nothing about the
code path that does not use that seam. `verify`'s exemption is documented in three places and
was still missed here, because the test *looked* uniform — four rows in one table, one of them
quietly testing the host instead.

---

## What is not done

Phase 3a is finished. Everything below is either another phase's work or a deliberate
non-goal, collected here so the next reader does not have to reconstruct it from the sections
above.

**The consumer.** The install contract is specified and implemented nowhere.
`ADB_BROKER.md` → **The consumer install contract** is what to build against;
`foundation/source/adbbroker` in the `photos` repository is where it lands. Its adapter today
runs a broker it locates via `broker_path` or `PATH` and installs nothing. `v0.1.0-rc3` is a good
artifact to pin against. Note that all five contract rules fail *silently* when broken, which is
the shape that hid three separate defects during this phase — see below.

**The `go fix` rewrite in `app/broker/wire_test.go`** (`typ.Fields()` over `typ.NumField()`),
still unapplied because its output includes an awkward `field := field`. Its own commit if
wanted; nothing depends on it.

**Everything in `ADB_BROKER.md` → Open questions**, unchanged by this phase. Numbers 7–9 are the
ones with teeth, and they share a subject: `verify` degrades as a host accumulates journal
history — the linear entry-array walk, a possible `--since` bound, and journal rotation. None is
phase 3a business, and none is urgent until a host has been running the broker for a while.

**What this phase learned about its own record-keeping**, because it happened three times and
will happen again:

- The `$HOME` fix that changed which function was called and not what happened, and was
  described as done for four months (A).
- The fail-closed test whose fourth case was reading the host's real audit log rather than the
  one it substituted, passing everywhere and asserting nothing (E).
- `THREAT_MODEL.md` §6.6 declaring supply chain out of scope, months after this project started
  publishing attestations and producing reproducible builds (E).

Each read as current and was not. Each was found by *running* something rather than reading it —
a reproduction, an installed binary, a shipped release. **A claim nothing executes is a claim
nobody checks**, and this document has now been wrong about its own contents twice by the same
mechanism.

---

## Open questions

1. ~~**Reproduce the `$HOME` fallback** on a host with an unresolvable uid before calling A
   verified.~~ Done 2026-08-01, and it found that the fix did not work. See A, and
   `zarf/repro-passwd-fallback.sh`. `v0.1.0-rc1` carried the defect and is **withdrawn** —
   release deleted, retracted in `go.mod`; see *Releases*. (A)
2. ~~**Does the VCS revision become a `probe` member, or stay in the audit record?**~~ Closed by
   B: `version` reports it, `probe` does not, and the audit record never carried a version to
   stay in. (B)
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
- Cutting a release: tag `vX.Y.Z` on a commit reachable from `main` and push it. The workflow
  does the rest, and refuses a tag that does not descend from `main`. Rehearse first with the
  `workflow_dispatch` dry run — but see *Releases* for why a dry run cannot produce the tagged
  build's bytes.
- **Phase 3a is done.** See **What is not done** for what is not, and why none of it belongs to
  this phase.
