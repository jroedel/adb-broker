# Phase 3 — Verification

Phase 1 was planning, Phase 2 was building. This is the phase that tests whether any of it is
true.

## Context

Phase 1 planned, Phase 2 built: 28 commits, 13 packages, green in every build configuration.
But almost everything is verified against *recorded* measurements rather than against reality:

- **No device test has ever run.** All 19 skip; the phone was never attached during the build.
- **The binary has never been installed.** `/usr/local/bin/adb-broker` does not exist and the
  production audit log is still 0 bytes, so the setuid design and the two-control audit
  guarantee are untested end to end.
- **Nothing has ever consumed the wire format.** Our tests assert the bytes we chose.
- **The spec's process-model numbers trace to no measurement**, and they justify the
  no-daemon decision.

Three defects are already confirmed before Phase 3 starts, which is itself the argument for
it. Phase 3 exists to find the rest.

---

## Confirmed defects (fix before photos consumes the contract)

**A — the `list` terminator discriminator is unsafe. Confirmed by running the binary.**
The spec says the summary is "distinguished by having no `path` member", but a failed `list`
emits an error object that *does* carry `path`:

```
{"proto":1,"status":"error","code":"path_denied","path":"/sdcard/NOPE","message":"..."}
```

A consumer following the documented rule decodes that as a file record — `path_b64:""`,
`size:0`, `mtime:0` — and loses the `code`. The collision is data-dependent (a `fetch`
refused at the flag boundary carries no `path`), so it survives hand-testing and fires in
production. **Fix:** the discriminator is the presence of `status`; file records carry none.
Correct `docs/ADB_BROKER.md` and add `path_b64` to error objects that name a path.

**B — a failed `fetch` writes an error object after a partial payload, and that costs a real
safety property.** `app/broker/fetch.go` writes the header from inside the `FetchInfo`
callback, then on a later error calls `e.fail(...)` onto the same stdout. A consumer reading
exactly `size` bytes eats part of that JSON as payload, so **every mid-stream fetch failure
degrades to "truncated stream"** and `path_not_found` / `transfer_failed` /
`device_disconnected` become indistinguishable. The first two are per-file, the third aborts
the run — so a phone unplugged mid-run looks like 20,000 per-file failures instead of one
abort, exactly the outcome the taxonomy exists to prevent. **Fix:** once the header is out,
the only further object on stdout is a trailer; define a failure trailer
`{"status":"error","code":…}`. The framing stays intact and the code stays recoverable.

**C — per-path errors are not round-trippable.** `PathErrorResponse` is `{code, path}` with
no `path_b64`. Every other path in the contract is authoritative-by-base64 because filenames
are bytes; the one place a consumer might want to *act* on a path is the one place it gets
only the lossy rendering. **Fix:** add `path_b64`. Additive, so `proto` stays 1.

**D — fixture mode is missing `--fail-after` and `--inject-error`.** Both are described in
the spec; neither exists. They are what makes A, B and the 16-code mapping testable against
the real binary rather than against a consumer's fakes. Their absence is *why* defect B could
not be reproduced by execution above. **Fix:** implement both, fixture-tagged.

---

## Stage 1 — Hardware validation (do first; the phone is attached now)

The phone may not be available later, so this leads.

1. `make test-device` — all 19 tests. Expect at least one interesting failure; they encode
   `adb_experiment.md`'s recorded values, so a disagreement is a finding.
2. **Settle `TestDeviceRecvDoneArgumentWidthIsFourBytes`** — the codebase's only unverified
   protocol assumption, inferred from AOSP rather than measured. A wrong width desyncs the
   *next* command, so the test asserts on a following command.
3. **Measure the process model with the real binary**, since its numbers are unsourced:
   per-invocation cost (spawn + connect + transport + `STA2` + `LST2`), wall clock for a full
   six-root enumeration, and fetch throughput through the Go `RECV` path. Compare against the
   spec's claim of ~10 ms spawn, 23,939 records over "11" roots, 21 MB/s, "under 3%".
   **If the numbers contradict the 3% claim, reopen the daemon decision rather than restating
   it.**
4. Attempt the two remaining `adb_experiment.md` "Still untested" items that hardware allows:
   a `LIS2` stream large enough to stress the reader, and a mid-transfer `RECV` failure.

**Output:** a new `docs/DEVICE_FINDINGS.md` in the established experiment style —
measured values, what changed in the spec, what remains untested.

## Stage 2 — Install and the real audit trail (needs root from your other account)

This is the only way to test the two-control design. Commands to run as root:

```bash
cd /opt/projects/adb-broker && make build
sudo ./zarf/install.sh --binary bin/adb-broker --client agy_user
sudo ./zarf/install.sh --verify-only
```

Then, as `agy_user`, I verify the properties that only a real install can show:

- `/usr/local/bin/adb-broker` is `adb-broker:adb-broker-clients` mode `4550`, setuid, and
  **not writable by its own owner**.
- Running it as uid 1003 appends to a log owned by uid 995 — `caller_uid` in the record is
  1003 while the file owner is 995, which is the whole two-control design.
- `chattr +a` is honoured by the real binary.
- A uid outside `adb-broker-clients` cannot execute it.
- Anchors reach journald carrying `_UID=995` and `_EXE=/usr/local/bin/adb-broker`. **This is
  the first time `WriteAnchor` touches the real socket** — every existing test uses a temp
  socket.
- `verify` against **real journal files**, not `--anchors -`. This closes the largest single
  coverage hole: `anchorFields`' file-reading branch is 0% covered in every configuration.
- `verify` **discards the forged anchor** published during the audit experiment, which is
  permanently in this host's journal from an ordinary uid. A real adversarial fixture.

## Stage 3 — Fix the four confirmed defects

In order, because D unblocks testing A and B: **D → A → B → C**. Each gets a test that fails
before the fix. Files: `app/broker/{list,fetch,wire,verify}.go`, `app/broker/fixture.go`,
`docs/ADB_BROKER.md`.

Also decide, not just record:

- **`probe` should report the effective allowlist.** `path_denied` is specified as a
  configuration error, but the six roots are reported nowhere, so a consumer can only discover
  a bad root by connecting to the phone and being refused, once per source. Reporting them
  widens nothing — the caller cannot change them — and turns a per-source runtime refusal into
  a startup error. It is also the only thing that makes the photos migration require a manual
  audit of `photos.yaml`.
- **`fetch --serial` doubles the operation count.** Because `ExtBusiness.Fetch` takes no
  serial, a pinned-serial run does a full `Probe` per fetch: 40,000 operations and 40,000
  audit records on a first run. Either let `fetch` select a transport without a separate
  audited probe, or have `probe` report the attached-device count so a consumer can safely
  omit `--serial`.
- **`volume_unresolved` from a `list`** is specified to abort one source, but a remount fails
  every remaining source too — reproducing one level up the exact "thousand misleading
  symptoms" problem the spec solved one level down. It should abort the run.
- **`model` is specified and never populated**; **`state != "device"` is a check that cannot
  fire** because such a device fails earlier and returns an error object instead. Both are
  spec corrections, and the second is the same anti-pattern the spec criticises in the
  `host:host-features` trap.

## Stage 4 — Full `pr-review` skill run

Run the repo's own `pr-review` skill across all lenses over the 28-commit diff, writing
numbered findings under `.reviews/`. Weight it toward the hand-written parsers and the
security-critical paths: `devicepath`, `adbwire` framing, `journal` format, `audit` canonical
serialization, `adbsyncdb` traversal. Triage findings into fix-now / record / reject, and
reject explicitly rather than silently.

## Stage 5 — Wire photos to the broker

The real integration, and the thing that retires the "nobody has consumed this" risk.
A **new sibling package** `photos/foundation/source/adbbroker`, selected by a third
`source.transport` value, with `adb` left untouched so rollback is one config line.

- The existing `adb.Runner` seam buffers stdout into `[]byte` — fine for `find|stat`, fatal
  for 20,000 NDJSON records and framed binary. The new seam is callback-shaped
  (`Run(ctx, args, consume func(io.Reader) error)`), which makes leaking a process or dropping
  stderr structurally impossible.
- `list`: stream-decode, filter through the *existing* `source.Accept` / `source.HiddenBelow`
  (policy stays in photos, per the spec), buffer only accepted entries. **A stream with no
  terminal object is a failure**, and **records before an error terminator are discarded** —
  a partial tree presented as whole is the failure this tool exists to prevent.
- `fetch`: `io.CopyN` for exactly `size`, then the trailer **from the same buffered reader**
  (a second reader loses what `bufio` already pulled — the likeliest bug in the change),
  cross-check the trailer digest against the locally computed one, `O_EXCL` staging as today.
- The 16 codes map onto photos' existing abort / skip-source / warn-and-continue flow. It
  currently has only two source-level outcomes, so add one sentinel `source.ErrSourceRefused`
  for "abort this source loudly, but not the run" — `path_denied` needs it, and today a
  skipped source exits 0, which for `path_denied` means a silently short backup.
- Delete `photos/docs/ADB_BROKER.md` — a stale fork of the spec that still says
  `photos-adb-broker` and still documents `--verify-device`. Two copies of a contract is the
  drift the design warns about.
- Migration acceptance test, free and decisive: one `-dry-run` per transport over the same
  root; the two reports must agree file for file. The ledger is transport-independent — both
  adapters produce the same path, size and whole-second mtime — so flipping back and forth
  re-archives nothing.

## Stage 6 — Close the coverage gaps that matter, and add CI

Not coverage for its own sake; these specific paths:

- `adbsyncdb`: **reconnect failing after a RECV failure** (`reconnect.go`'s error return and
  `Fetch`'s `errors.Join` branch are both 0%) — the double-failure case.
- `adbwire`: transport dying *mid-exchange* (protocol-shape failures are tested; socket-dies
  failures are not), and an already-cancelled context.
- `audit`: `ChainError.Error`/`Unwrap` and `Log.Path` are never called by any test.
- `journal`: `readError` is 0% and appears unreachable — determine whether it is dead code.

CI: `.github/workflows/ci.yml` running vet + staticcheck under both release and fixture tags,
`test-unit`, `test-fixture`, `deps-check`, `gofmt`, and both builds. `device` and `integration`
stay out — no hardware in CI. There is no CI in this repo today, which is why four
configurations are easy to forget.

## Stage 7 — Sign-offs and doc reconciliation

- **Explicit written sign-off** in `THREAT_MODEL.md` for the two assumptions no test on this
  hardware can settle: **T7** (the `LST2`→`RECV` TOCTOU race, which needs code execution on
  the phone) and **T27** (whether any non-UTF-8 filename exists — none was ever found). Dated,
  with the reasoning, so each is a decision rather than an omission.
- **`business/types/devicepath/volume.go` still carries the pre-correction comment** claiming
  the `dev` check catches a symlink escape. The docs were corrected; the code comment was not.
- Correct the process-model section with Stage 1's real numbers, and strike the figures that
  trace to nothing.
- Quantify journald retention (the truncation-detection horizon) and the `KEYED-HASH` linear
  walk's speed on this host — both recorded as unmeasured.

---

## Verification

Phase 3 is done when:

1. `make test-device` **runs** — not skips — with the phone attached, and every failure is
   either fixed or recorded as a finding with its measurement.
2. The `RECV` `DONE` width is measured, and `adb_experiment.md` no longer lists it as the
   codebase's one unverified assumption.
3. `sudo ./zarf/install.sh --verify-only` passes against a real setuid binary, and a run as
   uid 1003 leaves records in the uid-995-owned log with `caller_uid:1003`.
4. `verify` reads **real journal files**, confirms the chain, and discards the forged anchor.
5. `photos --transport broker -dry-run` and `--transport adb -dry-run` agree file for file
   over the same root, and one real broker-backed archive run completes.
6. All four confirmed defects have a test that failed before the fix.
7. CI is green on a pushed branch.
8. Every item in the assumption inventory is measured, tested, signed off, or struck.

**The honest failure mode to watch for:** Stage 1 or Stage 5 finding something that
invalidates a design decision rather than a line of code — the process-model numbers and
defect B are both already in that territory. Where that happens, rework the decision rather
than patching around it, which is what was done when `/sdcard` turned out to be a symlink.
