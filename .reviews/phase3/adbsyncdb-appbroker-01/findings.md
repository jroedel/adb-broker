# Review — `business/domain/device/stores/adbsyncdb` + `app/broker`

Stage 4 of the phase-3 verification plan, second of three area reviews. Scope `main..HEAD`;
both trees are wholly new. Acceptance criteria were `docs/ADB_BROKER.md` and
`docs/THREAT_MODEL.md`, this repo having no issue tracker. The spec was mid-correction while
this ran, so every code/doc disagreement was checked against `3d2c964` first — nothing below is
spec-lag.

Verification run clean: `go vet ./...`, `go vet -tags=fixture ./...`,
`go test ./app/broker/ ./business/domain/device/...`, and the fixture-tagged fixturedb tests.

**Gate: G3 — Repair.** One correctness finding in the reconnect path; the rest is tightening
and polish. No security finding, no data-integrity finding, no boundary-crossing finding.

---

## What was checked hardest, and found sound

**Mutex discipline.** Every `*Locked` method is reached only from the four exported methods
(each `Lock`/`defer Unlock` over its whole body), from another `Locked` method, or — for
`dropSessionIfDeadLocked` — from `walk.go`, which itself only runs inside `List`'s locked scope.
No exported method returns while holding `s.mu`.

**The classification switch, `codeForWire` (`adbsyncdb.go:529`).** Exhaustive against
`adbwire`'s eight sentinels. Six get an explicit case; `ErrProtocol` and `ErrSyncSessionDead`
fall to the caller's `fallback` deliberately and are documented as context-dependent rather than
overlooked; `ErrUnknownService` falls to the default correctly, since this store's call sites
never name a host service. The per-call-site `fallback` is chosen for context —
`CodeTransferFailed` for `Fetch`, `CodeDeviceDisconnected` for a walk.

**The traversal (`walk.go`).** Depth accounting matches the documented meaning exactly:
`maxDepth == 0 || depth < maxDepth`, so `MaxDepth: 1` is immediate children with no descent.
`.` and `..` are skipped by name before any other check, defensively, even though adbd is
measured never to emit them. Every descended directory is re-stat'ed immediately before being
opened (`walk.go:278`) rather than trusted from the parent's `LIS2` record, which closes the
window a bind-mount or symlink swap would open; the allowlist is correctly *not* re-checked per
descent, because `AuthorizedPath.Child` already revalidates the whole joined path at
construction.

**`app/broker`'s stdout contract.** Every stdout write goes through `writeJSON` or the fetch
payload copy. `runFetch`'s framing was traced at every failure point: a header-write failure
writes nothing further, and a failure after the header writes nothing to stdout at all — not
even a coerced path — which is the corruption `3d2c964` measured. `runList`'s terminator switch
is exhaustive with one `return` per arm, so no double-terminator path exists. `path_b64` is
threaded as raw bytes end to end: `fail`, `failCode` and `denyBeforeBus` all pass the raw
request path to `fromBusErrorResponse`, the one place the coerced `Path` and the raw `PathB64`
are built from the same string. `--client` is bounded to 64 ASCII bytes at the flag boundary and
reaches only `audit.Record.ClientAsserted`, never an anchor field. The fail-closed ordering in
`Main` holds, with `verify` the single documented exemption.

---

## Finding 1 (G3) — a `Fetch` whose `RECV` and reconnect both fail reports the wrong code, and the discarded one can be the only fatal signal

**Where:** `business/domain/device/stores/adbsyncdb/adbsyncdb.go:396-412`.

```go
n, err := sess.sc.Recv(ctx, path, io.MultiWriter(w, digest))
if err != nil {
	code := codeForWire(err, errcode.CodeTransferFailed)

	if rerr := s.reconnectLocked(ctx); rerr != nil {
		err = errors.Join(err, rerr)
	}

	return devicebus.FetchResult{}, codeErr(code, err, "recv %q stopped after %d bytes", p.String(), n)
}
```

**Proof.** `code` is computed from the `RECV` failure *before* the reconnect is attempted and is
never revisited. When `reconnectLocked` also fails, its own classification — a dead adb server
maps to `CodeNoADBServer` — is folded into the *message* by `errors.Join`, but the outer
`codeErr(code, …)` still carries the pre-reconnect code. `errcode.From` matches the outermost
`*codeError` immediately and never unwraps into the joined tree, so the reconnect's
classification is unreachable.

**Failure scenario.** `RECV` fails for an ordinary reason and the phone is then unplugged, or the
adb server dies, so the reconnect's dial also fails. The wire reports `transfer_failed` —
documented as a per-file failure the run continues past — when the true state is
`no_adb_server` or `device_disconnected`, both fatal. `ADB_BROKER.md:254` is explicit that a
refused connection to `127.0.0.1:5037` must be `no_adb_server`.

**Why this matters more than its size suggests.** It is the same failure shape as defect B, one
layer down: a fatal, run-aborting condition presenting as a per-file skip. Defect B's whole
argument was that a phone unplugged mid-run must not look like 20,000 per-file failures instead
of one abort — and this path produces exactly that, from the classification side rather than the
framing side.

**Bounded, but not harmless.** `reconnectLocked` unconditionally closes the session first, so no
dead session is ever handed to a later caller, and `app/broker` invokes `Fetch` once per
process, so the next invocation reports the true code. The wrong code still reaches the consumer
for the operation where it mattered.

**No coverage in either direction.** `TestFetchRecvFailureReconnectsOnce` exercises `RECV`
failing and the reconnect *succeeding*; nothing drives the reconnect itself to fail.

**Status: fixed** — classification now prefers the reconnect's own code when it is fatal and the
`RECV` code is not, with the joined message preserved. Test added driving the reconnect's dial
to fail after a `RECV` failure and asserting `no_adb_server` rather than `transfer_failed`.

---

## Finding 2 (G2) — `codeForErrno`'s fallback ignores the caller's context and says "transfer failed" where nothing was transferred

**Where:** `business/domain/device/stores/adbsyncdb/adbsyncdb.go:562-575`.

`notFound` exists so each call site can supply the context-appropriate code for its own
`ENOENT` — `walkRoot` passes `CodeRootNotFound`. But the `default` arm ignores it and hardcodes
`CodeTransferFailed`, documented as "one file's transfer failed". `walkRoot` never attempts a
transfer; it fails an `LST2` of the listing root, so an unmeasured errno there (`EIO`,
`ENOTDIR` from a race, `ELOOP`) is reported as a transfer failure.

G2 rather than G3 because both codes are non-fatal, so a consumer's abort-versus-continue
decision is unchanged — a message-quality defect, not a decision-quality one.

`TestListRootFailures` covers errno 2 and 13 for the root but has no third-errno case, which is
exactly the one that falls through.

**Status: fixed** — the fallback is threaded per call site the way `codeForWire`'s already is,
with a test asserting the root case no longer claims a transfer.

---

## Finding 3 (G1) — `exitError`'s comment claims more than four of its own call sites deliver

**Where:** `app/broker/broker.go:83-84` — "exitError means an error object was written and no
usable output was produced."

Four return sites disagree by design, each correctly: `env.emit`'s write-failure branch,
`runList`'s `errStdout` branch, `env.writeFailed`, and `env.transferFailedMidStream` all return
`exitError` having written *no* object to stdout — because stdout itself failed, or because
writing one would corrupt an already-committed byte count. Only the comment overstates.

**Status: fixed** — softened to cover both cases.

---

## Spec weakness

`ADB_BROKER.md:254` is written from the initial-connection perspective and does not anticipate
the reconnect-after-`RECV`-failure path that the same document's "Connection lifecycle" section
introduces, where the adb server can just as easily be the thing that died. Finding 1 is the gap
that leaves open. The spec should say that a fatal code must be reported however the failure is
discovered, including via a failed reconnect.

## Open checks, stated rather than dropped

- **Whether an unmeasured errno can reach `walkRoot` on real hardware.** Not reproduced against
  a device — none was attached for this review. Rests on the code's logic, not a measurement.
  `EIO` and a TOCTOU `ENOTDIR` are plausible without an adversary.
- **The same `codeForErrno` pattern on the per-entry paths** (`walk.go:178`, `walk.go:293`, both
  passing `CodePathNotFound`). Milder, because both codes there describe a single failed path.
- **Clone Hunter and the straight-line pass: not run**, deferred. `codeErr(codeForWire(err, X),
  err, …)` repeats across `adbsyncdb.go`, `reconnect.go` and `walk.go` and could be folded — but
  that should follow Finding 2's fix rather than precede it, so it does not erase the
  per-call-site context that finding is about.
- **Whether anything calls `Fetch` more than once per `Store` lifetime.** Finding 1's
  "self-corrects next invocation" framing depends on one `Fetch` per process, true of every call
  site in `app/broker` today. Recheck if that seam changes.

## Lenses run

Security Sentinel (G0), Spec Cartographer (G3 — Finding 1 and the spec weakness), Service
Steward (G2 — Finding 2), Error Tripwire (G3 — Finding 1 is precisely a failure-path visibility
gap; every other error path traced was sound), Boundary Keeper (G0 — the App/Business primitive
boundary holds as documented), Doc Drift Check (G1 — Finding 3), Harness Map (G2 — the reconnect
double-failure path had zero coverage; everything else in scope has a targeted test). Clone
Hunter and Straight-Line: deferred, see above.
