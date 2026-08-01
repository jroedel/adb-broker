# Review — `business/types/devicepath` + `foundation/adbwire`

Stage 4 of the phase-3 verification plan, first of three area reviews. Scope `main..HEAD`;
both packages are wholly new (14 files, ~5,900 lines, all additions). Acceptance criteria were
`docs/ADB_BROKER.md` and `docs/THREAT_MODEL.md`, this repo having no issue tracker.

Verification run clean: `go vet ./business/types/devicepath/... ./foundation/adbwire/...` and
`go test` over both.

**Gate: G3 — Repair.** One finding, in a comment rather than in code. No security finding, no
correctness finding.

---

## What was checked hardest, and found sound

These are recorded because a review that only lists findings reads as though nothing else was
examined.

**`devicepath`** — compiled-allowlist immutability, the `/sdcard/` spelling rule, every
rejected path form (NUL, `..`, `.`, relative, trailing and doubled slash, parent-of-root),
segment-boundary matching (`Download` vs `Download-private`), `Child`'s revalidation,
`Narrow`'s can-only-reduce / monotone / all-or-nothing invariants, and the volume pin's
`dev`-only comparison with `ino` as provenance. No defect found in any of them; each has a
targeted test (e.g. `TestNarrow_CannotWiden`,
`TestParseAuthorizedPath_NULIsCheckedBeforeTheAllowlist`,
`TestVolumeContains_MatchingDevWithADifferentInoIsAllowedBecauseThePinIsDevOnly`).

**`adbwire`** — every length field (`syncMaxChunk`, `syncMaxName`, `syncMaxFailMessage`,
`syncMaxPath`, `hostRequestMax`) is bounded before its allocation; every `readFull` goes
through `io.ReadFull`, so no path assumes a full buffer; and both previously-measured desync
bugs — `LIS2`'s 72-byte zeroed `DONE` body and `RECV`'s 4-byte `DONE` argument — are correctly
implemented with a device-measured regression test each.

Every `switch` branch in `sync.go`'s `statCommand`, `List` and `Recv`, and in `adbwire.go`'s
`query` and `switchServiceLocked`, was traced for the desync class specifically: **every error
path that would leave undrained or ambiguous bytes on the wire calls `s.kill()` (sync) or
`c.spend()` (host).** No session survives a failure it should not.

---

## Finding 1 — `devicepath`'s package doc claims to be the only confinement boundary, and it is not

**Where:** `business/types/devicepath/path.go:1-27` (the package doc — this is what `go doc
devicepath` prints).

**The claim.** "The rules in this package are therefore the ONLY boundary between an adb sync
transport and the rest of the device's filesystem", followed by "Confinement is two mechanisms,
and they are different in kind: AuthorizedPath… / Volume…".

**Why it is wrong.** `THREAT_MODEL.md` §5.7 and `ADB_BROKER.md` are explicit that confinement
below the root rests on **three** load-bearing checks, not two: the string rules, the `dev`
pin, and the **kind check** that admits only regular files and directories. The kind check is
what actually stops a planted symlink (T6), and it lives in the storage layer against
`filekind.Kind`, outside this package. §5.7: "removing the kind check … would make symlink
escapes reachable, and nothing else in the design would stop them."

`volume.go:46`, two files away in the same package, already says this correctly: "It does NOT
close the symlink case — that is the kind check's job, elsewhere, and the two are not
redundant."

**Why it matters.** A control credited with more than it does is worse than no control, and
this repository has already walked back two claims of exactly this shape (the single-spelling
rule, and the "two independent checks" reading of the volume pin). This one survived, in the
file most likely to be audited on its own, contradicting a more careful comment in the same
package.

**Status: fixed** — the enumeration now names the third mechanism and scopes the
"only boundary" claim to what this package can decide from a path string and a dev pin, with a
cross-reference to §5.7.

---

## Spec weakness — a named serial that is not attached has no code of its own

`foundation/adbwire` correctly gives it a sentinel (`ErrDeviceNotFound`, `errors.go:23`,
tested per-string in `TestFailProseMapping`), and `probe`'s own "four distinct prose failures"
table lists it. The taxonomy in `ADB_BROKER.md` has no slot for it, and `errcode` defines no
matching `Code`.

Confirmed downstream (outside this review's scope, checked while triaging): the single
classification switch at `business/domain/device/stores/adbsyncdb/adbsyncdb.go:539` maps it to
`no_device`, together with `ErrNoDevices`.

The consumer's action is identical either way — abort the run — so the cheap correct answer is
to document that `no_device` also covers "the device you named is not attached", rather than to
add a seventeenth code for a case that branches the same way. Recorded for the spec pass.
`no_device`'s current gloss, "Nothing attached", is untrue of this case and is what should
change.

---

## Open checks, stated rather than silently dropped

- **Whether `adbwire`'s sentinels are mapped to `errcode.Code` in exactly one place.**
  Answered after the review: yes, the switch at `adbsyncdb.go:530-548`, and it is the only one.
  `ADB_BROKER.md`'s architecture table attributes a "FAIL→code table" to `foundation/adbwire`,
  which could be read as asking that package to produce an `errcode.Code` directly; it stops at
  its own sentinels, and it must, because no foundation package imports anything else in this
  module. The table's wording is loose, not the code.
- **Case sensitivity of the accepted spelling.** `ParseAuthorizedPath` compares segments
  byte-for-byte (`TestParseAuthorizedPath_IsCaseSensitive`). Nothing in `adb_experiment.md`
  measures whether the device's shared-storage FUSE layer is case-sensitive. Not a finding —
  noted because it is the one path-form category the measured device table does not cover.
- **Clone Hunter and the straight-line/simplification pass were not run** — deferred, not
  skipped. `sync.go`'s `statCommand`/`List`/`Recv` do share header-read and kill-session
  boilerplate that could be factored, but the byte-consumption order in that file is unusually
  load bearing, and it should not go to a simplification pass without someone re-deriving the
  byte counts first.

## Lenses run

Security Sentinel (G0), Spec Cartographer (G3 — Finding 1, plus the spec weakness above),
Service Steward (G0 — idiomatic modern Go: `errors.AsType`, `slices`, `strings.SplitSeq`,
atomic-pointer allowlist), Error Tripwire (G0, traced exhaustively — see above), Doc Drift
Check (source of the G3), Harness Map (G0 — both historically-bitten desync bugs have unit and
real-device regression tests), Boundary Keeper (G0 — `AuthorizedPath`/`Volume` unforgeable,
`adbwire` a true leaf with zero intra-repo imports). Clone Hunter and Straight-Line: not run,
see above.
