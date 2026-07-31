# Review — `foundation/audit` + `foundation/journal`

Stage 4 of the phase-3 verification plan, third of three area reviews. Scope `main..HEAD`; both
packages are wholly new. Acceptance criteria were `docs/ADB_BROKER.md` and
`docs/THREAT_MODEL.md` (§4.2, §5.5, §5.6 especially).

Verification run clean: `go vet` and `go test` over both packages.

**Gate: G3 — Repair.** One correctness finding with a reproduced failure, one contract
violation, one undocumented design gap, and a definite answer on a suspected piece of dead
code. No secrets, no injection: the one security-relevant control — the `_UID`/`_EXE` anchor
filter — is present, mandatory by type, and tested against a fixture modelling the real forged
anchor this host's journal contains.

---

## What was checked hardest, and found sound

**Canonical serialization (`record.go`).** Field order is a hand-written literal sequence rather
than reflection over struct tags, and `TestCanonicalFieldOrder` proves the two cannot drift.
Every field is always emitted, so there is no omitempty-shaped ambiguity between "absent" and
"present but zero". The escape set is pinned exactly, including that HTML-special characters are
deliberately *not* escaped — unlike `encoding/json`'s default, which the package correctly
declines to depend on. Because every string field is independently escaped as a proper JSON
string, no field's content can make the byte stream parse as a different set of key/value
pairs. Timestamps are zone-independent and truncate rather than round; an unrepresentable year
is rejected rather than silently emitted at a different width. `HashRecord` excludes the
record's own `Hash` by construction and is tested against a golden digest.

**The chain (`log.go`).** `Open` does what it claims: it recomputes the tail's hash against that
record's own `Prev`, and confirms the descriptor is really `O_APPEND` via `fcntl(F_GETFL)`
rather than trusting the flags it asked for. `VerifyChain` rejects an edited record, a reordered
pair and a middle deletion, and `TestVerifyChainCannotDetectTailTruncation` exists specifically
to pin the one gap only the anchor closes. `decodeLine` rejects unknown members and trailing
data, so unhashed bytes cannot ride along in a line that still verifies. Sequence numbers cannot
skip or collide: `Append` assigns under one mutex that also guards the write, 64 concurrent
appends produce a gap-free chain, and `VerifyChain` independently rejects any `Seq` that is not
`LastSeq + 1`.

**The anchor filter.** `Filter.UID` and `Filter.Exe` are non-optional — there is no way to
construct a filter matching "any uid", which is what T31 requires — and `decidesMatch` refuses
an entry carrying two different values for `MESSAGE_ID`, `_UID` or `_EXE` rather than picking a
winner, closing the place a shadowed field could otherwise decide a match in the sender's
favour.

**The parser's refusal to guess (`journal.go`).** An unrecognised incompatible flag, a bad
signature or an out-of-range header is `ErrUnsupportedFormat`, never a quiet empty result. The
entry-array walk keeps a `visited` set, so a cyclic chain cannot spin forever. Every offset is
bounds-checked against `usedEnd` before dereference and every declared object size against a
cap before allocation, so a corrupt file cannot drive unbounded allocation. `readFields`
distinguishes "compressed, so possibly the field we need" from "absent", so a compressed `_EXE`
is refused rather than silently treated as a non-match. The integration test diffed 804,689
field values byte-for-byte against `journalctl -o export` with zero mismatches — the strongest
evidence available for a parser with no standard-library reference to check against.

---

## Finding 1 (G3) — a record that loses only its trailing newline permanently poisons everything appended after it

**Where:** `foundation/audit/log.go:464` (`bytes.TrimRight(buf, "\n")`) with `Append`'s
unconditional write at `log.go:240`.

`TailRecord` grows a window backwards, trims trailing newlines, and decodes what remains. It
never checks whether the buffer *ended* in `\n` — only whether what survives trimming is
decodable. A final line that is complete valid JSON but missing its own trailing newline, the
last byte `encodeLine` writes, is therefore accepted as a healthy tail, hash and all. `Append`
then writes with no leading separator and no check of the current last byte, so the next record
is concatenated directly onto it.

**Reproduced empirically.** Drop exactly the last byte of a two-record log and: `TailRecord`
succeeds, returning record 2 with a verifying hash; `Open` succeeds, so **fail-closed does not
engage and the broker runs normally**; a third `Append` succeeds and reports its operation as
durably recorded. `VerifyChain` then fails — "chain diverges at line 2: decode record: trailing
data after record" — and reports `Records:1, LastSeq:1`. Records 2 and 3 are both unreachable,
because `bufio.Scanner` splits on `\n` and there is none between them.

This contradicts `Append`'s own promise that "a crash part-way through a twenty-thousand record
run leaves a valid shorter chain rather than a corrupt one". That holds for a *shorter*
interrupted write, which `TestTailRecordPartialFinalLine` covers. It fails for the one adjacent
case where the interruption lands on the final byte.

**Preconditions, honestly.** A write that transfers every byte except the final newline —
`ENOSPC` landing there, or a crash mid-syscall. Not attacker-triggerable at will, but disk-full
is the ordinary way a host misbehaves without malice (`THREAT_MODEL.md` A4), and robustness
against exactly this is what an append-only audit log is for.

**Status: fixed** — `TailRecord` now requires the raw bytes to end in a newline, routing the
"valid JSON but no terminator" case into the existing fail-closed path.

## Finding 2 (G2) — two of `Append`'s four failure modes violate the package's own contract

**Where:** `foundation/audit/log.go:229-238`.

The package doc defines `ErrAuditUnavailable` as covering "the log cannot be opened **or appended
to**" and tells callers to fail closed on it. Of `Append`'s four failure modes, the closed-log
and `Write` paths wrap it; the `HashRecord` and `encodeLine` paths do not. Both trace to
`Canonical`'s single failure mode, a `Record.TS` outside years 0000-9999. `Append` normalises to
UTC milliseconds first, which narrows the window without closing it.

A caller written against the documented contract would not recognise these two as the
audit-unavailable condition the design says every `Append` failure is — a fail-closed bypass in
whatever caller trusts the contract literally.

**Status: fixed** — both wrapped, with a test asserting `errors.Is(err, ErrAuditUnavailable)` for
an out-of-range timestamp.

## Finding 3 — durability across power loss was neither implemented nor documented

`Append` never calls `File.Sync`, so a write can return success — allowing the described
operation to proceed under the fail-closed policy — while the record sits in the page cache. A
panic or power loss then loses it entirely. That is a stronger failure than either gap the
package documents: an edited tail is caught at `Open`, a truncated tail by the anchor
comparison, but a record that was never durably written leaves nothing to detect.

Unlike those two, it was not a *named* trade anywhere, which made it read as an oversight rather
than a decision.

**Status: closed rather than documented.** The maintainer's decision was to fsync on every
`Append`, with a sync failure surfacing as an `Append` failure like any other — a record that is
not durable must not be reported as recorded. The cost is real and is written into the comment:
roughly 1-5 ms per record, so on the order of a minute added to a 48,704-file first run, against
the ~329 s of protocol setup that run already pays.

## Finding 4 — `journal.readError` is not dead code, but its comment describes a scenario it does not guard

Asked for a definite answer, and here it is.

- Its `io.ErrUnexpectedEOF` branch is **provably unreachable**: `os.File.ReadAt` loops on
  `internal/poll.FD.Pread`, which converts a zero-byte read at EOF into `io.EOF` and never
  produces `ErrUnexpectedEOF`.
- The scenario its comment cites — "a file journald is still writing" — **cannot reach it
  either**. Such a file only grows, and every read is already bounds-checked against `usedEnd`, a
  snapshot taken at `Open`. The mid-append case is handled by that arithmetic and the
  unused-object zero check, neither of which is `readError`.
- Its `io.EOF` branch **is** reachable, by exactly one route: the file *shrinking* after `Open`
  cached `usedEnd`. journald never does that to an open inode — rotation unlinks or renames, and
  POSIX keeps an open fd's bytes intact — so it takes an external truncation of the still-open
  file. Confirmed by truncating a built fixture under an open `*Reader`: the branch is hit and
  `Entries` returns the surviving entries with a nil error.

A sibling reviewer, asked the same question independently, reached the same mechanism and leaned
toward deleting the branch on the grounds that a defensive branch guarding an impossible race
reads as evidence of a property the code does not have.

**Status: comment rewritten, branch kept.** The false claim was the defect; a defensive branch in
a parser reading files this process does not control is worth keeping once honestly described.

---

## Open checks, stated rather than dropped

- **U+FFFD is not injective, deliberately.** A raw invalid UTF-8 byte and a literal U+FFFD
  canonicalize identically, so two different original records can produce identical bytes. Looked
  for a way to turn that into a forgery — two operationally different records colliding on
  `Decision` or `Op` — and could not: it only ever conflates two spellings of the same field's
  content, both of which the design already treats as not literally representable. Real, tested,
  and not exploitable.
- **`AnchorTail` reads `Seq()` and `Head()` under two separate lock acquisitions**, so a
  concurrent `Append` between them would publish a mismatched anchor. Honestly documented as a
  caller precondition; whether it holds is a property of `app/broker` and `devicebus`, not
  verified here.
- **`Filter.Exe` is mandatory in code while the docs say only `_UID` is load bearing.** Not a
  drift finding on reflection: `_EXE` is also journald-stamped and unforgeable, and requiring it
  narrows further without being credited as doing the primary job. "Load bearing" in the prose
  means the field that excludes any other local process, which is true of `_UID` alone.
- **Clone Hunter and the straight-line pass: not run**, deferred for the same reason as the
  sibling reviews — byte-exact hashing and hand-written parsing should not go to a
  simplification pass without someone re-deriving the invariants first.
- **Boundary Keeper: not applicable.** Both are leaf foundation packages with no App/Business/
  Storage crossing of their own.
- **`verify`'s anchor-vs-log comparison lives in `app/broker/verify.go`**, out of scope. Whether
  the caller builds `Filter.Exe` from the *installed* path rather than the running process's
  argv[0], as T31 requires, was not verified here.

## Lenses run

Security Sentinel (G0), Spec Cartographer (G3 — Findings 1 and 3 against T12/T13/T17), Service
Steward (G3 — Finding 1), Error Tripwire (G2 — Finding 2), Doc Drift Check (G3 — Finding 1
contradicts `Append`'s doc, Finding 2 contradicts the package contract, Finding 4 the
`readError` comment), Harness Map (G2 — Finding 4 plus the untested bad-timestamp path).
Boundary Keeper: not applicable. Clone Hunter and Straight-Line: not run.

Diagrams: skipped deliberately. Nothing here changes a client-facing contract, and the chain's
shape is already stated precisely in `record.go` as
`hash_n = SHA-256(hash_{n-1} ‖ canonical(record_n))` — a diagram would flatten that rather than
clarify it.
