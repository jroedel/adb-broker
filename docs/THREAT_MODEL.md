# The adb Broker — Threat Model

What this binary is built to defend against, what it is not, and what each control
actually buys. It expands the short **Threat model** section in `ADB_BROKER.md`; where the
two disagree, this document is the one to fix.

The rule throughout is that a control is only worth having if it is clear what it stops
and what it does not. Several of the broker's mechanisms look like ceremony until the
adversary they answer is named, and at least two of them are weaker than their names
suggest. Both cases are stated in place rather than left for a reader to discover.

**Evidence status.** Claims about device and protocol behaviour are measured — the runs are
in `adb_experiment.md`, 2026-07-30, against the target phone. Claims about the host
environment were largely unverified when this document was first written; the audit
infrastructure has since been measured on 2026-07-31 and those runs are in
`audit_experiment.md`. That pass confirmed the anchor path end to end, confirmed both audit
controls on real hardware, and turned up one threat this document had missed entirely (T31,
forged anchors via a world-writable journal socket). §8.1 is answered and closed: bypassing
the broker requires neither root nor any particular uid. Anything still resting on
architecture rather than a run says so in place.

**Revised 2026-08-01: the privileged install was withdrawn, and this document is weaker for
it by design.** The broker no longer runs as a service account, the audit log is an ordinary
file owned by the account that writes it, and `chattr +a` is gone. Two of the four boundaries
in §2 collapse into one; A2 splits into A2a and A2b; §5.5 becomes the only audit control and
loses half its filter; §8.2 reopens; §8.6 is declined. Each is amended in place with the
measurement behind it, and the trade is argued once, at `ADB_BROKER.md` → **Installation**.
The short version: the withdrawn controls protected the audit log rather than the phone, and
they cost a root-run step on every host rebuild — which is a way for the archive to stop being
made at all.

---

## 1. What is being protected

Three assets, in priority order. The ordering matters because two of the controls trade
against each other and the tie is broken by this list.

1. **The phone's storage outside the user's own media.** Application sandboxes under
   `/data`, system paths, and anything on `/sdcard` that is not one of the six allowlisted
   trees. The requirement is that these are unreachable *through this binary*, including
   by a caller that asks for them deliberately and by a device that offers them in a
   directory listing.

2. **The record of what was read.** If the broker did reach something, that fact must
   survive an attempt to erase, truncate, reorder or rewrite it — and the record must
   describe the operation that actually happened, not one that was merely validated.

3. **The archive's correctness.** Photos that exist on the phone must not be silently
   omitted, and bytes that are archived must be the bytes the device holds. This is not a
   security property in the usual sense, but it shares controls with the first two and it
   is the reason the tool exists, so it belongs here rather than in a separate document.

Availability is deliberately **not** on this list. See §7.1.

---

## 2. System and trust boundaries

```
   ┌─ host ──────────────────────────────────────────────────────────┐
   │                                                                 │
   │  consumer (uid A) ─exec─▶ adb-broker (uid A, no setuid)         │
   │        │                        │        │                      │
   │        │                        │        └─append─▶ audit.log   │
   │        │                        │                   (owner A,   │
   │        │                        │                    0600, in   │
   │        │                        │                    ~/.local/  │
   │        │                        │                    state)     │
   │        │                        │                               │
   │        │                        └─anchor─▶ systemd journal      │
   │        │                                         ▲              │
   │        │                                         │  ← §4.2 T31  │
   │        └────────────── any other local process ──┤              │
   │                                                  │  socket is   │
   │                          adb server ◀────────────┘  mode 0666   │
   │                        127.0.0.1:5037    ← §8.1                 │
   └──────────────────────────────┬──────────────────────────────────┘
                                  │ USB
                             ┌────▼────┐
                             │  adbd   │   no confinement of its own (measured)
                             │  phone  │
                             └─────────┘
```

Five boundaries, and it is worth being explicit about which are enforced by what. The fifth is
new on 2026-08-01 and exists only because the binary is now downloaded rather than compiled by
whoever runs it:

| Boundary | Enforced by | Strength |
|---|---|---|
| Caller → broker | `AuthorizedPath` / `Volume` types; compiled allowlist and service vocabulary | Compile-time; a caller cannot express a denied operation |
| Broker → phone | The adb sync service vocabulary the broker will emit | Compiled constant, not convention |
| Broker → audit log | Nothing, since 2026-08-01. The broker and the log's owner are the same account | **Not a boundary.** Was two independent kernel-enforced controls; see §5.5 |
| Audit log → tamper detection | Hash chain + journald anchor | Detection, not prevention — and not against the backup account itself |
| Release artifact → installed binary | An embedded SHA-256 the consumer checks before installing; a provenance attestation and a reproducible build for anyone auditing after the fact | Detection at install time only. Nothing revisits the file afterwards — see §4.4, T34 |

The third row used to read *separate uid, `chattr +a`, root-owned parent directory*. That
install was withdrawn (`ADB_BROKER.md` → **Installation**), and the row is left in place
reading "nothing" rather than deleted, because a boundary that used to exist and no longer does
is worth more to a reader than a table that never mentions it. Everything that row carried has
moved into the fourth, which is detection and was always only detection.

`adbd` is **inside** the trust boundary in the sense that the broker believes what it
says — and outside it in the sense that everything it says is re-validated. It applies no
confinement of its own: measured, the sync channel stats `/`, `/data/data` and `/data/misc`
freely. The broker's rules are the only boundary there is.

---

## 3. Adversaries in scope

### A1 — A hostile or buggy caller

Anything invoking the broker: the archiver, a shell, a script, a compromised `photos`. It
controls `--root`, `--path`, `--serial`, the optional configuration file, the environment,
and whether it reads stdout at all.

**Assumed capable of:** asking for any path in any spelling, supplying malformed or
adversarial path forms, discarding stdout and stderr, invoking the broker in a loop.

**Not assumed capable of:** nothing structural, since 2026-08-01. This line previously read
*modifying the installed binary, or writing to the audit log (owned by a different uid)*, and
both of those exclusions came from the setuid install. With the broker running as its caller,
a caller that is the backup account **can** rewrite the binary and **can** write the log. What
it still cannot do is express a denied operation *through* the broker — that is compile-time
and untouched — or produce a false record and have it survive `verify` alongside anchors it
did not publish.

The distinction that now matters for this adversary is which account it runs as, and A2 is
where that is split.

This is the adversary most of the confinement design answers, and it is the one where the
controls are strongest — a denied operation is not a check that was skipped, it is a
program that does not compile.

### A2 — A local unprivileged process on the host

Can write files and execute code as an ordinary user, can read this repository and rebuild
the binary from modified source.

**Since 2026-08-01 this adversary must be split in two, and the split is the whole of what the
withdrawn install used to buy.**

**A2a — running as any uid other than the backup account.** It cannot write the binary
(`0755`, owned by the backup user, in that user's `~/.local/bin`), cannot open or unlink the
audit log (`0600` in a `0700` directory owned by that user), and cannot publish an anchor that
`verify` will accept, because journald derives `_UID` from the socket's own credentials and a
sender cannot set it. This is very nearly what the whole of A2 used to be, and against it
essentially nothing has changed.

**A2b — running as the backup account itself.** Every one of those falls. It owns the binary,
owns the log, and publishes anchors under the uid the trust filter selects on. Against A2b the
audit log is not evidence, and no control in this document makes it so. This is a real
enlargement of the adversary's reach and it is accepted deliberately — see §5.5 for the
argument, which rests on the fact that A2b can already read the phone directly (§8.1) without
touching any of this.

Under either split it can build and run *its own* copy of the broker, and that copy is a
different program whose reads are unlogged. See §6.2 for what the audit guarantee reduces to,
and §8.1 for the measurement that reframed this adversary.

**What it can do that this document originally missed:** write to
`/run/systemd/journal/socket`, which is mode `0666`. That makes it able to publish forged
anchors. See T31.

### A3 — A malicious or compromised application on the phone

An ordinary Android app with write access to shared storage. It cannot escape its own
sandbox, but it can create entries inside the media tree — including a symlink at
`/sdcard/Pictures/x` pointing at `/data/data/com.something/databases/`.

This is a real adversary, not a hypothetical, and it is the one the volume pin and the
symlink refusal exist for. A broker that validated only the requested path string and read
whatever came back would have an allowlist that any app on the device could step around.

### A5 — Whoever controls the release artifact

New on 2026-08-01, and new because the software changed rather than because the analysis
improved. Until tagged releases existed, every operator compiled the binary from a checkout they
could read, and the only way to ship them different code was to change the source. That is the
premise §6.6 rested on, and it is gone: the consumer is now told to download a binary it did not
build, from a host neither it nor this project controls.

The adversary is anyone who can put bytes where a consumer will fetch them — a compromised
maintainer account, a compromised Actions runner, a GitHub-side compromise, or anything on the
network between the release and the download.

What makes this adversary worth its own entry rather than a footnote to A2 is *reach*. A2b can
already overwrite the installed binary on one host, having got onto it. A5 substitutes code on
**every** host that installs, before any of them has been touched, and the substituted binary is
subject to none of the controls in this document — it is the thing that was supposed to enforce
them. Every threat in §4 is answered by code, so an adversary who chooses the code answers
nothing.

### A4 — The environment, behaving badly without malice

A replug that renumbers the transport, a storage remount that reassigns `dev`, an adb
upstream release that rewords a `FAIL` message, a depth-limited configuration, a device
whose `adbd` predates the V2 sync commands.

Not an adversary, but it exercises the same paths and produces the same class of outcome —
a confident, wrong, silent answer. The controls are shared, so it is modelled here.

---

## 4. Threats and the controls that answer them

Grouped by asset. **Evidence** is `measured` where `adb_experiment.md` demonstrates the
device behaviour the threat depends on, `judgement` where the rule is retained on prudence.

### 4.1 Reaching storage outside the media tree

| # | Threat | Control | Evidence | Residual |
|---|---|---|---|---|
| T1 | Caller names a path outside the allowlist (`/data/data/...`) | Compiled six-root allowlist; `ParseAuthorizedPath` is the only constructor for a path the storage layer will accept | measured (roots exist; `adbd` stats `/data` freely) | None from A1 |
| T2 | Caller widens authority via flag, env var or config file | No input can widen. A config file may only *narrow*; an entry not already under a compiled root is a startup error | judgement (design rule) | Editing source and rebuilding — attributable, and see §8.2 |
| T3 | Caller reaches the same bytes under `/storage/emulated/0/…` | Refused, and deliberately **not** resolved | measured (three spellings, one inode) | **This is not an authority boundary.** The bytes are reachable under the accepted spelling. It is a canonicalization rule; its value is in T11 |
| T4 | Path-form tricks: `..`, relative paths, trailing/doubled slash, NUL | Rejected before anything else looks at the path | measured — each form tested against the device; `..` genuinely escapes upward, relative paths resolve with cwd `/` | None for the forms tested |
| T5 | Prefix confusion: `/sdcard/Download-private` | Comparison is over path segments, never string prefixes | measured (`error=2`, so the device would have answered) | None |
| T6 | An app plants a symlink in the media tree pointing at `/data` | **One** control, not two: the kind check. `LIST_V2` dirents carry `lstat` semantics, so non-regular/non-directory entries are omitted and never followed | measured (`LST2` does not follow symlinks, `STA2` does) | TOCTOU — see T7. **The `dev` check does not help here** — see §5.7 |
| T7 | The file is swapped for a symlink between `LST2` and `RECV` | None available. `RECV` follows symlinks and the protocol offers no `openat`-style handle | measured (`RECV` necessarily traverses two symlinks on every read) | **Accepted, signed off 2026-07-31 — see §5.8.** Requires code execution on the phone timed against the broker; such an adversary has better options |
| T8 | A bind mount inside the tree introduces a foreign filesystem with no symlink anywhere | The `dev` pin catches it; a string rule never could | judgement (mechanism follows from the measured `dev` values) | None known. **This is the only threat the `dev` check uniquely answers** — see §5.7 |
| T9 | The device returns a directory entry naming something outside the tree | Device-supplied paths are re-parsed through `ParseAuthorizedPath` **and** `dev`-checked on the return path | measured (`adbd` applies no confinement) | None known |
| T10 | The broker is used as a general remote-execution channel to the phone | There is no shell. The outbound vocabulary is a compiled constant: six host services plus `LST2`, `STA2`, `LIS2`, `RECV`. `shell:`, `exec:`, `SEND`, `root:`, `tcpip:`, `reverse:` are never sent | judgement (design rule, enforced by construction) | A source edit and rebuild — again attributable |

T3 deserves the emphasis it gets in the table. An earlier draft of the spec implied the
single-spelling rule was itself containment. It is not: all three spellings reach the same
inode, so refusing two of them denies access to nothing. Keeping it is still correct, but
for the audit reason below, and misplacing the trust would leave the real boundary — the
allowlist plus the volume pin — carrying more than it was credited with.

### 4.2 The audit record

| # | Threat | Control | Evidence | Residual |
|---|---|---|---|---|
| T11 | The log describes an operation other than the one performed | NUL rejection (the device truncates at the NUL and would act on a shorter path than the one validated and logged); one accepted spelling per directory; `path_b64` as the authoritative path field | measured — `/sdcard/DCIM\x00x` returns the inode for `/sdcard/DCIM` | None for the forms tested |
| T12 | A record is edited, reordered, or removed from the middle | `hash_n = SHA-256(hash_{n-1} ‖ canonical(record_n))`, with byte-exact specified serialization | judgement | Detection only, not prevention |
| T13 | The tail is truncated, or the whole file deleted and a shorter valid chain recomputed | The chain head is anchored to the systemd journal, under a stable `MESSAGE_ID`, in a sink the broker cannot rewrite. A log recreated from nothing anchors its empty chain at seq 0 before any device contact, so even a reset that is never appended to leaves a mark | measured — anchor round-tripped with its custom fields intact, 2026-07-31; seq-0 creation anchor added 2026-08-01 | Local root can rewrite both sinks — §5.1. **Detected by `verify`, not at startup** — see §5.6, and note the horizon set by journald retention (spec, open question 9). Since the log is now owned by the account that writes it, deletion is cheap for A2b and the anchor is the only thing that notices |
| T31 | A forged anchor is published to make a truncated chain verify | `verify` accepts only anchors whose journald-stamped `_UID` is the uid it runs as and whose `_EXE` is the running binary's path; everything else is discarded | **measured — a well-formed anchor carrying the real `MESSAGE_ID` with a fabricated seq and hash was published from an ordinary uid, and is now permanently in this host's journal** | **None from A2a; the control is defeated outright by A2b.** `_UID` still cannot be influenced by the sender, but since 2026-08-01 it names the backup account rather than a service account, so on this host it discards nothing (measured: all 3,652 anchor entries carry `_UID=1003`) and `_EXE` carries the filter alone — see §5.5 |
| T14 | The caller suppresses the record by discarding stdout/stderr | Neither stream is the audit trail. The record's contents come from the operation, not the invocation | judgement | None from A1 *as a caller*. A1 that is also A2b can write the log file directly, which is a different threat (T12/T13) rather than suppression |
| T15 | A denial goes unrecorded | Denials are logged with the same weight as successes, no sampling | judgement | None |
| T16 | The audit extension is not wired, so nothing is written | The log is opened and its head verified in `main`, **before** the bus is constructed. Wiring the extension is not what makes the log exist | judgement | None from a wiring mistake; see §5.2 |
| T17 | The log cannot be opened, or its head does not verify | `audit_unavailable`, exit, no device contact | judgement | Availability — deliberately, §7.1 |
| T18 | Device identity in the log is unstable or forgeable | Serial only. `usb:` path and `transport_id` are never logged as identity | measured — across a port change the serial was stable while `usb:1-1`→`usb:1-2` and `transport_id` 2→3 | `transport_id` reuse could address a different phone; not logged, so moot |

### 4.3 Archive correctness

| # | Threat | Control | Evidence | Residual |
|---|---|---|---|---|
| T19 | A failure is misclassified and a run continues past a condition that should stop it — or aborts on one that should not | Error codes derive from `errno`, the `host:devices` state token, and a single isolated `FAIL`→code table with a test per string | measured — four distinct prose strings catalogued; `errno` 0/2/13 observed | An upstream rewording breaks one table rather than leaking into behaviour |
| T20 | A >4 GiB file reports a wrong size, silently disabling the incremental path | `STAT_V2`/`LIST_V2` required; a device lacking them is refused with `unsupported`, with no fallback and no degradation | measured — 64-bit size round-tripped exactly; V2 present on the target | Refusing to run is the intended failure |
| T21 | The capability check passes against a device that does not support V2 | Features **must** be read from `host-serial:<serial>:features` | measured — `host:host-features` reports `stat_v2`, `ls_v2`, `sendrecv_v2` **with no phone attached at all** | A check that can never fail is the worst kind; naming the right service is the whole control |
| T22 | A `LIS2` reader desyncs and reports empty directories | The terminating `DONE` carries a 72-byte zeroed body that must be consumed; explicit test required | measured — hit during discovery, presented as *"all these directories are empty"* | None once tested |
| T23 | A transfer is truncated and the short file is archived as complete | Header/raw-bytes/trailer framing: exactly `size` bytes then a required trailer; `sha256` of forwarded bytes | measured — byte count matches listing size exactly; chunks are 64 KiB | **Not** end-to-end device verification. The broker never re-reads the device, and `--verify-device` was removed because hashing on the phone needs a shell |
| T24 | An empty file is treated as a failure | Zero `DATA` packets is success | measured — one such file exists on the device | None |
| T25 | The run hangs forever | Deadlines on every read and write | measured — an over-sized length prefix blocks with no reply, no timeout, ever | None |
| T26 | `mtime` is "corrected" and every cheap-path comparison breaks | `mtime.Mtime` wraps `int64` seconds and exposes no timezone conversion, no `time.Time`, no arithmetic | measured — camera files and screenshots disagree about what `mtime` means | The helpful mistake is not available to write |
| T27 | A non-UTF-8 filename is silently never archived | `path_b64` is MUST and authoritative; `path` is lossy and for humans | **judgement, not measured** — Stage 1 walked all six roots to unlimited depth, 48,704 files, zero non-UTF-8 names (`phase3_device_findings.md` §6) | **Accepted on prudence, signed off 2026-07-31 — see §5.9.** Cost of the check is nil; cost of being wrong is a silently unarchived file |
| T28 | A depth-limited run reports a phone with no photos, successfully | Documented: all six roots have zero regular files at the top level | measured — 7 entries in `DCIM`, 8 in `Movies`, all directories | Not an error condition, so only documentation and a test guard it |
| T29 | `ENOENT` is reported as proof a tree is gone | It is not authoritative — `adbd` returns `error=2` for paths it can see but not read | measured (`/data/data/com.android.providers.media`) | Affects wording shown to a human |
| T30 | A fixture binary in a production path bypasses the allowlist | Fixture mode is behind a build tag, absent from the release binary, produces a differently-named binary, and reports a `+fixture` version visible in the first `probe` and in the audit log | judgement | The allowlist still applies to virtual paths, so a fixture binary is not itself an escape — only a remap |

---

### 4.4 The binary itself

New with A5. The asset here is not the phone, the log or the archive — it is the code that
protects all three, so a threat that lands here defeats §4.1 through §4.3 at once without
touching any of them.

| # | Threat | Control | Evidence | Residual |
|---|---|---|---|---|
| T32 | The published artifact is not what this source builds — a substituted binary, or a compromised runner | **Reproducibility.** A clean clone at the tag plus `make dist VERSION=<tag>` produces the published bytes exactly, so anyone can rebuild and compare without trusting the publisher. Plus a signed SLSA v1 provenance attestation binding each artifact to the workflow, ref and commit that produced it; plus the release workflow's own guards — the tag must descend from `main`, and `check-artifact.sh` refuses to publish a binary that misreports its version, its commit, or a clean tree | **measured, 2026-08-01 on `v0.1.0-rc1`** — rebuilt from a fresh clone on a different machine, byte-identical for both architectures; `gh attestation verify` exits 0 for both and names `.github/workflows/release.yml @ refs/tags/v0.1.0-rc1` at `a336b59` | **Detection, and only if someone looks.** Neither control fires by itself. The attestation proves *where a binary came from*, never that the source it came from is honest — an adversary who commits to `main` gets a perfectly valid attestation. Reproducibility is the stronger of the two precisely because it needs no trust, and the weaker in practice because nobody runs it |
| T33 | A consumer installs a different artifact than the one it was written against — a substitution in transit, or version drift | The consumer embeds the expected SHA-256 for the **pinned** version and verifies before installing, offline, with nothing but `crypto/sha256`. Never `latest`. See `ADB_BROKER.md` → **The consumer install contract** | judgement | The digest ships inside the consumer, so an adversary who can edit the consumer defeats it — but that adversary has no need of the broker. TLS is *not* relied on here |
| T34 | The installed binary is replaced after it is installed | **None.** | — | **None, deliberately.** This is A2b, and §5.5 already accepts it: the binary and the account that could overwrite it are the same uid. A digest checked at install time says nothing about the file a minute later |

## 5. Where controls stop

Stated plainly, because a control credited with more than it does is worse than no control.

### 5.1 Local root defeats every control here

Root can rewrite the audit log and the journal, replace the installed binary, and read the
phone with its own copy of `adb` without involving this binary at all. The anchor raises the
bar from *"any local user with a text editor"* to *"tampering with two independent sinks
consistently"* — which is the entire claim, and it is not a claim of resistance.

Since the setuid install was withdrawn, the account that runs the backups clears that bar too,
without being root: it owns both the log and the binary whose `_EXE` the anchor filter selects
on. §5.5 splits A2 accordingly. This section is still about root, which additionally reaches
*every other* account's chains and the journal itself; it is simply no longer the only
adversary the audit log fails against.

The honest answer against a root adversary is an off-box sink. It is deferred (spec, open
question 3) because it would put network access into a binary that currently has none, and
that trade is worth making deliberately.

### 5.2 The confinement/extension split is a real distinction, not a stylistic one

Confinement lives in the core `Business` type; audit logging is an extension. The asymmetry
is deliberate: a decorator can be omitted at wiring time, and a wiring mistake must not be
able to disable the allowlist. Audit logging survives the same mistake only because the
fail-closed check runs in `main` before the bus exists. If that check is ever moved or made
conditional, audit logging inherits the weakness the extension pattern has and the split
stops being justified.

### 5.3 The type system carries confinement; the runtime carries the volume pin

`AuthorizedPath` makes "fetch a path that was never checked" fail to compile. The `dev`
check cannot work that way — it depends on a value that only exists once a device is
reachable — so it gets its own unforgeable type (`Volume`, constructible only by the
resolver that performed the `STA2`) and both are required by every `Storer` method. The
guarantee is structural in both halves, but by two different mechanisms, and only the first
is checked by the compiler alone.

### 5.4 `ino` is provenance, not a control

The pin enforces `dev` only. Enforcing `ino` would defend against `/sdcard` being
re-pointed at another Android user's storage — which requires privilege on the phone, and a
compromised phone is out of scope. It is recorded in the audit log because the log's job is
to answer *what did this binary read*, and nothing branches on it.

### 5.5 The anchor is now the only audit control, and half its filter stopped working

This section was already the most load-bearing in the document. Since 2026-08-01 it is the
whole of §4.2's protection, and its own basis has narrowed. Both changes are stated here
together because reading either one alone gives the wrong impression.

**The anchor is now the only control.** The withdrawn install put two kernel-enforced controls
in front of the log — an owner the caller was not, and `chattr +a` the caller could not remove.
Both are gone (`ADB_BROKER.md` → **Installation**). The log is an ordinary file owned by the
account that writes it. Prevention is not narrower than it was; it is absent. Everything in
§4.2 rests on detection, and detection rests here.

**Half the filter stopped discriminating.** The journal socket is world-writable, so
`MESSAGE_ID` proves nothing about who wrote an anchor — anyone can write one, and one forged
during the experiment is in this host's journal permanently. `_UID` cannot be forged: journald
derives it from the sending socket's credentials. But it is now the *backup account's* uid
rather than a service account's, and the measurement is blunt about what that costs. Every
anchor-carrying entry on this host, counted 2026-08-01:

```
3,652 entries with the broker's MESSAGE_ID
  _UID=1003 on all 3,652 — including the forged one
  _EXE across ~100 paths: broker.test, deviceaudit.test, adb-broker-fixture,
       /usr/bin/python3.12, /usr/local/bin/adb-broker
```

`_UID` discards none of them. `_EXE` discards all of them. The filter has two halves and one
of them is doing all the work — and it is the half an adversary running as the backup account
defeats by overwriting a binary it owns.

So state it by adversary:

- **A2a** (any other uid): unchanged. It cannot set `_UID`, so it cannot publish an anchor
  this filter accepts. The control holds exactly as it did.
- **A2b** (the backup account): defeated. Right `_UID` for free, right `_EXE` by writing to
  its own `~/.local/bin`. Against A2b an anchor is not evidence, and nothing here pretends
  otherwise.

**One thing the retreat improves, which belongs next to what it costs.** Under the setuid
install the anchor was not merely narrower — it was, as far as anyone measured, absent. Stage 2
ran the installed binary end to end and found no anchor had ever been published by the service
account (`phase3_device_findings.md` §8; undiagnosed, one candidate being that `SOCK_DGRAM`
sends from a setuid process are dropped). T13 and T31 were therefore documented controls with
no observed instance behind them. Running as the invoking user is the configuration in which
anchoring is measured working, thousands of times over. A control whose filter is half as
discriminating but which actually fires is worth more than one that does not.

**Why the rest is accepted.** A2b can already read the phone directly — §8.1, measured, ten
lines of socket code — and can delete the log outright. There is no version of this design in which
A2b is held off by anything short of the privileged install, and the privileged install is what
the archive could not afford to depend on. The trade is stated in full at
`ADB_BROKER.md` → **Installation**: an audit control that survives a laptop rebuild and detects
tampering by everyone else beats one that also resists the backup account but stops being
installed.

**What still holds, and must keep holding.** The anchor remains trustworthy exactly insofar as
the filter is applied. Drop it and the control inverts — it accepts every anchor, including the
adversary's, which is worse than no anchor at all because it produces a confident pass. That is
the `host:host-features` failure shape from T21, a check that cannot fail, and it gets the same
treatment: a test whose fixture is the forged anchor itself. That test is now more important
than it was, not less, because `_EXE` is the only half of the filter it can still exercise.

`_AUDIT_LOGINUID` is also stamped by journald and recorded. It is the most interesting field
for forensics — it names the login session behind an invocation — and with `_UID` no longer
discriminating, it is the one that most often distinguishes a real run from a same-uid forgery
after the fact. It is not a control: nothing branches on it.

### 5.6 Startup detects a rewritten tail; only `verify` detects a removed one

The fail-closed startup check re-hashes the tail record. It does not consult the journal.

The reason changed on 2026-08-01 and the conclusion did not. It used to be an authority
question: consulting the journal meant granting the broker's service account
`systemd-journal`, read access to every service's logs on the host, bought for a read-only
check on a hot path. Running as the invoking user removes that entirely — the user can read
its own anchors by ACL, measured. What remains is cost: `foundation/journal` walks the entry
array linearly, `O(all journal files)` per read, and a first-ever run performs roughly 20,000
operations. A startup check that slow is one that gets turned off.

The consequence is a real, named gap: a truncated chain recomputes cleanly, so startup passes
on a log whose most recent records were removed. Closing it is `verify`'s job, which is why
`verify` belongs in monitoring on a schedule rather than being reached for after something
already looks wrong. A control that only runs when someone suspects a problem is not
protecting the period nobody was suspicious.
### 5.7 The kind check and the `dev` check answer different threats, not the same one twice

Earlier revisions of this document and of the spec credited T6 to "two independent checks",
implying the kind check and the `dev` check were redundant defences against a planted symlink.
They are not, and the measurements already in `adb_experiment.md` show why.

A `LIST_V2` dirent carries `lstat` semantics, so for a symlink the reported `dev` is the
filesystem holding the **symlink inode**, not its target:

```
LST2 /sdcard  ->  SYMLINK  dev=65034      (root filesystem — where the link lives)
STA2 /sdcard  ->  dir      dev=190        (media volume — where it points)
```

A symlink planted at `/sdcard/Pictures/x` therefore has its inode on the media volume and
reports `dev=190`, matching the pin, regardless of where it points. The `dev` check passes it.

| Threat | Control that catches it | Control that does not |
|---|---|---|
| T6, a planted symlink | The kind check, alone | The `dev` check |
| T8, a bind mount | The `dev` check, alone | The kind check — a bind mount is a genuine directory |

So each control is load bearing and unsubstitutable, and neither has a spare. The practical
consequence: **removing the kind check as "redundant with the `dev` check" would make symlink
escapes reachable**, and nothing else in the design would stop them. The reverse holds for
bind mounts.

This does not weaken T6 — a rule that refuses every symlink outright, without reasoning about
where it points, is the strongest form the control could take. What was wrong was the claim of
redundancy, which would have made either check look safe to drop.

Found while writing fixture mode: a local tree has no bind mount constructible without root,
so reproducing the wire store's Lstat-only `dev` check faithfully would have left that check
with no reachable test — which is what prompted looking at what it actually catches.

### 5.8 Sign-off, 2026-07-31 — T7 is accepted, and cannot be tested from the host

The phase-3 verification plan requires this to be a decision rather than an omission, so it is
recorded here rather than left as a bare "Accepted" in a table cell.

**What is accepted.** An adversary who can run code on the phone, timed against the broker's
own request sequence, can substitute what a validated path resolves to between the `LST2` that
named it and the `RECV` that reads it — swapping the regular file the listing saw for a symlink
(or a different file) an instant before the read follows it. The broker will forward whatever
bytes come back, labelled with the path it validated, hashed and recorded as if they were the
bytes `LST2` described.

**Why it cannot be tested.** Reproducing this race requires planting a binary on the phone and
firing it at the moment between two specific sync-protocol exchanges — that is code execution on
the device. Granting a test harness that capability and granting it to nothing else is not
available: the whole reason this transport was chosen is that the broker never opens a shell or
`exec:` channel to the phone, for anyone, including its own test suite. §8.5 already records this
plainly: the case "needs a fixture that does not exist on this device." There is no host-side
substitute for a race that only exists on the device's clock.

**Why the risk is accepted rather than merely unaddressed.** The question that matters is not
whether the race exists — it measurably does, `RECV` necessarily traverses two symlinks on every
read — but what it hands an adversary who could not already get the same thing more directly.
An attacker capable of timed code execution on the phone already has read and write access to
its own app sandbox and to whatever shared storage will give it, which is most of what winning
this race would buy. The broker's own controls still bound what is left:

- **The volume pin is re-checked per step, not once per run.** `Volume.Contains` gates every
  `dev` seen on every step of a fetch, so a substituted target still has to resolve to the
  media volume's `dev` — it cannot pivot the race into `/data` or the root filesystem through
  this binary. The race can swap *which file on the media volume* is read; it cannot use this
  binary to walk off the volume.
- **The symlink refusal below the root (§5.7) still governs what was ever listed.** The kind
  check that makes T6 refuse a planted symlink outright is evaluated at `LST2` time, before the
  race window opens. T7 is specifically about what changes *after* that check ran, which is why
  it is a distinct threat rather than a second way to defeat the same one.
- **The trailer digest is computed over the bytes actually forwarded.** Whatever `RECV`
  returned, that is what was hashed and logged — the audit record does not claim the broker read
  what `LST2` promised, only what it forwarded in this invocation.

**What is NOT covered — stated plainly.** The trailer digest is not end-to-end device
verification. It proves the broker forwarded what it received from `RECV`; it proves nothing
about whether that matches what `LST2` reported earlier, because the broker never re-reads the
device to check the two against each other. `--verify-device` was removed for the identical
reason this race cannot be closed (§7.4): verifying on the phone needs a shell, and a shell is
the one channel this design refuses to open. So the residual exposure is real and is not
papered over by the hash: within the media volume, a substitution timed against the broker's
own request sequence is undetectable by this binary, and the record it produces will be
internally consistent and wrong.

**What would change the answer.** A sync-protocol primitive with `openat`-then-read-by-handle
semantics — pinning the byte range read to the inode that was stat'd, rather than re-resolving
the name at `RECV` time — would close this, and nothing in the current adb sync vocabulary
offers it. Short of a protocol change, or moving off this transport entirely (§6.1's premise),
the answer stands as accepted.

### 5.9 Sign-off, 2026-07-31 — T27 stays on prudence; the negative result is strong but not proof

Recorded here as a decision rather than a default, per the phase-3 verification plan.

**What is accepted.** `path_b64` remains MUST and authoritative, and `path` remains lossy and
for humans only, on the strength of an argument rather than an observed non-UTF-8 filename.

**The evidence, cited rather than restated.** The Stage 1 device run walked all six allowlist
roots to unlimited depth and found **48,704 regular files, zero non-UTF-8 names, zero symlinks,
zero per-path errors** (`docs/phase3_device_findings.md` §6). That same document's "Still
untested" list is explicit about what this does and does not establish: "None found among
48,704, up from the discovery run's sample. The `path_b64` rule stays justified by prudence, and
this is now a much stronger negative result." A strong negative result over a large sample is
still a negative result — it describes this device, on this day, with these apps installed, and
it says nothing about a different device, a different locale, or a different app writing a name
that does not decode as UTF-8 tomorrow.

**Why prudence is the right basis, not a weaker one.** Android filenames are byte strings by
specification, not by convention — nothing in the platform guarantees UTF-8, so the absence of a
counterexample here is a fact about this sample, not about the platform. The rule is kept
because it costs nothing to keep: `path_b64` is computed for every entry regardless, and a
consumer that decodes `path_b64` cannot construct a request for a file that does not exist —
round-tripping through base64 never requires the underlying bytes to be valid UTF-8. There is no
version of "drop the rule" that saves real cost, so 48,704 files with no counterexample is not a
reason to relax it. It would only be a reason to relax it if keeping `path_b64` were expensive,
and it is not.

**What would change the answer.** Finding one non-UTF-8 name — on this device or another —
would convert this from a prudence rule into a demonstrated requirement; that strengthens the
decision, it does not reverse it. What would actually force a revision is a real cost to
carrying `path_b64` (a downstream consumer that cannot decode it, or a size constraint on the
field) — nothing of that kind is known today.

---

## 6. Explicitly out of scope

Each of these is excluded on purpose. Where exclusion would change if circumstances
changed, that is said.

### 6.1 A compromised `adbd`, or a rooted phone

If the device lies about `dev`, about dirent kinds, or about what a path resolves to, every
control in §4.1 rests on a false premise. Nothing in this design detects that, and nothing
can over this protocol.

### 6.2 Anyone reading the phone without using this binary

The goal is that *this binary* is not the instrument, and that its own history is not
rewritable. It is not that the phone is unreachable from the host. A separate copy of `adb`,
or a rebuilt copy of the broker with its checks removed, reads whatever the device will
serve.

What the controls still buy under that adversary is narrower than it was, and the wording has
to change with it. This paragraph used to say such a copy **cannot open the audit log** (wrong
uid) and **cannot unlink it** (root-owned directory). Since 2026-08-01 that is true only of
A2a. A rebuilt copy run by the backup account can do both.

What survives for every adversary is weaker and still worth having: an unrecorded read stays
unrecorded — no copy can make the log claim it did *not* happen, because the log never claimed
completeness — and an erased or shortened log is detectable against the anchors by anyone the
`_UID`/`_EXE` filter does not admit. The log remains truthful about what the deployed broker
did, for as long as the deployed broker's own account is not the adversary. It was never a
complete record of what happened to the phone.

**This exclusion was mis-scoped as root-only; corrected in `ADB_BROKER.md`.** It is reachable
by A2 with a socket call and no privilege whatsoever — measured, §8.1. That makes this the
widest exclusion in the document, and the one most likely to be misread as narrower than it
is.

### 6.3 Physical access to the phone, and the USB path

An unlocked phone in someone's hand, a malicious USB host, or interception on the cable are
all outside this design. USB debugging authorization is the device's control, not the
broker's; the broker reports `unauthorized` and stops.

### 6.4 Everything downstream of the handoff

Once bytes leave the broker's stdout, their confidentiality and integrity are `photos`'
problem. The staging file, `O_EXCL`, the refuse-to-overwrite guarantee and the archive at
rest are all outside this boundary — the broker never writes to the local filesystem except
appending to the audit log.

### 6.5 Denial of service against the phone or the run

The broker is a read-only client that a caller can invoke in a loop. Nothing rate-limits it,
and nothing needs to: the caller already has whatever access it would abuse.

### 6.6 Supply chain — no longer wholly out of scope

**This section said the opposite until 2026-08-01, and it was not wrong when written.** It read:
"Nothing in the design verifies that the installed binary was built from reviewed source — no
signature, no reproducible build, no attestation." All three clauses are now false. Tagged
releases publish a SLSA v1 provenance attestation, and the build reproduces byte-for-byte from a
clean clone at the tag (measured on `v0.1.0-rc1`). The old text is quoted rather than deleted
because what changed is the software, not the analysis: until releases existed, every operator
compiled from a checkout they could read, and there was nothing for a supply-chain control to
protect.

What is in scope now is A5 and T32–T34 in §4.4. What remains out of scope:

- **The toolchain and the runner.** A compromised Go toolchain, a compromised GitHub-hosted
  runner image, or a compromised `actions/*` action produces a correctly attested artifact. The
  actions are pinned to major versions, not digests, which is a deliberate cost/benefit choice
  and not a claim that it is safe.
- **Whether the source is honest.** No control here distinguishes reviewed source from source an
  adversary committed. That is what §8.2 is about and it is unchanged — provenance answers
  *where a binary came from*, never *whether the thing it came from should be trusted*.
- **The consumer's own supply chain.** The embedded digest is only as good as the consumer
  binary carrying it.

So the honest summary is narrower than "we do supply chain now": a release can be tied to a
commit and a workflow, and independently rebuilt by anyone who cares to. Nothing forces anyone
to check either, and nothing vouches for the commit.

### 6.7 Confidentiality of the audit log

The log records paths — which are personal data on a personal phone. It is mode `0640`, so
it is not world-readable, but no stronger protection is specified and log confidentiality is
not a goal of this design. Worth knowing before it is shipped anywhere.

---

## 7. Deliberate trades

### 7.1 Availability is sacrificed for auditability

A broken audit path cannot back up photos. That is the intended behaviour: an unauditable read
of the phone is exactly the thing being prevented, and a control that disengages under pressure
is not a control. `audit_unavailable`, `volume_unresolved` and `unsupported` all abort rather
than degrade, and asset 3 — archive correctness — outranks getting a run to finish.

The 2026-08-01 retreat pays down one case of this that was never a good trade. "Misconfigured
install" used to include *no install performed yet*, so a rebuilt host aborted every run until
someone ran a root script. Availability was being spent there on nothing: an absent log is not
an unauditable read, it is a first run. The broker now creates the log and anchors its empty
chain (`ADB_BROKER.md` → **Fail closed**). Every other abort in this section stands unchanged —
what is refused is a log that cannot be opened, appended to, or recomputed, which is a real
failure to record rather than an absence of history.

### 7.2 Refusing to resolve, rather than resolving carefully

Alternate spellings are refused rather than canonicalized, because path-resolution logic is
where confinement bugs live. A guarantee with no moving parts beats a correct one that has
some.

### 7.3 Refusing all symlinks below the root may be too blunt

It costs nothing today — zero symlinks among 48,704 files, measured across all six roots to
unlimited depth (`docs/phase3_device_findings.md` §6; the earlier 1,778 was the discovery
run's bounded sample). A future device shipping a
legitimate one shows up as *missing files*, not as an error, which is the failure direction
this tool exists to prevent. The `list` summary counts refused non-regular entries
specifically so the cost is visible rather than silent. Still genuinely open (spec, open
question 4).

### 7.4 End-to-end verification given up to keep the shell channel closed

`--verify-device` would require running `sha256sum` on the phone, which requires a shell
channel, and a binary that can execute one command on the device can execute any. The
trailer digest plus an exact byte count is what remains.

---

## 8. Open questions

Ordered by how much they change the model.

### 8.1 ~~Does reaching the adb server actually require root?~~ Answered: it requires nothing

`ADB_BROKER.md` excludes *"an adversary who is already root on the host and simply reads the
phone with their own copy of `adb`."* The adb server listens on `127.0.0.1:5037` — a TCP
socket with no peer-credential check — so on the face of it **any local process that can
open a loopback connection can speak the sync protocol directly**, root or not. That is the
same A2 adversary the document says is *in* scope.

If that is right, the bypass in §6.2 costs an adversary nothing but a socket, and the spec's
wording overstates the barrier. It does not change any control — the controls were never
about protecting the phone from the host — but it does change what should be claimed for
them, and the claim as written is the kind that gets quoted later.

**Answered, measured 2026-07-31: no. It requires nothing.**

```
ss -ltnp            ->  LISTEN 127.0.0.1:5037  users:(("adb",pid=29995,fd=9))
                        server running as uid 1003, an ordinary user, not root
as uid 1003         ->  host:version  ->  OKAY
as nobody (65534)   ->  host:version  ->  OKAY
```

`nobody` has no relationship to the server's owner, so this is not a same-uid effect: adb
performs no peer-credential check on a TCP socket and nothing in its protocol authenticates a
client. **Any local process can speak the sync protocol directly** and read whatever the
device serves, in about ten lines.

`ADB_BROKER.md`'s exclusion is corrected accordingly, and §6.2 is reachable by A2 by
measurement rather than by argument.

Three consequences worth separating, because they pull in different directions:

1. **No control in this document changes.** None of them was protecting the phone from the
   host; §1's first asset is explicitly *unreachable through this binary*, not unreachable.
   The claim to make is the weakest honest one: the broker confines itself, not the phone.
2. **The caller group bought less than its name suggested — and was withdrawn for it.**
   Restricting execution to `adb-broker-clients` never restricted who could read the phone;
   nothing does. It restricted who could produce a *broker-attributed* read and who could
   append to the audit log at all, which was worth having but was not phone confinement and
   should never have been credited as any. On 2026-08-01 the whole privileged install went,
   this measurement being the main reason: a control that costs a root-run step on every host
   rebuild has to be buying more than log hygiene to be worth the ritual. See
   `ADB_BROKER.md` → **Installation**, and §5.5 for what is left.
3. **The bypass is closable, but not by this binary.** adb can be made to listen on a unix
   socket instead (`ADB_SERVER_SOCKET=unix:…`), at which point file permissions gate access
   and the bypass becomes a group membership rather than a socket call. That is host
   hardening, outside the broker — and it collides with the spec's rule that the server
   address is compiled in and not configurable, since the broker could then no longer reach
   it. Recorded as §8.6 rather than decided here.

The corollary relied on elsewhere still holds and is now measured: because the socket needs no
group membership, the broker needs none either — which is why the withdrawn `install.sh`
granted it nothing for adb access, and why the current install can grant nothing at all and
lose no capability. The broker reaching the adb server has never depended on privilege, and
that is precisely what made the privileged install droppable.

### 8.2 What makes "edit the source and rebuild" attributable?

T2 and T10 both fall back on it. Nothing specified establishes it: there is no signing, no
build provenance, and `make install` is a root-run step with no stated policy about who may
run it. If the answer is *"the repository is reviewed and only root installs"*, that is a
fine answer, but it is an assumption about the operating environment and it belongs written
down next to the controls that lean on it.

**Narrowed 2026-07-31, then widened again 2026-08-01.** `zarf/install.sh` briefly made two
parts of the environment explicit rather than assumed: root was required, and the set of uids
permitted to execute the broker was an enumerated group that `verify-install` reported. Both
went with the install.

So the question is now open at full width: *who may install* is whoever owns the account, and
*what was built* is unestablished. The only attribution left for T2 and T10 is `_EXE` on the
anchors, which says which path published a chain head and nothing whatsoever about what was
compiled into it.

One qualification, because the loss here is smaller than it looks and the fix is cheap. Stage 2
added a provenance check: `verify-install` read Go's VCS stamp and failed on a binary built
from a modified tree (`phase3_device_findings.md` §8). The *stamp* is still there — the Go
toolchain embeds it, and nothing about the retreat removes it. What went is the thing that read
it. Restoring that costs a subcommand or a line in `probe`, needs no privilege, and would
answer more of this question than the service account ever did.

This is the sharpest cost of the retreat that is *not* offset by §8.1's measurement, and it is
recorded as an open question rather than dressed up. If it ever needs answering, the answer is
build provenance, not the reinstatement of a service account — the two were never the same
control, and pairing them is what made the old install look like it addressed this.

### 8.3 Off-box anchoring

Deferred (spec, open question 3). Worth revisiting only if local root enters scope — at
which point most of §4.2 needs rethinking, not just the anchor.

### 8.4 Allowlist completeness

Six roots, all confirmed to exist; whether the set is *complete* is open. Note the direction
of the risk: an incomplete allowlist threatens asset 3 (files silently never archived), not
asset 1. Widening it is a security decision; narrowing it is a data-loss one. They should not
be reviewed with the same reflex.

### 8.5 Untested cases that touch this model

From `adb_experiment.md`, still unmeasured: a `LIS2` stream large enough to stress the
reader, any non-UTF-8 filename (none exists here to find), a mid-transfer `RECV` failure
after `DATA` has flowed, and `RECV` on a final component that is a symlink pointing outside
the root — the T7 TOCTOU case, which needs a fixture that does not exist on this device.

### 8.6 ~~Should the adb server be moved to a unix socket?~~ Declined 2026-08-01

Following from §8.1: `ADB_SERVER_SOCKET=unix:<path>` would put file permissions in front of the
server, turning the bypass from a socket call into a group membership. It would be the single
largest reduction in A2's capability available on this host, and it is entirely outside this
binary.

**Declined, on the same grounds that withdrew the privileged install**, and recorded as a
decision rather than left open, because leaving it open is what this section warned against.

The reasoning is not that it would fail. It would work. It is that it is the same shape of
control as the one just abandoned, and it fails the same test:

- **It is host configuration that must be re-applied on every rebuild.** A `journald.conf`-era
  ritual, and one that also reaches every other adb consumer on the machine, so re-applying it
  is not a private act with private consequences.
- **It would drag the broker along with it.** The spec compiles `127.0.0.1:5037` in and refuses
  to make it configurable, so the broker would have to compile in a unix socket path instead
  and the "one address, not configurable" property would need re-deriving. A control outside
  the binary that forces a change inside it is not outside the binary.
- **It buys nothing for the assets in §1.** It narrows who can read the phone *without* the
  broker, which §1 explicitly does not claim to protect — asset 1 is *unreachable through this
  binary*, not unreachable. Adopting it would improve a property this document has twice said
  it does not have.

The honest summary is the one at the top of `ADB_BROKER.md`'s **Why a broker at all**: this
project is a controlled, auditable path to the phone, not an attempt to be the only path. adb
is not lockable-down from here, the attempts to do so cost more than they returned, and the
value is in the narrow interface and the record it leaves.

Revisit only if §9's first bullet lands — local root entering scope — at which point this
becomes one line item in a much larger rethink.

---

## 9. What would force a revision

- Local root enters scope — most of §4.2 changes, and §5.1 becomes the document.
- The phone gains a second Android user — `ino` stops being provenance and becomes a
  control (§5.4).
- The broker gains network access for any reason — §6.5 and the entire "no exec, one
  loopback socket" posture need re-deriving.
- A persistent/daemon mode is added — the process-per-operation model is doing quiet work
  here, and a long-lived process holding a pinned volume across many callers is a different
  shape.
- `adbd` gains device-side confinement — §2's premise changes, and several §4.1 controls
  stop being the only boundary.
- The adb server is moved behind a unix socket — A2's bypass becomes a group membership,
  several claims here can be *strengthened* rather than weakened, and the spec's compiled-in
  `127.0.0.1:5037` has to change with them. Declined 2026-08-01 (§8.6); it stays on this list
  because if someone else on the host does it, this document is affected whether or not it was
  our decision.
- **A privileged install is reinstated** — §5.5 and the §2 boundary table go back to two
  controls at the log, A2 stops needing its a/b split, and §8.2 narrows again. This is the
  reverse of the 2026-08-01 retreat and the parts to restore are enumerated at
  `ADB_BROKER.md` → **Installation**.
- **The broker runs as an account other than the one that owns the archive** — the reasoning
  in §5.5 for accepting A2b assumes those are the same account and that it can already reach
  the phone unaided. Separate them and the acceptance has to be re-argued, not inherited.
- systemd changes the journal file format incompatibly — `verify` stops being able to read
  anchors, and must fail loudly rather than report "no anchors found", which is
  indistinguishable from tampering. Measured flags on this host are
  `COMPRESSED-ZSTD KEYED-HASH COMPACT`; a fourth would be a hard error by design.
- journald retention rotates away an anchor older than the window being verified — the
  truncation guarantee (T13) has a horizon nothing here sets. Unquantified.
- The broker is granted `systemd-journal` membership for any reason — the startup check could
  then compare against the journal (§5.6), but at the cost of read access to every service's
  logs on the host. The trade was declined once; declining it again should be a decision, not
  an oversight.
