# Phase 3 — Device Findings

First contact between the built binary and real hardware. Measured 2026-07-31 against the
target phone, using the compiled Go implementation rather than the Python prototype that
produced `adb_experiment.md`.

Device serials are truncated throughout, per the standing rule.

**Result: 31 of 33 device-tagged tests passed, one failed, one skipped — and both of the
latter are findings rather than bugs.**

---

## 1. The last unverified protocol assumption is now measured

`TestDeviceRecvDoneArgumentWidthIsFourBytes` **passes.**

`LIS2`'s terminating `DONE` was measured during discovery to carry a full 72-byte dirent body.
`RECV`'s was never measured, because the successful transfers in Phase 6 had no reason to read
past it, so `foundation/adbwire` assumed a 4-byte argument from adb's own client and AOSP
`SYNC.TXT`. It was the only inference-rather-than-measurement left in the codebase.

The test settles it the only way available: complete a `RECV`, then issue another command on
the same sync channel. A wrong width leaves stray bytes and desyncs the *next* operation rather
than failing the current one — the same silent shape as the `LIS2` bug that once presented as
"all these directories are empty". The following command succeeded.

**`adb_experiment.md`'s "Still untested" list no longer contains a protocol assumption.**

## 2. A 5.33 GB file exists, and it vindicates the no-fallback rule

Throughput was measured on the largest file a walk of `/sdcard/DCIM` found:

```
5,333,190,049 bytes in 2m10.1s = 39.1 MiB/s
```

Two things follow.

**The `STAT_V2`-or-refuse rule is no longer justified by a hypothetical.** The spec argued that
legacy 32-bit `STAT` would report a >4 GiB video with a silently wrong size, and that being
discovered years later is worse than a run that refuses to start. Measured: this file would
have been reported as **1,038,222,753 bytes — wrong by exactly 4.00 GiB**. The archiver's
cheap-path comparison keys on size, so it would have treated a 5.33 GB video as a 1.04 GB one
forever. There is now a real file on a real device demonstrating it.

**The Go implementation matches the prototype's throughput.** 39.1 MiB/s against the
prototype's 39.5 MiB/s, so the compiled `RECV` path costs nothing measurable over raw sockets.
As the experiment noted, this is a USB 2.0 port measurement close to saturation, not a device
or protocol limit, and it remains not a number to size anything against.

## 3. The depth-1 claim was wrong — generalized from two roots to six

`TestDeviceRootsHaveNoRegularFilesAtDepthOne` **failed**, which is the useful outcome.

The spec said "there is not a single regular file at the top level of any of the six roots".
The discovery run sampled only `DCIM` (7 entries) and `Movies` (8 entries) and generalized.
Measured across all six:

| Root | Regular files at depth 1 |
|---|---|
| `/sdcard/DCIM` | 0 |
| `/sdcard/Movies` | 0 |
| `/sdcard/Music` | 0 |
| `/sdcard/Recordings` | 0 |
| **`/sdcard/Download`** | **503** |
| **`/sdcard/Pictures`** | **47** |

**The trap is real but worse than described, because it is inconsistent.** A uniformly empty
depth-1 result is at least noticeable. What actually happens is that a depth-limited
configuration *appears to work* — `Download` and `Pictures` produce files — while silently
archiving nothing from `DCIM`, the root that matters most.

The test now reports per-root counts and asserts nothing about them: requiring zero was
asserting a property of one phone's file layout, and it would fail the moment anyone saves a
file to `Download`. What it still does is state how many roots are empty, so the trap stays
visible if it ever stops existing.

## 4. No zero-byte file exists any more

`TestDeviceRecvZeroByteFileProducesNoData` **skipped**: "no zero-byte regular file found under
the allowlist roots in a bounded walk".

The discovery run found one ("smallest file: 0 bytes → `DONE` immediately, zero `DATA`
packets"). It is gone — deleted between runs, or outside this walk's bound. The skip is correct
behaviour rather than a failure, and the zero-`DATA` handling is still covered by unit and
fixture tests, where a zero-byte file is constructed deliberately instead of hoped for.

Worth noting because it is a general lesson about this manifest: **a test that depends on a
particular file existing on someone's phone is a test that decays.** The ones that survived are
the ones that assert protocol properties.

## 5. Enumeration and per-invocation cost, measured

The spec's **Process model** section claimed to be "Measured on the real device" but its figures
appear nowhere in `adb_experiment.md`: 23,939 records, "11" source roots (this broker has six —
11 was the archiver's configured count under the pre-broker CLI adapter), 21 MB/s (the
experiment says 39.5 MiB/s), and ~10 ms process spawn. Measured properly:

| | Measured |
|---|---|
| Session setup — dial, `host:version`, `host:devices`, features, transport select, `sync:` | **4.48 ms** mean of 5 (range 2.27–7.78 ms) |
| Volume pin — `STA2` on `/sdcard` | **2.28 ms** |
| **Protocol cost before any work, per invocation** | **≈ 6.76 ms**, plus process spawn |
| Full enumeration, six roots, unlimited depth | **48,704 files in 12.87 s** |

Per root:

| Root | Files | Wall clock |
|---|---|---|
| `/sdcard/Pictures` | 25,806 | 4.42 s |
| `/sdcard/DCIM` | 20,555 | 6.95 s |
| `/sdcard/Movies` | 1,776 | 0.78 s |
| `/sdcard/Download` | 565 | 0.69 s |
| `/sdcard/Music` | 2 | 0.02 s |
| `/sdcard/Recordings` | 0 | 0.01 s |

**The real library is about twice the size the spec assumed** — 48,704 files against 23,939 —
and enumeration of all of it takes 12.9 s, which is close to the claimed ~10 s by luck rather
than by measurement.

The per-invocation figure is the one that matters and the one the spec got wrong. It is not
"~10 ms of spawn"; it is **~6.8 ms of protocol** — a dial, six host-service exchanges and an
`STA2` — *before* any spawn cost, paid on every single invocation. For a first-ever run
fetching all 48,704 files that is **≈ 329 seconds of protocol setup alone**, and the spec's
"under 3%" was arithmetic on figures that were not about this binary.

**The one-shot design is unchanged and is not in question.** It stands on lifecycle grounds —
no daemon state, no deadlock surface, no long-lived process holding a pinned volume across
callers — and that argument does not depend on the overhead being 3% rather than 8%. What
changes is the spec's provenance: the section must stop claiming a measurement it never made,
and state the real cost.

## 6. Confinement, at scale

Across the full six-root walk to unlimited depth:

```
48,704 regular files, 0 entries refused as non-regular or off-volume, 0 per-path errors
```

Still **zero symlinks anywhere below the roots**, now over 48,704 files rather than the
discovery run's 1,778. So refusing every symlink below the root continues to cost nothing on
this device, and the open question about whether that rule is too blunt (`THREAT_MODEL.md`
§7.3) remains open on the same terms: it costs nothing, and a future device shipping a
legitimate one would show up as missing files rather than as an error.

Zero per-path errors also means the `partial` status path went unexercised on real hardware —
every root read cleanly. It stays covered by fixture and unit tests.

## 7. Host preconditions the spec does not state

Two operational facts that cost time before any of the above could run.

**USB debugging authorization is per adb-server RSA key.** The phone had file transfer enabled
and showed "USB debugging connected", and the server still reported `unauthorized`. The adb
server here runs as an ordinary user with its own key at `~/.android/adbkey`, and the phone
must trust *that* key. A different account on the same host has a different key, and trusting
one does nothing for the other. Replugging re-triggers the trust dialog, which must be accepted
with "Always allow from this computer".

**File transfer mode must be selected**, not "No data transfer" — this is separate from the
debugging trust above, and both are required.

Neither appears in `ADB_BROKER.md`'s "The adb server must already be running" section, which
should say what "running" actually requires.

---

## What this changes

1. **`adb_experiment.md`**: the `RECV` `DONE` width moves from "Still untested" to measured.
2. **`ADB_BROKER.md`**: the depth-1 claim is corrected from "no root has regular files at
   depth 1" to a per-root table, with the trap restated as *inconsistent* rather than uniform.
3. **`ADB_BROKER.md` Process model**: the unsourced figures are replaced with the measurements
   above, and the section stops claiming a measurement it never made. The one-shot decision is
   restated on lifecycle grounds, where it always belonged.
4. **`ADB_BROKER.md` Transport**: host preconditions — file-transfer mode and per-key debugging
   authorization — are stated.
5. The device manifest's depth-1 test reports instead of asserting, and the zero-byte test's
   skip is documented as expected rather than as a gap.

## Still untested after this pass

- **A mid-transfer `RECV` failure** on real hardware. Now reproducible in fixture mode via
  `--fail-after`, but not on the device without yanking storage mid-read.
- **The `LIS2` large-directory stress case** is effectively settled: `/sdcard/Pictures`
  enumerated 25,806 files across its tree with no desync, which is far past the "few hundred
  entries" the discovery run reached. It is not a single directory of that size, so the
  strictest form of the case remains unmeasured.
- **A non-UTF-8 filename.** None found among 48,704, up from the discovery run's sample. The
  `path_b64` rule stays justified by prudence, and this is now a much stronger negative result.
- **The `partial` listing path** on real hardware: zero per-path errors occurred.

---

## 8. Stage 2: the two audit controls work, and the anchor silently does not

The binary was installed setuid for the first time and the audit design exercised end to end.

**Both controls hold.** The installed binary, run as uid 1003, appended to a log owned by uid
995; uid 1003 is refused writing that log directly, and cannot read it either (mode 0640,
wrong group). `verify` — running at euid 995 through setuid — read the log its caller cannot,
and the chain verified. Ownership and `chattr +a` had never before been exercised by anything
but a temp file.

**Build provenance is now reported.** `verify-install` reads Go's VCS stamp and fails on a
binary built from a modified tree. The first version of that check was broken — it compared the
wrong awk field and reported "provenance is unknown" for a correctly stamped binary, while the
install still said "all checks passed". A verification step that silently degrades to "cannot
tell" is the failure mode this repository keeps correcting, and it reached production here.

### The finding: no anchor was published

`verify --anchors -` against every journal entry carrying the broker's `MESSAGE_ID`:

```
/var/log/adb-broker/audit.log verified 1 record(s), but no anchor published by uid 995
from /usr/local/bin/adb-broker was found, so a truncated tail could not be ruled out
```

3,365 entries carry that `MESSAGE_ID`. Every one is from uid 1003:

| `_UID` | `_EXE` | Count |
|---|---|---|
| 1003 | `broker.test` | 2,649 |
| 1003 | `deviceaudit.test` | 672 |
| 1003 | *(absent)* | 43 |
| 1003 | `python3.12` | 1 |

**Not one from uid 995.** The broker ran, wrote its record, and published no anchor — and
`WriteAnchor`'s failure is deliberately ignored, so nothing reported it. The design decision
that an anchor failure must not fail an operation is right; the consequence, that a
permanently broken anchor path is invisible, was not thought through.

This matters because the anchor is the *only* control against tail truncation (§5.6). Without
it, a truncated log recomputes cleanly and `verify` can only say "could not be ruled out" —
which is exactly what it said, honestly, and which is the whole guarantee going unenforced.

Note what the filter did do correctly: it discarded all 3,365 non-matching anchors, including
the deliberate forgery from `python3.12`. The `_UID` discrimination works. There was simply
nothing genuine to find.

**Not yet diagnosed.** Candidates, in order of suspicion: the anchor is written after the audit
record but the process exits before the datagram is flushed; `AF_UNIX`/`SOCK_DGRAM` sends from a
setuid process are rejected or dropped somewhere; or the code path is not reached at all under
the installed binary's wiring. Distinguishing them needs the socket exercised directly as uid
995, which needs root.

Two related observations from the same data:

- **The test suite publishes 3,321 real anchors into the host's journal.** This was recorded as
  a known limitation — `deviceaudit`'s `writeAnchor` seam is unexported, so app-layer tests hit
  the real socket. Seeing the volume makes the case for fixing it: the journal now holds
  thousands of entries claiming to anchor an audit log, all of them from test binaries.
- **`verify --anchors <glob>` cannot succeed on this host**, and that is structural rather than
  a bug. The filter correctly uses `os.Geteuid()` — 995 under setuid — but 995 is deliberately
  not in `systemd-journal` (§5.6 declined that grant), so the files are unreadable; and running
  `verify` as root to read them would filter for `_UID=0` and match nothing. The only workable
  operator path is a pipe: `journalctl` as root into a broker still at euid 995. The glob
  argument should say so rather than offering a path that cannot work.

---

## 9. Two numbers this project recorded as unmeasured

Both were flagged as open questions rather than guesses: journald retention (ADB_BROKER.md open
question 9, THREAT_MODEL.md §9 and T13) and a linear-walk verification speed (ADB_BROKER.md open
question 7, phase-3-verification-plan.md Stage 7). Measured on this host, 2026-07-31.

### 9.1 journald retention — the truncation-detection horizon

This agent's uid (1003) is in neither `adm` nor `systemd-journal`, which is the same restriction
§8 already documented for `verify --anchors`. `journalctl` warns about it on every invocation and
only returns this uid's own split-by-uid entries. What follows is reported split by what was
actually readable.

**Storage is persistent, not volatile.** `/etc/systemd/journald.conf` has `Storage=` commented
out (compile-time default `auto`), and `/var/log/journal/<machine-id>/` exists on disk (directory
present since 2024-09-12) — `auto` with the directory present means persistent storage. Anchors
survive a reboot on this host. There is no `/etc/systemd/journald.conf.d/` at all — no drop-ins,
nothing overriding the shipped defaults. Every retention-relevant key in the file is commented,
i.e. left at its compiled-in default: `SystemMaxUse=`, `SystemKeepFree=`, `SystemMaxFileSize=`
and `MaxRetentionSec=` are all unset; `SystemMaxFiles=` defaults to 100; `MaxFileSec=` defaults to
1 month (a per-file rotation trigger, not a deletion rule). **`MaxRetentionSec` being unset is
the load-bearing fact**: nothing on this host deletes a journal entry for being old. Eviction only
happens under size pressure.

**Content this uid could read:** `journalctl --list-boots` (own entries only) shows the oldest
visible boot starting Wed 2026-07-22 12:22:07 CEST — a 9-day window from today. This is not the
retention horizon; it's the limit of what uid 1003 personally logged and can see.

**Content this uid could not read but could measure via filesystem metadata:** the directory
(`drwxr-sr-x+`, world `r-x`) is listable and stat-able by anyone, even though the `root:systemd-
journal 0640` files inside are not (`head`/`cat` on `system.journal` confirmed: `Permission
denied`). Archived journal filenames embed the first entry's realtime timestamp in hex
microseconds-since-epoch; decoding the oldest surviving file's name
(`system@...-0006516f2ee078f2.journal`) gives `1778387829946610` µs = **2026-05-10 04:37:10 UTC**,
which matches that file's filesystem birth time exactly (`stat`: `Birth: 2026-05-10 06:37:10
+0200`), confirming the decode. That is **82 days** before today. `du -sh` on the machine-id
directory (stat-only, no read needed) reports **1.9G** across 100 files (53 of them `system@…`);
`df` on the containing filesystem shows **1.8T total, 481G available** — journal usage is under
0.11% of the free space on this host. `journalctl --disk-usage` as this uid separately reports
63.9M, which is this uid's own slice, not the total.

**The horizon, stated as a sentence an operator can act on:** on this host, storage is persistent
and no age-based eviction is configured (`MaxRetentionSec` unset), so a published anchor is not
deleted for being old — it is only at risk once total journal usage grows enough to force
`SystemMaxUse`/`SystemKeepFree`-driven rotation or the 100-file cap, and at the measured rate
(1.9G in at least 82 days, against 481G free) that is not imminent on this host; but "not
imminent today" is not a number, and nothing in the design states what the actual cap resolves to
in days, because that cap is a percentage of free space and log volume, not a fixed duration —
**the horizon exists, is currently long (≥ 82 days, observed), and is unquantified in days**
because it is defined by disk headroom and journal volume rather than by time. An operator who
wants a hard guarantee should set `MaxRetentionSec` explicitly rather than rely on this behavior,
which is a property of default disk headroom, not a stated design guarantee.

This does not overturn anything already written: THREAT_MODEL.md line 535 already says
"unquantified," and ADB_BROKER.md's open question 9 already says the same. It replaces
"unquantified" with what could actually be measured on this host, and adds the one fact that
matters beyond a day count: retention here is size-bounded, not time-bounded, which the design
had not stated either way.

### 9.2 The audit hash chain's linear verify walk

Two different linear walks are in play in this codebase and they should not be conflated. The
`KEYED-HASH`-driven walk named in ADB_BROKER.md's open question 7 is `foundation/journal`'s entry-
array traversal over systemd's own journal files, done because `KEYED-HASH` tables use SipHash-2-4
and this repo has no SipHash implementation. That walk was **not** measured here: this uid cannot
read the journal files needed to build a realistic-sized fixture (§9.1), and open question 7 is
about that code path specifically, not about `foundation/audit`.

What was measured is `foundation/audit`'s own linear walk: `VerifyChain` in `log.go`, which reads
the audit log start-to-finish and recomputes every record's SHA-256 chain link
(`record.go:HashRecord`). This is the walk that decides whether the *audit log's own* `verify`
stays practical as that log grows — a related question, not the same one, and one the docs had
also left unquantified.

**Method.** A standalone Go module in scratchpad (`auditbench`, `replace`-directed at this repo's
module path — nothing added to `/opt/projects/adb-broker`) built synthetic logs through the
package's real `audit.Open`/`audit.Append` path, one record per call, then timed a single
`audit.VerifyChain` pass over the resulting file. Three sizes, three repetitions each:

| Records | File size | Wall clock (3 runs) | Records/sec (3 runs) | Per record (3 runs) |
|---|---|---|---|---|
| 10,000 | 4,848,151 B | 116.6 / 113.6 / 113.2 ms | 85,762 / 88,057 / 88,356 | 11.66 / 11.36 / 11.32 µs |
| 50,000 | 24,329,274 B | 564.1 / 587.3 / 572.9 ms | 88,634 / 85,128 / 87,279 | 11.28 / 11.75 / 11.46 µs |
| 200,000 | 97,583,343 B | 2307.0 / 2445.3 / 2329.2 ms | 86,692 / 81,788 / 85,868 | 11.54 / 12.23 / 11.65 µs |

Host: Intel(R) Core(TM) i5-8250U CPU @ 1.60GHz, 8 logical CPUs (`GOMAXPROCS=8`), though
`VerifyChain` is single-threaded — the walk is sequential by construction (each record's hash
depends on the previous one).

Wall clock scales linearly with record count (10k→50k is 5x the records for ~4.9x the time;
50k→200k is 4x the records for ~4.0-4.2x the time), and records/sec stays flat at
**≈ 82,000–88,000/sec** across two full orders of magnitude — this is `O(n)`, as the design always
said, with a per-record cost that does not grow with log size. Per-record cost averages
**≈ 11.6 µs**, using the 200,000-record trials (the largest, least warm-up-sensitive sample).

**What this costs in practice:**

- **The measured library, 48,704 records** (one archive run, one record per file — §5): a full
  chain verification costs **48,704 × 11.6 µs ≈ 0.57 seconds**. Trivially practical.
- **A year of daily runs**, with rotation deliberately absent (ADB_BROKER.md line 1114) so the log
  only grows: if every day adds another 48,704-record archive run, day 365 holds
  17,776,960 records, and *that single verify* costs **≈ 206 seconds (≈ 3.4 minutes)**.
- **Cumulative cost of running `verify` once a day for that whole year**, each time against the
  log as it stood that day (Σ, d=1..365, of d × 0.57 s): **≈ 38,400 seconds ≈ 10.7 hours of CPU
  time spent verifying, over the year**, growing without bound in subsequent years because nothing
  here rotates the log.

**Does this invalidate anything written?** No existing claim is contradicted — the docs called
this "unmeasured," not wrong. It does sharpen the open question, though: at today's 48,704-file
library the walk is a non-issue (sub-second), but the *design* choice to run rotation-free
(ADB_BROKER.md line 1114) means the linear-walk cost is unbounded over the life of the host, not
just of one archive run, and 3-4 minutes at one year is the kind of number that should be in the
design rather than left as "unmeasured," since it is the point at which an operator running
`verify` interactively would start to notice the wait.
