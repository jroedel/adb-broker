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
