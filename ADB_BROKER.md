# The adb Broker — Interface Specification

A small Go binary, packaged alongside `photos`, that mediates every read of the phone.
This document specifies what the archiver needs from it and why, so the broker can be
implemented and tested independently.

The consumer is `foundation/source/adb`, which satisfies the `foundation/source.Reader`
port. Nothing above that port knows the broker exists.

---

## Why a broker at all

The current adapter shells out to the `adb` CLI. Four things about that are load bearing
and none of them are stable.

**It parses the device's `stat` output.** Enumeration runs
`find <root> -maxdepth 1 -type f -exec stat -c '%s|%Y|%n' {} +` and splits on `|`. That
depends on Android's toybox `stat` supporting `-c`, on `find` supporting `-exec … {} +`,
and on the format specifiers meaning what they mean today. Verified on toybox
0.8.13-android; asserted nowhere else.

**It classifies failures by matching English text in adb's stderr.** Today the adapter
literally does `strings.Contains(text, "no devices")` to decide whether a run should abort
or continue. This is the weakest point in the whole design, because the two outcomes are
very different: an absent device must stop the run, while an unreadable subdirectory must
not. A wording change in a future adb release silently swaps them.

**It quotes shell words itself.** `adb shell` joins its arguments and hands the result to
the device's shell, so the adapter builds single-quoted words by hand. Correct for the
paths measured, but it is the adapter's problem rather than the transport's.

**It requires the `adb` CLI on PATH**, at an unknown version, with an unknown daemon
already running or not.

A broker owns all four. What the archiver gets back is a versioned contract with typed
errors, which is the part that actually matters.

---

## Process model

**One-shot subcommands, not a long-running daemon.** This is a recommendation from
measurement rather than a preference.

Measured on the real device: enumeration is **one call per configured source root** — 11
of them — and returns 23,939 records in about 10 seconds total. Fetching is one call per
*file that is actually new*, which on a settled library is a handful. Process spawn at
~10 ms is invisible against either.

The one case where it matters is a first-ever run, which fetches everything: ~20,000
spawns is about 200 seconds of overhead on top of roughly 110 minutes of transfer at the
measured 21 MB/s. Under 3%, once, is not worth a daemon's lifecycle and deadlock
surface.

If a later measurement contradicts this, a persistent mode can be added behind the same
subcommand names without changing the wire formats below.

### Streams

- **stdout carries the protocol and nothing else.** No banners, no progress, no warnings.
- **stderr is for humans** and is captured and logged by the archiver at debug level.
- Exit code `0` for success or partial success, non-zero for a failure that produced no
  usable output. The exit code is a coarse signal; the JSON `status` field is
  authoritative.

### Discovery

The archiver locates the binary in this order, and reports clearly if it finds nothing:

1. `source.broker_path` in `photos.yaml`, if set.
2. A binary named `photos-adb-broker` in the same directory as the running `photos`
   executable — the packaged case.
3. `photos-adb-broker` on `PATH`.

---

## Operations

Three, matching the port exactly. Every subcommand accepts `--serial <id>` to pin a
device, and `--json` is implied (there is no human output mode on stdout).

### 1. `probe` — is a device reachable

```
photos-adb-broker probe [--serial <id>]
```

```json
{"proto":1,"status":"ok","serial":"EXAMPLESERIAL1","state":"device","model":"Pixel_8_Pro","broker":"0.1.0","adb":"1.0.41"}
```

Called once before a run. A disconnected phone makes every configured source unreachable,
and saying so once up front is clearer than eleven identical per-source failures — so this
is what decides whether a run starts at all.

`state` must be reported verbatim from the transport (`device`, `unauthorized`,
`offline`, `bootloader`, …). The archiver treats anything other than `device` as fatal,
and needs the raw value to say why.

With no `--serial` and several devices attached, this must fail with
`multiple_devices` and list the serials. Picking one silently would archive from
whichever phone happened to answer.

### 2. `list` — enumerate a tree

```
photos-adb-broker list --root /sdcard/DCIM/Camera [--max-depth 1] [--serial <id>]
```

`--max-depth 1` means immediate children only; omitted means unlimited. (The port's
`Recurse bool` maps to exactly these two cases.)

**NDJSON on stdout, one record per regular file, streamed as discovered** — so a 20,000-file
listing can be parsed incrementally rather than buffered:

```json
{"path":"/sdcard/DCIM/Camera/IMG_0182.JPG","path_b64":"L3NkY2FyZC9EQ0lNL0NhbWVyYS9JTUdfMDE4Mi5KUEc=","size":103159,"mtime":1709828653}
```

Terminated by exactly one summary line, distinguished by having no `path`:

```json
{"proto":1,"status":"partial","files":20397,"errors":[{"code":"permission_denied","path":"/sdcard/DCIM/Camera/locked"}]}
```

| Field | Requirement | Notes |
|---|---|---|
| `path` | MUST | Absolute, forward slashes, as the device names it. |
| `path_b64` | SHOULD | Base64 of the raw path bytes. See *Filenames are bytes* below. |
| `size` | MUST | Exact bytes, `int64`. |
| `mtime` | MUST | Unix **seconds**. See *Timestamps are not to be corrected*. |
| `mtime_nsec` | MAY | Only if the transport genuinely provides it. |

**Only regular files.** Directories, symlinks, devices and sockets must be omitted.
Following a symlink could archive files from outside the tree the user named, and the
local-filesystem adapter already skips them, so the two transports must agree.

**No filtering.** Do not filter by extension, and do not skip hidden files or
directories. Extension and hidden-file policy lives in `source.Accept`, shared by both
adapters, and duplicating it in the broker is precisely how the two would drift apart.
A full listing is ~1.5 MB for this device, which is nothing at 21 MB/s.

> Optional, if it is cheap: `--prune <name>` to skip named directories during traversal,
> so a large `.thumbnails` cache need not be walked at all. The archiver will not depend
> on it.

### 3. `fetch` — stream one file

```
photos-adb-broker fetch --path /sdcard/DCIM/Camera/IMG_0182.JPG [--serial <id>] [--verify-device]
```

Framed as header line, raw bytes, trailer line:

```
{"proto":1,"op":"fetch","size":103159}\n
<exactly 103159 bytes, verbatim>
{"status":"ok","bytes":103159,"sha256":"e3b0c442…"}\n
```

The framing exists so that a truncated transfer is detectable: the archiver reads exactly
`size` bytes and then requires a trailer. A stream that ends without one is a failure,
whatever the byte count said.

`sha256` in the trailer **should** be the digest of the bytes the broker forwarded. To be
precise about what that buys: it detects corruption between the broker and the archiver,
and a bug in the archiver's own write path. It is *not* end-to-end device verification,
because the broker never re-reads the device.

`--verify-device` **may** additionally hash the file on the device and report
`sha256_device`. That is a genuine end-to-end check, it costs a second full read on the
device, and it is therefore off by default — the archiver's integration tests will use
it, production runs will not.

**Never write to the local filesystem.** The archiver creates the staging file itself
with `O_EXCL` and hashes bytes as they arrive, which is where the refuse-to-overwrite
guarantee lives.

---

## Error taxonomy

This is the most important thing the broker provides, because the archiver's response to
a failure differs sharply by kind and it is currently guessing from prose.

Every failure — whether a whole operation or one path within a listing — carries a
machine-readable `code`:

```json
{"proto":1,"status":"error","code":"root_not_found","path":"/sdcard/NOPE","message":"no such file or directory"}
```

| `code` | Meaning | What the archiver does |
|---|---|---|
| `no_device` | Nothing attached | **Aborts the run.** Every source is unreachable. |
| `unauthorized` | USB debugging not accepted | Aborts, with instructions. |
| `offline` | Attached but not usable | Aborts. |
| `multiple_devices` | Ambiguous without `--serial` | Aborts. Never guesses. |
| `root_not_found` | The named tree does not exist | **Skips that source, continues.** One of eleven folders having been removed says nothing about the other ten. |
| `not_a_directory` | Root is a file | Skips that source. |
| `permission_denied` | A path could not be read | Per-path: warn, continue. Never ends a run. |
| `path_not_found` | A file vanished between `list` and `fetch` | Per-file failure, run continues. |
| `transfer_failed` | Stream ended early or was corrupt | Per-file failure, run continues. |
| `device_disconnected` | Device went away mid-operation | Aborts. |
| `unsupported` | Operation or flag not implemented | Aborts, with the version. |
| `internal` | Anything else | Aborts. |

`message` is free-form and for humans only; the archiver logs it and never branches on
it. New codes may be added — an unrecognized code is treated as `internal`, which is the
safe direction.

The partial case matters and deserves stating explicitly: a `list` that reads most of a
tree and fails on one subdirectory must emit every record it *did* read, then a summary
with `"status":"partial"` and the per-path errors. Exit code should still be `0`. The
archiver already distinguishes "nothing listed, so the root is wrong" from "some paths
failed, so warn and carry on", and this is what it needs to keep doing that.

---

## Two hard requirements that are easy to get wrong

### Timestamps are not to be corrected

**Report `mtime` exactly as the device stores it. Do not normalize, do not adjust for a
timezone, do not reconcile it with anything.**

Measured on this device, modification times mean different things for different files.
For the 10,593 camera files, the value rendered *in UTC* equals the filename's local wall
clock — so it sits a whole UTC offset away from the true capture instant. For the 3,189
screenshots it is a correct epoch. The producing application decides, not the transport.

The archiver relies on only one property: that the same file reports the same value on
two different runs. It compares at whole-second granularity, because the ledger column
stores Unix seconds. Any helpfulness here — inferring a zone, "fixing" the camera's
offset — breaks the comparison for every file on the device and silently disables the
cheap path, whose only symptom is that runs become inexplicably slow.

### Filenames are bytes

Android filenames are byte strings, not necessarily valid UTF-8, and JSON strings must
be. A camera roll is ASCII, but the messaging, design-app and download folders contain
whatever arrived.

So `path_b64` should always be present and is authoritative; `path` is for logs and may
be lossy. The archiver uses `path_b64` when present. The cost of getting this wrong is a
file that is never archived, which is the one outcome the whole design exists to prevent
— cheap insurance for a case that may never arise.

---

## What the broker must not do

Non-negotiable, because the tool's central promise is that the source is never modified:

- **No writes to the device.** No push, no delete, no rename, no `chmod`, no shell
  execution on the archiver's behalf. The broker should expose no operation capable of
  it, so that the promise is enforced by the transport rather than by discipline. This is
  a real gain over the CLI, where `adb shell` can do anything.
- **No local filesystem writes**, other than to stdout/stderr.
- **No network access.**
- **No filtering, sorting or deduplication.** The archiver sorts by path (determinism is
  required — it decides which counterpart a paired RAW reports) and applies all policy
  itself.
- **No metadata parsing.** No EXIF, no thumbnails, no image decoding. Metadata is read
  from a verified local copy, by one code path shared with the rebuild command.

---

## Fixture mode, for tests and development

The most valuable thing the broker can add beyond production use.

```
photos-adb-broker --fixture /path/to/tree list --root /sdcard/DCIM/Camera
```

With `--fixture DIR`, the broker serves `DIR` as though it were the device: `/sdcard/…`
paths map to `DIR/sdcard/…`, and `probe` reports a synthetic serial with
`"state":"device"`. Same wire format, same error codes, no hardware.

This closes a real gap. The adapter's unit tests currently inject a fake command runner
in-process, which exercises the parsing but not the protocol; the device tests exercise
everything but skip whenever no phone is plugged in — as just happened. Fixture mode gives
CI a run that covers the whole path.

Worth supporting for the same reason:

- `--fail-after <n>` on `fetch`, truncating the stream mid-file, so the truncated-transfer
  path can be tested deliberately rather than hoped about.
- `--inject-error <code>` to produce any error in the table above on demand. The
  archiver's branching on those codes is safety-critical and otherwise untestable.

---

## Versioning

- Every stdout object carries `"proto":<int>`.
- `probe` reports `broker` (the binary's own version) and `adb` (the underlying
  implementation's).
- The archiver checks `proto` at `probe` time and refuses to run against an unknown major
  version rather than misparsing it.
- Adding fields is compatible. Removing or repurposing one is a `proto` bump. New `code`
  values are compatible, since unknown codes degrade to `internal`.

---

## Open questions for the implementer

1. **Does the broker speak the adb wire protocol directly, or wrap the `adb` CLI?**
   Directly is materially better: `list` could use the sync service's `LIST`/`STAT`
   instead of parsing `stat -c` output, which removes the toybox dependency entirely,
   and there is no requirement for an `adb` binary or a running daemon. If it wraps the
   CLI instead, the typed error codes still remove the worst of today's fragility — that
   alone is most of the value.

2. **Does the sync service give better than whole-second `mtime`?** Not needed, but if
   it does, `mtime_nsec` is worth reporting. The archiver's comparison stays at seconds
   because the ledger column does.

3. **Should `list` and `fetch` be combinable?** A `fetch-many` reading paths from stdin
   would amortize spawn cost on a first-ever run. Explicitly *not* requested for v1 — the
   measurement above says it is a 3% effect — but it is the natural extension if a
   persistent mode is ever wanted.

4. **Wake/keep-alive.** Enumerating 20,000 files takes eight seconds and a first run
   transfers for over an hour. Does anything need to hold a wake lock, and is that a
   write to the device under the rule above? If it needs one, it needs to be an explicit,
   documented exception rather than something the broker does quietly.
