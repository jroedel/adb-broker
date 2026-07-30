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

There is a fifth reason, and it is now the primary one. The CLI adapter can read the
entire device. `adb shell` is a general-purpose remote execution channel, and an adapter
built on it is confined only by what it happens to ask for. This broker is confined by
what it is *able* to ask for. See **Confinement**.

---

## Threat model

Stating this plainly, because two design decisions below look like ceremony without it.

The broker runs on a host that also runs automated agents with the ability to write files
and execute code as ordinary users. The assets being protected are:

1. **The phone's private storage.** Application sandboxes under `/data`, and any area of
   `/sdcard` outside the user's own media, must be unreachable *through this binary* —
   including by a caller that deliberately asks for them.
2. **The record of what was read.** If the broker did reach something, that fact must
   survive an attempt to erase it.

The adversary is assumed to be a local unprivileged process, possibly one that can edit
this repository and rebuild the binary. It is *not* assumed to have local root; where a
control fails against root, this document says so rather than implying otherwise.

Two things are explicitly out of scope. The broker cannot defend against a compromised
`adbd` on the phone, and it cannot defend against an adversary who is already root on
the host and simply reads the phone with their own copy of `adb`. The goal is that *this
binary* is not the instrument, and that its own history is not rewritable.

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

Neither stream is the audit trail. See **Audit logging** — the audit record is written
where the caller cannot influence it, and a caller that discards stdout and stderr
entirely still leaves one behind.

### Discovery

The archiver locates the binary in this order, and reports clearly if it finds nothing:

1. `source.broker_path` in `photos.yaml`, if set.
2. A binary named `photos-adb-broker` in the same directory as the running `photos`
   executable — the packaged case.
3. `photos-adb-broker` on `PATH`.

---

## Transport

**The broker speaks the adb sync protocol directly, over the local adb server.** It
connects to `127.0.0.1:5037`, selects a transport, and opens the `sync:` service. It does
not exec the `adb` binary, at any point, for any reason.

This is the decision that makes the rest of the document possible:

- **No `stat` parsing.** `STAT_V2` and `LIST_V2` return a struct with `mode`, `size` and
  `mtime` as integers. The toybox dependency disappears entirely.
- **No stderr prose to classify.** The protocol returns `FAIL` with a message and, more
  usefully, the host service returns structured failure at connect time. Error codes come
  from the transport's own states, not from matching English.
- **No shell quoting**, because there is no shell.
- **No shell channel exists at all.** The single most valuable property here: an adapter
  built on `adb shell` can do anything the phone's shell user can do, and is restrained
  only by intent. This broker's outbound vocabulary is a fixed, compiled-in set of adb
  service strings — `host:version`, `host:devices-l`, `host:transport:<serial>`,
  `host:transport-any`, and `sync:`. Within `sync:` it sends only `LST2`, `LIS2` and
  `RECV`. It never sends `shell:`, `exec:`, `SEND`, `reverse:`, `root:`, `tcpip:`, or
  anything else. This list is a constant in the source, not a convention.

### The adb server must already be running

If `127.0.0.1:5037` does not accept a connection, the broker fails with `no_adb_server`
and exits non-zero. **It never spawns `adb start-server`.**

The point of the transport choice is that the broker has no exec path whatsoever. A
binary that shells out "only to start the daemon" has a process-spawn code path, an
argv-construction code path, and a PATH dependency, and those are exactly the surfaces
being removed. Starting the daemon is the host's job, and its absence is a clear,
diagnosable error rather than something papered over.

The broker also never enables ADB-over-network, and never connects to anything other than
`127.0.0.1:5037`. The address is compiled in and not configurable.

### `STAT_V2` / `LIST_V2` are required

Legacy `STAT` and `LIST` report `size` as a 32-bit value. A video over 4 GiB would be
reported with a silently wrong size, and the archiver's entire cheap-path comparison —
the thing that makes an incremental run fast — keys on size and mtime.

**A device that does not offer the V2 sync commands is refused with `unsupported`.** The
broker does not fall back and does not degrade. A wrong size that looks right is worse
than a run that refuses to start, because the first is discovered years later and the
second is discovered immediately.

---

## Confinement

The broker reads six directory trees and nothing else, ever.

### The allowlist

Compiled into the binary, as a constant:

```
/sdcard/DCIM
/sdcard/Download
/sdcard/Movies
/sdcard/Music
/sdcard/Pictures
/sdcard/Recordings
```

Everything else on the device is unreachable. There is no flag, no environment variable
and no configuration file that widens this list. Widening it requires editing the source
and rebuilding, which is a reviewable, attributable act.

An optional configuration file **may only narrow** the compiled list — it can remove
roots or restrict to a subset, and any entry that is not already a subpath of a compiled
root is a startup error rather than an addition. The invariant is one-directional and
worth stating baldly: **no input the broker reads at runtime can increase its authority.**

### One spelling

Android reaches the same storage through several paths — `/sdcard`,
`/storage/self/primary`, `/storage/emulated/0`, and a per-user variant. They are the same
bytes under three names.

**Only the `/sdcard/…` spelling is accepted.** A request naming any other prefix is
refused with `path_denied` and is *not* resolved to see whether it would have been
permitted. This is deliberate: resolving alternate spellings means writing path-resolution
logic that the confinement guarantee then depends on, and path-resolution logic is where
confinement bugs live. Refusing to resolve is a guarantee with no moving parts.

A path is rejected before anything else looks at it if it is not absolute, does not begin
with `/sdcard/`, contains a `..` segment, contains an empty segment or a trailing slash,
or contains a NUL byte.

### Segment-aware prefix matching

`/sdcard/Download` authorises `/sdcard/Download/a.jpg`. It does not authorise
`/sdcard/Download-private/a.jpg`. The comparison is over path segments, never over string
prefixes, and there is a test for exactly this case.

A `--root` that is a *parent* of an allowed root — `/sdcard`, or `/` — is refused with
`path_denied`. It is not silently narrowed to the permitted children beneath it. A caller
asking for `/sdcard` is asking for something the broker will not do, and telling it so is
more useful than quietly doing something else.

### Symlinks are the escape hatch, and are refused

Any application on the phone can create `/sdcard/Pictures/x` as a symlink pointing at
`/data/data/com.something/databases/`. A broker that checks only the *requested* path
string and then reads whatever comes back has an allowlist that any app on the device can
step around.

So:

- Traversal uses `LIST_V2`, whose dirents carry `mode` with `lstat` semantics. Anything
  that is not a regular file — directory entries excepted, which are recursed into — is
  omitted. Symlinks, sockets, FIFOs, block and character devices never appear in a
  listing.
- `fetch` issues `LST2` (`LSTAT_V2`, which does *not* follow symlinks) and requires
  `S_ISREG` before issuing `RECV`. A symlink is refused with `path_denied`, not followed
  and not reported as its target.
- Every component of the path is checked, not only the leaf. A regular file beneath a
  symlinked *directory* is still outside the tree the user named.

**Residual risk, stated rather than hidden:** there is a window between the `LST2` and the
`RECV`, and `RECV` follows symlinks on the device side. An adversary with code execution
on the phone could replace a regular file with a symlink inside that window. The sync
protocol offers no `openat`-style handle to close it. This is accepted: an adversary who
already has code execution on the phone has better options than racing this broker, and
the alternative — not reading the phone at all — defeats the purpose. It is recorded here
so that nobody later mistakes the check for something stronger than it is.

### Enforcement is structural, not procedural

Confinement is not a check that each operation remembers to call. It is a type:

`devicepath.AuthorizedPath` has no exported fields and no exported way to construct a
non-zero value other than `ParseAuthorizedPath`, which applies every rule above. The
storage layer's methods accept `AuthorizedPath` and nothing else. "Fetch a path that was
never checked" is therefore not a bug that review has to catch — it is a program that
does not compile.

For the same reason confinement lives in the core `Business` type and **not** in a
business-layer extension. Extensions are decorators applied at wiring time, and a
decorator can be omitted; a wiring mistake must not be able to disable the allowlist.
Audit logging *is* an extension, because a missing audit decorator fails closed for a
different reason (see below) and the concern is genuinely cross-cutting.

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

`adb` reports the version of the *server* the broker is talking to, obtained from
`host:version` — not the version of any binary on PATH, since none is consulted.

`probe` also confirms `STAT_V2` availability and fails with `unsupported` if it is
absent, so that an incompatible device is discovered before eleven listings are attempted.

### 2. `list` — enumerate a tree

```
photos-adb-broker list --root /sdcard/DCIM/Camera [--max-depth 1] [--serial <id>]
```

`--max-depth 1` means immediate children only; omitted means unlimited. (The port's
`Recurse bool` maps to exactly these two cases.)

`--root` must lie within the allowlist, or the command fails with `path_denied` before any
transport connection is made.

The sync protocol's `LIST_V2` enumerates one directory, so recursion is driven by the
broker rather than the device. That is an advantage here: every directory the walk
descends into is re-checked against the allowlist and re-checked for symlink-ness, so
confinement is re-established at each step instead of being asserted once at the root.

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
| `path_b64` | MUST | Base64 of the raw path bytes. See *Filenames are bytes* below. |
| `size` | MUST | Exact bytes, `int64`, from `LIST_V2`. |
| `mtime` | MUST | Unix **seconds**. See *Timestamps are not to be corrected*. |
| `mtime_nsec` | MAY | Only if the transport genuinely provides it. |

`path_b64` is upgraded from SHOULD to MUST. It costs nothing, it is the authoritative
field, and making it optional invites an implementation that omits it on the ASCII paths
and gets the interesting ones wrong.

**Only regular files.** Directories, symlinks, devices and sockets must be omitted — now
a confinement requirement rather than a preference.

**No content filtering.** Do not filter by extension, and do not skip hidden files or
directories. Extension and hidden-file policy lives in `source.Accept`, shared by both
adapters, and duplicating it in the broker is precisely how the two would drift apart.

This is distinct from the allowlist, and the distinction is the reason the original rule
needed splitting. *Policy* — which of the files the archiver has been offered are worth
archiving — belongs to the archiver, because both transports must apply it identically.
*Authority* — which subtrees exist at all as far as this binary is concerned — belongs to
the broker, because it is enforced against the caller and the caller does not get a vote.

> Optional, if it is cheap: `--prune <name>` to skip named directories during traversal,
> so a large `.thumbnails` cache need not be walked at all. The archiver will not depend
> on it. It can only ever remove entries from a listing, so it cannot affect confinement.

### 3. `fetch` — stream one file

```
photos-adb-broker fetch --path /sdcard/DCIM/Camera/IMG_0182.JPG [--serial <id>]
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

`sha256` in the trailer is the digest of the bytes the broker forwarded. To be precise
about what that buys: it detects corruption between the broker and the archiver, and a bug
in the archiver's own write path. It is *not* end-to-end device verification, because the
broker never re-reads the device.

**`--verify-device` is removed.** Hashing the file on the phone requires running
`sha256sum` there, which requires a shell channel, which is the single thing the transport
choice exists to eliminate. A binary that can execute one command on the device can
execute any command on the device, and no amount of care about *which* command changes
that. The end-to-end check is given up deliberately; the trailer digest plus the exact
byte count is what remains, and integration tests use fixture mode instead.

**Never write to the local filesystem.** The archiver creates the staging file itself
with `O_EXCL` and hashes bytes as they arrive, which is where the refuse-to-overwrite
guarantee lives. The audit log is the sole exception, and it is append-only.

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
| `no_adb_server` | Nothing listening on `127.0.0.1:5037` | Aborts. The host must start it. |
| `path_denied` | Outside the allowlist, wrong spelling, or a symlink | **Aborts that source.** A configuration error, not a device condition. |
| `audit_unavailable` | The audit log cannot be opened or its head does not verify | Aborts the run before any device contact. |
| `root_not_found` | The named tree does not exist | **Skips that source, continues.** One of eleven folders having been removed says nothing about the other ten. |
| `not_a_directory` | Root is a file | Skips that source. |
| `permission_denied` | A path could not be read | Per-path: warn, continue. Never ends a run. |
| `path_not_found` | A file vanished between `list` and `fetch` | Per-file failure, run continues. |
| `transfer_failed` | Stream ended early or was corrupt | Per-file failure, run continues. |
| `device_disconnected` | Device went away mid-operation | Aborts. |
| `unsupported` | Operation or flag not implemented, or device lacks `STAT_V2` | Aborts, with the version. |
| `internal` | Anything else | Aborts. |

`message` is free-form and for humans only; the archiver logs it and never branches on
it. New codes may be added — an unrecognized code is treated as `internal`, which is the
safe direction.

`path_denied` deserves a note on why it aborts its source rather than warning. A denied
path is never a transient device condition; it means the archiver was configured to read
something this broker will not read. Continuing quietly would produce a backup that is
silently missing a whole tree, which is the failure mode the entire tool exists to
prevent. It does not abort the *run*, because the other ten sources are still valid.

The partial case matters and deserves stating explicitly: a `list` that reads most of a
tree and fails on one subdirectory must emit every record it *did* read, then a summary
with `"status":"partial"` and the per-path errors. Exit code should still be `0`. The
archiver already distinguishes "nothing listed, so the root is wrong" from "some paths
failed, so warn and carry on", and this is what it needs to keep doing that.

---

## Audit logging

Every operation the broker performs is recorded where the caller cannot reach it, in a
form where deletion and alteration are both detectable.

### What is logged

One record per operation — `probe`, `list`, `fetch` — with no exceptions and no sampling.
A first-ever run writes roughly 20,000 records; a settled run writes a handful. At about
250 bytes per record that is around 5 MB, once, which is not a problem worth engineering
around.

A denial is logged with the same weight as a success. The denial records are the ones that
matter most, and a design where the interesting events are the ones that go unwritten is
not an audit trail.

```json
{"seq":1042,"ts":"2026-07-30T16:52:03.114Z","op":"fetch","serial":"EXAMPLESERIAL1","path_b64":"L3NkY2FyZC8…","decision":"allow","result":"ok","bytes":103159,"sha256":"e3b0c442…","prev":"9f2b…","hash":"41d0…"}
```

Paths are recorded as `path_b64` for the same reason the wire format uses it — a log that
cannot faithfully record the path of the file it read is not evidence of anything.

### The chain

`hash_n = SHA-256(hash_{n-1} ‖ canonical(record_n without its own hash))`, with `hash_0`
being 32 zero bytes.

`canonical` must be byte-exact and specified, not left to `encoding/json` field ordering:
fields in the fixed order above, no insignificant whitespace, no HTML escaping. A chain
whose verifier and writer disagree about serialization is a chain that reports tampering
every time, which is the same as having no chain.

This makes editing a record, reordering records, or removing records from the middle all
detectable by recomputation. It does **not** by itself detect truncation of the tail or
deletion of the whole file, because an adversary can recompute a shorter valid chain.

### The anchor

So the chain head is anchored outside the file. Periodically, and at process exit, the
broker emits `{seq, hash}` to the systemd journal under a stable `MESSAGE_ID`. The journal
is written by a process the broker does not run as and cannot rewrite.

Verification compares the file's tail against the most recent journal anchor. A file
whose chain is internally valid but whose head is *behind* the anchor has been truncated,
and that is now visible.

Be clear about the limit: an adversary with local root can rewrite the journal too. The
anchor raises the bar from "any local user with a text editor" to "root, tampering with
two independent sinks consistently". Against a root adversary the honest answer is an
off-box sink, which is deferred (see **Open questions**) because it would put network
access into a binary that currently has none, and that is a trade worth making
deliberately rather than by default.

### Fail closed

At startup, before any device contact, the broker opens the audit log, reads the tail
record, and checks that its hash matches the most recent journal anchor. If the log cannot
be opened, cannot be appended to, or the head does not verify, the broker exits with
`audit_unavailable` and does nothing else.

This means a misconfigured install cannot back up photos. That is the intended behaviour:
an unauditable read of the phone is the thing being prevented, and a control that
disengages under pressure is not a control. Full verification of the entire chain is a
separate `verify` subcommand rather than a startup cost, since startup only needs to
detect truncation.

`verify` reads the log and the journal anchors and reports the first divergence. It takes
no device and no network.

### Where it lives

```
/var/log/photos-adb-broker/          root:root 0755   — broker cannot unlink from it
/var/log/photos-adb-broker/audit.log <broker uid>     — opened O_WRONLY|O_APPEND
```

The directory is root-owned so the broker cannot unlink or replace the file. The file
carries `chattr +a`, so append is the only write the kernel permits — and removing that
attribute requires `CAP_LINUX_IMMUTABLE`, which the broker does not have. Without `+a`,
`O_APPEND` is a convention the process can drop by reopening; with it, it is enforced.

Rotation is deliberately absent. Rotation and a hash chain interact badly — every rotation
is a chain break that must itself be anchored — and the volume does not require it. If it
ever does, segments must link to the previous segment's final hash, and that is a change
to make on purpose.

### Shape in the code

Audit logging is a business-layer extension (`business/domain/device/devicebus/extensions/deviceaudit`),
wrapping `ExtBusiness` and delegating. It is the textbook case for the pattern: it applies
to every method, it is orthogonal to what those methods do, and it must not be tangled
into the traversal logic.

The apparent tension with "a decorator can be omitted" is resolved by the startup check.
If the audit extension is not wired, the audit log is never opened; the fail-closed check
in `main` runs before the bus is constructed and refuses to proceed. Wiring the extension
is therefore not what makes the log appear — the log is opened unconditionally, and the
extension is what writes to it.

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

This is enforced by the type rather than by this paragraph. `mtime.Mtime` wraps an `int64`
of seconds and exposes no timezone conversion, no `time.Time`, and no arithmetic. The
helpful mistake is not available to write.

### Filenames are bytes

Android filenames are byte strings, not necessarily valid UTF-8, and JSON strings must
be. A camera roll is ASCII, but the messaging, design-app and download folders contain
whatever arrived.

So `path_b64` is always present and is authoritative; `path` is for logs and may be lossy.
The archiver uses `path_b64`. The cost of getting this wrong is a file that is never
archived, which is the one outcome the whole design exists to prevent — cheap insurance
for a case that may never arise.

`devicepath.DevicePath` holds the raw bytes in a `string`, which in Go is byte-safe. The
lossy UTF-8 coercion happens once, in `fromBusFileRecordResponse`, and only for the `path`
field.

---

## What the broker must not do

Non-negotiable, because the tool's central promise is that the source is never modified:

- **No writes to the device.** No push, no delete, no rename, no `chmod`, no shell
  execution on the archiver's behalf. The sync `SEND` command is never sent and the
  `shell:` and `exec:` services are never opened. This is enforced by the compiled service
  vocabulary described under **Transport**, not by discipline.
- **No reads outside the allowlist.** Enforced by `AuthorizedPath`, described under
  **Confinement**.
- **No local filesystem writes**, other than stdout, stderr, and appends to the audit log.
- **No network access**, other than a TCP connection to `127.0.0.1:5037`.
- **No process execution.** No `exec`, no `fork`, no PATH lookup, including for `adb`
  itself.
- **No content filtering, sorting or deduplication.** The archiver sorts by path
  (determinism is required — it decides which counterpart a paired RAW reports) and
  applies all policy itself.
- **No metadata parsing.** No EXIF, no thumbnails, no image decoding. Metadata is read
  from a verified local copy, by one code path shared with the rebuild command.

**The wake-lock question is answered "no".** Holding a wake lock requires running a command
on the device, which requires the shell channel that does not exist. If long transfers
prove to need one, it is the *host's* job — via the phone's own settings, or by keeping the
screen on — and not something this binary acquires quietly. The original spec was right to
ask whether that counts as a write to the device; the answer here is that it never gets the
chance.

---

## Architecture

Layered per the house rules. Primitives at the edges, strong types only in Business, every
crossing through a named converter.

```
cmd/photos-adb-broker/main.go               wiring; fail-closed audit init before anything else
app/broker/{probe,list,fetch}.go            subcommands: flags in, wire JSON out
app/broker/wire.go                          request + response structs, primitives only
app/broker/convert.go                       toBus* / fromBus*Response
business/domain/device/devicebus/
  devicebus.go                              Business, ExtBusiness, Extension, Storer
  model.go                                  Device, FileRecord, ListResult
  extensions/deviceaudit/deviceaudit.go     hash-chained audit decorator
business/domain/device/stores/adbsyncdb/
  adbsyncdb.go                              Storer implementation over the sync protocol
  convert.go                                toSync* / toBusFileRecord
business/types/devicepath/                  DevicePath, AuthorizedPath, the allowlist
business/types/serial/                      Serial
business/types/mtime/                       Mtime
business/types/filekind/                    Kind — regular, dir, symlink, other
business/types/errcode/                     Code
foundation/audit/                           chain, append-only sink, journald anchor
foundation/adbwire/                         sync protocol framing
```

### Type boundaries

| Layer | Type | Notes |
|---|---|---|
| App request | `ListRequest{Root, Serial string; MaxDepth int; Prune []string}` | flags arrive as primitives |
| App response | `FileRecordResponse{Path, PathB64 string; Size, Mtime int64}` | exactly the wire format above |
| Business | `FileRecord{Path devicepath.AuthorizedPath; Size int64; Mtime mtime.Mtime; Kind filekind.Kind}` | strong throughout |
| Storage row | `syncFileRecord{Path, PathB64 string; Size, MtimeSec int64; Mode uint32}` | natives, as `LIST_V2` returns them |

### Converters

| Direction | Name | Returns |
|---|---|---|
| App → Business | `toBusListRequest` | `(devicebus.ListInput, error)` — parses `--root` via `ParseAuthorizedPath`, accumulates `errs.FieldErrors` |
| Business → App | `fromBusFileRecordResponse` | response struct; `.String()` on every strong field, plus the base64 and the lossy `path` |
| Business → Storage | `toSyncPath`, `toSyncListRequest` | native request values |
| Storage → Business | `toBusFileRecord` | `(devicebus.FileRecord, error)` — parses `mode` into `filekind.Kind`, path into `AuthorizedPath` |

The Business→Storage direction is named `toSync*` rather than the house `toDB*`, because
the storage behind this boundary is a wire protocol and calling it a database would be a
small lie repeated in every file. The reverse direction keeps `toBusFileRecord`, which is
the house name in both directions anyway.

Note that the storage layer's `toBusFileRecord` re-parses each discovered path through
`ParseAuthorizedPath`. Paths that come *back* from the device are as untrusted as paths
that come in from the caller — a directory entry naming something outside the tree is
precisely the attack the symlink rules address, and re-parsing means the confinement type
is never bypassed by data flowing the other way.

### Validation lives in one place

All parsing and validation happens in App-layer `toBus*`, returning `errs.FieldErrors`,
with one deliberate exception: `ParseAuthorizedPath` is also called in the storage layer
for device-supplied paths, as above. The exception is documented at the call site.

---

## Fixture mode, for tests and development

The most valuable thing the broker can add beyond production use.

```
photos-adb-broker-fixture --fixture /path/to/tree list --root /sdcard/DCIM/Camera
```

With `--fixture DIR`, the broker serves `DIR` as though it were the device: `/sdcard/…`
paths map to `DIR/sdcard/…`, and `probe` reports a synthetic serial with
`"state":"device"`. Same wire format, same error codes, no hardware.

This closes a real gap. The adapter's unit tests currently inject a fake command runner
in-process, which exercises the parsing but not the protocol; the device tests exercise
everything but skip whenever no phone is plugged in — as just happened. Fixture mode gives
CI a run that covers the whole path.

**Fixture mode is behind a build tag and is absent from the release binary.** A flag that
remaps `/sdcard/…` onto an arbitrary local directory is an allowlist bypass by
construction, and one that ships in production is a bypass an attacker can use without
building anything. The fixture build produces a differently-named binary
(`photos-adb-broker-fixture`) and reports a `broker` version with a `+fixture` suffix, so a
fixture binary in a production path is visible in the first `probe` response and in the
audit log rather than being indistinguishable.

The allowlist still applies in fixture mode, against the virtual `/sdcard/…` paths. Tests
that exercise confinement must exercise the real confinement code, or they are testing
something else.

Worth supporting for the same reason:

- `--fail-after <n>` on `fetch`, truncating the stream mid-file, so the truncated-transfer
  path can be tested deliberately rather than hoped about.
- `--inject-error <code>` to produce any error in the table above on demand. The
  archiver's branching on those codes is safety-critical and otherwise untestable.

---

## Installation

The audit guarantee depends on file ownership the binary cannot establish for itself, so
installation is a documented, root-run step rather than something the broker does on first
use. A process that can create its own audit log can also recreate it.

`make install`, run as root:

1. Creates `/var/log/photos-adb-broker/`, owned `root:root`, mode `0755`.
2. Creates `audit.log`, owned by the uid the broker runs as, mode `0640`.
3. Sets `chattr +a` on `audit.log`.
4. Installs the binary to the target path, owned `root:root`, mode `0755`.
5. Prints what it did, and verifies each property afterwards rather than assuming the
   commands worked.

`make verify-install` re-checks all four properties without changing anything, and is
worth running from monitoring. The broker's own startup check covers the log; it cannot
check that it is not itself writable by the adversary, because by then it is too late.

---

## Versioning

- Every stdout object carries `"proto":<int>`.
- `probe` reports `broker` (the binary's own version) and `adb` (the adb server's).
- The archiver checks `proto` at `probe` time and refuses to run against an unknown major
  version rather than misparsing it.
- Adding fields is compatible. Removing or repurposing one is a `proto` bump. New `code`
  values are compatible, since unknown codes degrade to `internal`.

`proto` stays at `1`. The removal of `--verify-device` and the addition of `path_denied`,
`no_adb_server` and `audit_unavailable` are compatible under the rules above, and nothing
consumes the interface yet.

---

## Build order

1. `foundation/adbwire` — connect to `127.0.0.1:5037`, host services, `sync:`, `LST2`,
   `LIS2`, `RECV`. Tested against a real adb server with no device attached, which
   exercises the failure paths first.
2. `business/types/*` — `devicepath` with the full allowlist rule set, `mtime`,
   `filekind`, `serial`, `errcode`. `devicepath` gets the densest test file in the repo,
   including the `Download-private` case, every alternate spelling, `..`, NUL, and the
   parent-of-root case.
3. `foundation/audit` — chain, canonical serialization, append sink, journald anchor,
   `verify`. Round-trip and tamper-detection tests: edit a record, reorder two, truncate
   the tail, and confirm each is caught.
4. `business/domain/device` — model, `Storer`, `Business`, then `adbsyncdb` over the wire
   package.
5. `app/broker` + `cmd` — subcommands, wire structs, converters, fail-closed startup.
6. `deviceaudit` extension and wiring.
7. Fixture mode behind the build tag, then the `--fail-after` / `--inject-error` hooks.
8. `make install` and `make verify-install`.

Steps 1–3 are independent and have no dependency on a phone being present.

---

## Open questions

1. **The allowlist roots are provisional.** Six roots covering camera, downloads, audio
   recordings and pictures. Revisit against an actual top-level listing of the device once
   the broker can produce one — which it can, since `/sdcard` itself is denied, so this is
   a deliberate one-off inspection rather than something the tool does.
2. **Which uid does the broker run as, and is it the same one `photos` runs as?** If they
   are the same, the audit log is writable by whatever compromises `photos`, and the
   `chattr +a` is doing all the work. A dedicated uid is better and costs nothing.
3. **Off-box anchoring.** Deferred, because it would introduce network access to a binary
   that otherwise has none. Worth revisiting if the threat model ever includes local root.
4. **Does the sync service give better than whole-second `mtime`?** `STAT_V2` returns
   seconds. Not needed — the ledger column stores seconds — so `mtime_nsec` stays
   unimplemented.
5. **Should `list` and `fetch` be combinable?** A `fetch-many` reading paths from stdin
   would amortize spawn cost on a first-ever run. Explicitly *not* requested for v1 — the
   measurement above says it is a 3% effect — but it is the natural extension if a
   persistent mode is ever wanted. Note that it would need every path re-parsed through
   `ParseAuthorizedPath` individually, which is cheap.
