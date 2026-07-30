# The adb Broker — Interface Specification

A small Go binary, packaged alongside `photos`, that mediates every read of the phone.
This document specifies what the archiver needs from it and why, so the broker can be
implemented and tested independently.

The consumer is `foundation/source/adb`, which satisfies the `foundation/source.Reader`
port. Nothing above that port knows the broker exists.

**Provenance.** This revision replaces assumptions with measurements taken against a real
device on 2026-07-30; the raw hex dumps and per-phase reasoning are in `adb_experiment.md`
alongside this file. Where a claim below is measured it says so and gives the numbers. Where
a rule is retained on judgement without supporting evidence — there are two, and they are
flagged in place — it says that instead. One finding invalidated part of the original
confinement design and it has been reworked rather than patched, which is the largest change
here.

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
  service strings — `host:version`, `host:devices`, `host-serial:<serial>:features`,
  `host:transport:<serial>`, `host:transport-any`, and `sync:`. Within `sync:` it sends
  only `LST2`, `STA2`, `LIS2` and `RECV`. It never sends `shell:`, `exec:`, `SEND`,
  `reverse:`, `root:`, `tcpip:`, or anything else. This list is a constant in the source,
  not a convention.

  `STA2` is present for exactly one purpose — resolving the storage volume once per run,
  described under **Confinement** — and is used nowhere else. `host:devices` replaces
  `host:devices-l`: the short form is tab-separated (`EXAMPLESERIAL1\tdevice\n`) where the
  long form is space-padded columns, and only the state token is needed.

### Framing, measured

Confirmed against a live server. The host layer is `%04x`-length-prefixed ASCII; replies
are `OKAY` or `FAIL` followed by a `%04x`-length-prefixed payload. Inside `sync:`, framing
is a 4-byte ASCII ID plus a 4-byte little-endian argument.

Three framing facts that must be encoded once, in `foundation/adbwire`, and tested there:

- **`host:version`'s payload is itself ASCII hex** — a length field of `0004` wrapping the
  four characters `0029`. It is double-encoded, and reading the length as the value is an
  easy mistake.
- **A `LIS2` stream's terminating `DONE` is not a bare ID.** It carries a full 72-byte
  zeroed dirent body which must be consumed. A reader that stops at the ID leaves 72 stray
  zero bytes in the stream, and every subsequent command on that channel desyncs. This was
  hit during protocol discovery and it presented as *"all these directories are empty"* —
  a confident, wrong, silent answer rather than an error. It is the single most dangerous
  framing bug available here and deserves an explicit test.
- **An under-sized length prefix produces a device-shaped error.** Sending
  `0004host:version` makes the server read the request as `host` and reply `device offline
  (no transport)`. An off-by-one in our own encoder therefore surfaces as a phone problem,
  sending whoever debugs it to the hardware instead of to the framing code.

### Deadlines are mandatory

**Every read and write carries a deadline.** An over-sized length prefix makes the server
block waiting for bytes that never arrive, and it never replies — measured, no timeout, no
error, forever. A broker without its own deadlines hangs the archiver's run.

### Connection lifecycle: a sync `FAIL` is terminal

A single sync channel can carry many commands — measured with nine consecutive `LST2`
calls and mixed `LIS2`/`RECV` sequences on one socket. But the two failure classes behave
completely differently:

- **`LST2`/`LIS2` errors are in-band and recoverable.** The reply carries an `errno` in its
  `error` field and the channel stays usable. Confirmed: a nonexistent path returns
  `error=2` and two further commands succeeded on the same socket.
- **Any `RECV` `FAIL` kills the sync session.** Measured on fresh channels for each case —
  `open failed: No such file or directory`, `open failed: Permission denied`, `read failed:
  Is a directory` — and in every case the channel was dead afterwards.

So the fetch loop must reconnect after a failed `RECV`, and the spec says so rather than
leaving an implementation to discover it under load. On a first-ever run every unreadable
file costs a full transport re-establishment; that is acceptable but must be deliberate.

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

Confirmed available on the target device: `stat_v2`, `ls_v2` and `sendrecv_v2` are all
present, so the no-fallback rule costs nothing today. The 64-bit `size` was verified by
round-tripping a 27,190,943-byte file exactly.

#### The capability check must query the device, not the server

This is a trap with a live footgun in it, and naming the wrong service produces a check
that silently never fails.

**The feature list MUST be read from `host-serial:<serial>:features`.** It MUST NOT be read
from `host:host-features`, which reports the *adb server's* own capabilities. Measured, with
no phone attached at all:

```
host:host-features  ->  OKAY  'shell_v2,cmd,stat_v2,ls_v2,…,sendrecv_v2,…'
host:features       ->  FAIL  'no devices/emulators found'
```

`host:host-features` reports `stat_v2`, `ls_v2` and `sendrecv_v2` against an empty USB bus.
A broker wired to it would pass its V2 check on a disconnected device, on an unauthorized
device, and on a device whose `adbd` predates V2 entirely — the guarantee would rest on a
constant. That is a check that can never fail, which is the worst kind, because it never
looks broken.

Note also that `host:features` — without the `host-` prefix on the second word — is *not*
the server's list either. It implicitly selects a device and fails when none is usable. The
three names are easy to confuse and only one of them is evidence about the phone. The two
lists are genuinely different sets, not one a subset of the other: the server's includes
`push_sync`, the device's includes `devraw`, `app_info` and `delayed_ack`.

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

All six roots were confirmed to exist on the target device — directories, mode `0o2770`,
`uid=10269 gid=1023`, all on the same filesystem.

### There is no device-side confinement to fall back on

Worth stating before the rules, because it establishes what they are carrying. The sync
channel stats freely outside `/sdcard`:

```
/            error=0   dir 0o40755
/data/data   error=0   dir 0o40771   nlink=430
/data/misc   error=0   dir 0o41771
/init                error=13 (EACCES)
/proc/1/environ      error=13 (EACCES)
```

`adbd` applies no confinement of its own to the paths it will stat. **The rules below are
the only boundary between this transport and the rest of the device.** That is the design
premise, and it is now measured rather than assumed — which is also why `devicepath` gets
the densest test file in the repo.

### One spelling

Android reaches the same storage through several paths — `/sdcard`,
`/storage/self/primary`, `/storage/emulated/0`, and a per-user variant.

They are not merely equivalent, they are the *same inode*, confirmed by `dev`+`ino`:

```
/sdcard/DCIM                  dev=190 ino=4812
/storage/self/primary/DCIM    dev=190 ino=4812
/storage/emulated/0/DCIM      dev=190 ino=4812
```

**Only the `/sdcard/…` spelling is accepted.** A request naming any other prefix is
refused with `path_denied` and is *not* resolved to see whether it would have been
permitted. Resolving alternate spellings means writing path-resolution logic that the
confinement guarantee then depends on, and path-resolution logic is where confinement bugs
live. Refusing to resolve is a guarantee with no moving parts.

**But be honest about what the rule buys.** Since the three spellings reach the same
directory, refusing `/storage/emulated/0/…` does not deny access to anything — a caller
that wanted those bytes can ask for them under the accepted name. The single-spelling rule
is a **canonicalization rule, not an authority boundary**: it keeps the broker's own path
construction honest and it makes audit records comparable, because one directory cannot
appear in the log under three names. The authority boundary is the allowlist plus the
volume pin below. Earlier drafts of this document implied the spelling rule was itself
containment; it is not, and pretending otherwise would misplace the trust.

### Rejected path forms, and why each one is real

A path is rejected before anything else looks at it if it is not absolute, does not begin
with `/sdcard/`, contains a `..` segment, contains an empty segment or a trailing slash, or
contains a NUL byte.

Every one of these was measured against the device rather than assumed:

| Form | Device behaviour | Consequence if not rejected |
|---|---|---|
| `/sdcard/DCIM\x00x` | **`error=0`, returns the inode for `/sdcard/DCIM`** | The path is truncated at the NUL. The broker would validate one string, the device would act on a shorter one, and the audit log would record the string that was validated — a faithful record of an operation that never happened. |
| `/sdcard/DCIM/..` | **`error=0`, resolves to the volume root** | `..` genuinely escapes upward. Resolution is physical — symlinks expanded first — which is why `/sdcard/DCIM/..` succeeds while `/sdcard/../sdcard/DCIM` returns `error=2`. |
| `sdcard/DCIM` | **`error=0`, same inode as `/sdcard/DCIM`** | Relative paths resolve, with `adbd`'s working directory at `/`. `.` returns the root inode. |
| `/sdcard/DCIM/` and `/sdcard/DCIM//` | **`error=0`, same inode** | Two spellings of one path produce two different audit records for one operation. |

The NUL case is the one to remember. It is the only measured behaviour in this document
where a missing check would make the **audit log lie** rather than merely permit an
unwanted read.

### Segment-aware prefix matching

`/sdcard/Download` authorises `/sdcard/Download/a.jpg`. It does not authorise
`/sdcard/Download-private/a.jpg`. The comparison is over path segments, never over string
prefixes, and there is a test for exactly this case.

A `--root` that is a *parent* of an allowed root — `/sdcard`, or `/` — is refused with
`path_denied`. It is not silently narrowed to the permitted children beneath it. A caller
asking for `/sdcard` is asking for something the broker will not do, and telling it so is
more useful than quietly doing something else.

### Symlinks are the escape hatch — but the root is itself a symlink

Any application on the phone can create `/sdcard/Pictures/x` as a symlink pointing at
`/data/data/com.something/databases/`. A broker that checks only the *requested* path
string and then reads whatever comes back has an allowlist that any app on the device can
step around. That much is unchanged.

What changed is the rule. An earlier draft of this document said *"every component of the
path is checked, and a symlink at any component is refused."* **That rule is
unimplementable, because `/sdcard` is itself a symlink**, and so is one of the components
it resolves through. Measured:

```
LST2 /sdcard  ->  mode 0o120644  SYMLINK  size=21   (target: /storage/self/primary)
STA2 /sdcard  ->  mode 0o42770   dir      dev=190 ino=3252
```

| Path | Kind | dev | ino |
|---|---|---|---|
| `/storage` | dir `0o710` | 23 | 13 |
| `/storage/self` | dir `0o755` | 23 | 14 |
| `/storage/self/primary` | **SYMLINK** `0o120777` | 23 | 45 |
| `/storage/emulated` | dir `0o550` | 190 | 129 |
| `/storage/emulated/0` | dir `0o2770` | 190 | 3252 |
| `/sdcard` | **SYMLINK** `0o120644` | 65034 | 48 |

Two symlinks sit in the `/sdcard/…` prefix, both fixed by Android's storage layout rather
than created by any app. A rule refusing symlinks at every component rejects every path the
allowlist exists to permit. The rule has to distinguish *the platform's own root
indirection*, which is unavoidable, from *a symlink inside the media tree*, which is the
actual attack.

So confinement is now two mechanisms, and the second is stronger than what it replaces.

#### Part 1 — the volume pin

**Once per run, before any listing, the broker resolves the storage volume and pins it.**
It issues `STA2` on the compiled constant `/sdcard` — `STA2` follows symlinks, which is
exactly what is wanted here and is why it is in the vocabulary — and records the resulting
`(dev, ino)` as the run's volume identity.

The resolution must yield a directory. If it does not, or `STA2` fails, the run aborts with
`volume_unresolved` before any path is served. The device is not presenting storage in the
shape this broker understands, and guessing is not an option.

This resolution is the **only** place the broker traverses a symlink deliberately. It
happens once, in one function, against a compiled constant — not once per caller-supplied
path. `/sdcard` here is not an `AuthorizedPath` and does not become one; the volume
resolver takes the constant directly, which is why `/sdcard` remains denied as a `--root`
(see below) without contradiction.

#### Part 2 — everything beneath the root must be on the pinned volume, and must not be a symlink

- Traversal uses `LIST_V2`, whose dirents carry `mode` with `lstat` semantics **and `dev`**.
  An entry is omitted unless it is a regular file or a directory. Symlinks, sockets, FIFOs,
  block and character devices never appear in a listing and are never followed.
- **Every dirent's `dev` must equal the pinned `dev`.** An entry on any other filesystem is
  refused with `path_denied` regardless of its name or kind.
- `fetch` issues `LST2` (which does *not* follow symlinks — confirmed, see below) and
  requires both `S_ISREG` **and** a matching `dev` before issuing `RECV`.
- Every directory the walk descends into is re-checked against both conditions, so
  confinement is re-established at each step rather than asserted once at the root.

**Why the `dev` check is stronger than the string rule it replaces.** The old rule compared
spellings; this compares filesystems. A symlink escaping the media tree lands on a
different `dev` — the media volume is `dev=190`, `/data` is `dev=65088`, the root filesystem
is `dev=65034` — and is therefore detectable *by where it actually leads* rather than by
what it is named. It also catches a case the string rule never could: a **bind mount**
inside the tree, which introduces a foreign filesystem with no symlink involved anywhere.

The kind check and the `dev` check are deliberately both present. The kind check refuses
symlinks outright, including ones that stay on the same volume; the `dev` check catches
anything that leads off-volume by any mechanism. Neither subsumes the other.

**`dev` is not stable and must never be compiled in.** Device numbers are assigned at mount
time and can differ across reboots or remounts. The pin is established at runtime, per run,
and is recorded in the run's audit record so that two runs can be compared after the fact. A
hard-coded `190` would be a latent, silent failure the first time the phone rebooted.

**What this costs on a real device: nothing.** A bounded 12-directory walk of the media tree
found 1,778 regular files, all on `dev=190`, and **zero symlinks**. Refusing symlinks below
the root does not exclude any real content on this phone.

#### `LST2` does not follow symlinks; `STA2` does

Confirmed, and confirmed without ever opening a shell on the device — the root symlink
provided the test case for free:

```
LST2 /sdcard        ->  SYMLINK      LST2 /sdcard/DCIM  ->  dir
STA2 /sdcard        ->  dir          STA2 /sdcard/DCIM  ->  dir   (identical)
```

`RECV` also follows symlinks. This is not merely documented upstream, it is unavoidable
here: every successful read under `/sdcard/…` traverses two of them.

**Residual risk, stated rather than hidden:** there is a window between the `LST2` and the
`RECV`, and `RECV` follows symlinks on the device side. An adversary with code execution
on the phone could replace a regular file with a symlink inside that window. The sync
protocol offers no `openat`-style handle to close it, and the `dev` check cannot help
because it is performed on the pre-swap `LST2` result. This is accepted: an adversary who
already has code execution on the phone has better options than racing this broker, and
the alternative — not reading the phone at all — defeats the purpose. It is recorded here
so that nobody later mistakes the check for something stronger than it is.

### Enforcement is structural, not procedural

Confinement is not a check that each operation remembers to call. It is a type:

`devicepath.AuthorizedPath` has no exported fields and no exported way to construct a
non-zero value other than `ParseAuthorizedPath`, which applies every *string* rule above.
The storage layer's methods accept `AuthorizedPath` and nothing else. "Fetch a path that was
never checked" is therefore not a bug that review has to catch — it is a program that
does not compile.

The volume pin cannot work the same way, and it is worth being precise about why rather
than pretending one type covers both. The string rules are decidable from the path alone,
so they can be enforced by a constructor. The `dev` check depends on a value that only
exists at runtime, after a device is reachable — it is a property of the pairing of a path
with a particular mounted volume, not of the path.

So it gets its own type and the same treatment:

- `devicevolume.Volume` holds the pinned `(dev, ino)` and is constructible only by the
  resolver that performed the `STA2`. There is no literal, no zero value that means
  anything, and no setter.
- The `Storer` methods take **both** an `AuthorizedPath` and a `Volume`. A caller with a
  validated path but no pinned volume cannot express a fetch.
- Checking a dirent's `dev` against the `Volume` is the only exported operation on it.

The result is that both halves of confinement are unforgeable rather than remembered: a
path that skipped validation will not compile, and a fetch attempted before the volume was
pinned will not compile either.

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
{"proto":1,"status":"ok","serial":"EXAMPLESERIAL1","state":"device","model":"Pixel_8_Pro","broker":"0.1.0","adb":"1.0.41","volume":{"dev":190,"ino":3252}}
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

`probe` also confirms `STAT_V2` availability — via `host-serial:<serial>:features`, never
`host:host-features` — and fails with `unsupported` if it is absent, so that an incompatible
device is discovered before eleven listings are attempted.

`state` comes from the `host:devices` state token, **not** from parsing a `FAIL` message.
Four distinct prose failures were catalogued during discovery:

| Condition | `FAIL` message |
|---|---|
| No device attached | `no devices/emulators found` |
| Named serial absent | `device '<serial>' not found` |
| Present, not trusted | `device unauthorized.\nThis adb server's $ADB_VENDOR_KEYS is not set…` |
| No transport selected | `device offline (no transport)` |

They are distinguishable, so the temptation to branch on them is real — and it is exactly
the mistake this broker exists to remove from the CLI adapter. The state token is structured
and stable; the prose is neither, and one of these messages even contains advice (`try 'adb
kill-server'`) that the broker must never take.

Note also that **an empty device list is `OKAY` with a zero-length payload, not `FAIL`**.
Code that keys off `FAIL` alone will not notice that no phone is attached.

`probe` performs the volume resolution described under **Confinement** and reports the pinned
`volume` shown above, so that a run's audit trail records which filesystem it read and not
merely which path strings it used. It fails with `volume_unresolved` if `/sdcard` does not
resolve to a directory.

### 2. `list` — enumerate a tree

```
photos-adb-broker list --root /sdcard/DCIM/Camera [--max-depth 1] [--serial <id>]
```

`--max-depth 1` means immediate children only; omitted means unlimited. (The port's
`Recurse bool` maps to exactly these two cases.)

`--root` must lie within the allowlist, or the command fails with `path_denied` before any
transport connection is made.

The sync protocol's `LIST_V2` enumerates one directory, so recursion is driven by the
broker rather than the device — confirmed by measurement, listings are strictly one level.
That is an advantage here: every directory the walk descends into is re-checked against the
allowlist, re-checked for symlink-ness, and re-checked against the pinned volume, so
confinement is re-established at each step instead of being asserted once at the root.

`.` and `..` are not returned by `adbd` in a `LIS2` stream. The broker must still not
recurse into them if they ever appear; relying on the device to filter them is relying on
the wrong party.

**A `--max-depth 1` listing of an allowlist root returns nothing.** Measured: all seven
entries of `/sdcard/DCIM` and all eight of `/sdcard/Movies` are directories, and there is not
a single regular file at the top level of any of the six roots. This is worth stating in the
spec because the failure it produces is not an error — a depth-limited run reports a phone
with no photos on it, successfully. Any test that lists a root at depth 1 and asserts a
non-empty result will fail for reasons that have nothing to do with the code.

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
| `mtime_nsec` | MUST NOT | **The transport cannot provide it.** See below. |

`mtime_nsec` is downgraded from MAY to MUST NOT, and this closes an open question rather
than deferring it. The `STAT_V2`/`LIST_V2` reply was decoded field by field and carries
`atime`, `mtime` and `ctime` as 64-bit **whole seconds** with no sub-second companion field.
Sub-second precision is not unimplemented, it is **unavailable over this protocol**. A field
that can never be populated should not be in the contract inviting someone to try.

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

**Measured properties of `RECV` that the implementation must accommodate:**

- **Chunks are 64 KiB.** A 27,190,943-byte file arrived as 415 `DATA` packets with a maximum
  chunk of exactly 65536 bytes.
- **The byte count matches the listing's `size` exactly.** Verified on the largest file
  available. This is the property the archiver's cheap-path comparison depends on, and it
  holds.
- **A zero-byte file produces no `DATA` packets at all** — just an immediate `DONE`. An
  implementation that expects at least one `DATA`, or that treats "no data received" as a
  failure, will break on empty files, and there is one on the target device. Its digest is
  the empty-input SHA-256 `e3b0c442…`, which is exactly the value in this document's own
  example trailer.
- **A `RECV` failure kills the sync channel** and the next operation must reconnect. See
  *Connection lifecycle* under **Transport**. The three observed failures were `open failed:
  No such file or directory`, `open failed: Permission denied`, and `read failed: Is a
  directory`.

Throughput was measured at ~39.5 MiB/s, but over a USB 2.0 port that this is close to
saturating. It is a port measurement, not a device or protocol one, and is not a number to
size anything against.

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
| `path_denied` | Outside the allowlist, wrong spelling, a symlink, or off the pinned volume | **Aborts that source.** A configuration error, not a device condition. |
| `audit_unavailable` | The audit log cannot be opened or its head does not verify | Aborts the run before any device contact. |
| `volume_unresolved` | `/sdcard` does not `STA2` to a directory | Aborts the run. Storage is not in the expected shape; nothing is served. |
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

### Where the codes come from

The whole point of the broker is that these codes are derived from structured signals rather
than from English. There are exactly three sources, and only the last is prose:

1. **`errno` from `LST2`/`LIS2`.** The `error` field is a plain errno and is fully
   machine-readable — `0`, `2` (`ENOENT`), `13` (`EACCES`) were all observed. This is the
   primary source and covers per-path outcomes.
2. **The `host:devices` state token** — `device`, `unauthorized`, `offline`, … — for device
   state. Structured and stable.
3. **`FAIL` message text**, for the small set of transport-level failures that offer nothing
   better. The broker maps these to codes at a single chokepoint in `foundation/adbwire`,
   and that mapping is the one place in the binary where matching adb's English is
   tolerated. It is isolated there deliberately, with a test per string, so that a wording
   change upstream breaks one table rather than leaking into behaviour.

**`ENOENT` does not prove absence.** Measured: `/data/data/com.android.providers.media`
returns `error=2` even though it exists — `adbd` hides existence rather than admitting a
permission failure. So `root_not_found` must not be reported as authoritative evidence that
a tree is gone. For allowlist roots this is harmless, since they resolve or they do not; it
matters for the wording the archiver shows a human, which should say the root could not be
read rather than that it does not exist.

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

This is also why the NUL rejection under **Confinement** is an audit requirement and not
merely a hygiene rule. A path containing a NUL is truncated by the device, so an
unvalidated one would be logged in full while a shorter path was actually read. A log that
records a different operation from the one performed is worse than no log, because it is
believed.

The run's pinned volume is recorded once per run, as `{"op":"probe","volume":{"dev":190,
"ino":3252}}`, so that the trail says which filesystem was read and not merely which path
strings were used. Since `dev` is reassigned at mount time, this is the only way two runs
can be compared meaningfully.

**`usb:` path and `transport_id` must not be logged as device identity.** Measured across a
port change: the serial was stable while `usb:1-1` became `usb:1-2` and `transport_id` went
from `2` to `3`. `transport_id` is a monotonic per-connection counter — it advances on
re-enumeration, so a cached one identifies nothing and after enough churn could address a
*different* phone. The serial is the only durable handle.

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

**Honest status of this rule: it is justified by prudence, not by evidence from this
device.** Every name sampled during protocol discovery — across `DCIM`, `Movies`, `Music`
and `Recordings` — was pure ASCII, and no invalid-UTF-8 name was found to point at. The rule
stays, because the cost of the check is nil and the cost of being wrong is a silently
unarchived file, and because the folders most likely to contain such a name (messaging and
download caches) are exactly the ones not fully walked. But it should not be cited as
something the measurements confirmed, because they did not.

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
  volume.go                                 STA2 root resolution; the only deliberate symlink traversal
  reconnect.go                              re-establish transport after a terminal RECV FAIL
  convert.go                                toSync* / toBusFileRecord
business/types/devicepath/                  DevicePath, AuthorizedPath, the allowlist
business/types/devicevolume/                Volume — the pinned (dev, ino)
business/types/serial/                      Serial
business/types/mtime/                       Mtime
business/types/filekind/                    Kind — regular, dir, symlink, other
business/types/errcode/                     Code
foundation/audit/                           chain, append-only sink, journald anchor
foundation/adbwire/                         framing, host services, sync commands, FAIL→code table
```

### Type boundaries

| Layer | Type | Notes |
|---|---|---|
| App request | `ListRequest{Root, Serial string; MaxDepth int; Prune []string}` | flags arrive as primitives |
| App response | `FileRecordResponse{Path, PathB64 string; Size, Mtime int64}` | exactly the wire format above |
| Business | `FileRecord{Path devicepath.AuthorizedPath; Size int64; Mtime mtime.Mtime; Kind filekind.Kind}` | strong throughout |
| Storage row | `syncFileRecord{Path, PathB64 string; Size, MtimeSec int64; Mode uint32; Dev, Ino uint64}` | natives, as `LIST_V2` returns them |

`Dev` and `Ino` are new on the storage row and are `uint64` primitives there, per the house
rule that DB/wire rows hold natives only. They are parsed into `devicevolume.Volume` by the
storage-layer `toBusFileRecord`, which is also where the pinned-volume comparison happens —
the row cannot cross into Business unless its `dev` matches. `Volume` never appears in an App
request or response struct; `probe`'s response carries `dev` and `ino` as plain `int64`
fields, converted explicitly in `fromBusProbeResponse`.

**Types to confirm before implementation.** Per the house rules the concrete choices at each
boundary are yours, and three here are worth an explicit decision rather than my default:
`Dev`/`Ino` as `uint64` on the row (the kernel's own width) versus `int64` throughout to
avoid an unsigned/signed conversion at the JSON edge; whether `devicevolume.Volume` is its
own `business/types` package or lives inside `devicepath` alongside the allowlist; and
whether `probe`'s response nests `volume` as an object or flattens to `volume_dev` /
`volume_ino`.

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
`ParseAuthorizedPath` **and** checks the dirent's `dev` against the pinned `Volume`. Paths
that come *back* from the device are as untrusted as paths that come in from the caller — a
directory entry naming something outside the tree is precisely the attack the symlink rules
address, and re-parsing means the confinement type is never bypassed by data flowing the
other way. Since `adbd` applies no confinement of its own, this return path is not a
theoretical concern.

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

**The volume pin applies in fixture mode too**, resolved against the fixture directory's own
`(dev, ino)` rather than being stubbed out. This matters more than it looks: the pin is now
half of confinement, and a fixture mode that skips it can only test the other half. It also
makes the escape case cheap to test for real — a symlink inside the fixture tree pointing at
`/tmp` crosses a filesystem boundary on most hosts and must be refused, and one pointing
elsewhere within the same filesystem must still be refused by the kind check. Those are the
two mechanisms exercised independently, on hardware nobody has to plug in.

A caveat worth writing down before someone hits it: on a host where the fixture directory and
the escape target share a filesystem, the `dev` half of that test silently passes for the
wrong reason. Fixture tests that mean to exercise the `dev` check must place the target on a
genuinely different mount, or assert on the refusal reason rather than merely the refusal.

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
`no_adb_server`, `audit_unavailable` and `volume_unresolved` are compatible under the rules
above, and nothing consumes the interface yet.

The one field that changed meaning rather than being added is `mtime_nsec`, which went from
MAY to MUST NOT. That is a tightening of a field no implementation ever populated, on an
interface with no consumers, so it does not warrant a `proto` bump — but it is recorded here
rather than passed over silently, since "MAY became MUST NOT" is exactly the kind of edit
that would deserve one on a shipped interface.

---

## Build order

1. `foundation/adbwire` — connect to `127.0.0.1:5037`, host services, `sync:`, `LST2`,
   `STA2`, `LIS2`, `RECV`, deadlines on every exchange, and the `FAIL`→code table. Tested
   against a real adb server with **no device attached**, which exercises the failure paths
   first — and which the discovery experiment showed is a genuinely productive place to
   start: the empty-list-is-`OKAY` case, all four `FAIL` strings, and every malformed-framing
   case are reachable with no phone. Must include the `DONE`-carries-72-zero-bytes test and
   the double-encoded `host:version` payload.
2. `business/types/*` — `devicepath` with the full allowlist rule set, `devicevolume`,
   `mtime`, `filekind`, `serial`, `errcode`. `devicepath` gets the densest test file in the
   repo. Every one of these is a measured device behaviour, not a hypothetical, and each
   deserves a named test case:
   - `Download-private` — segment-boundary matching
   - all three spellings of the same directory
   - `..` mid-path, and `..` as the final segment (which resolves to the volume root)
   - a NUL byte (the device truncates at it)
   - a relative path such as `sdcard/DCIM` (the device resolves it)
   - trailing slash and doubled slash (the device accepts both)
   - parent-of-root: `/sdcard` and `/`
   - `devicevolume`: a dirent whose `dev` differs from the pin is refused
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
   recordings and pictures. All six were confirmed to exist on the target device, so the
   list is at least not wrong; whether it is *complete* is still open and is deliberately
   parked until we are less busy. Revisiting it needs a one-off inspection of the top level
   of the volume, which is a deliberate act rather than something the tool does — `/sdcard`
   remains denied as a `--root`.
2. **Which uid does the broker run as, and is it the same one `photos` runs as?** If they
   are the same, the audit log is writable by whatever compromises `photos`, and the
   `chattr +a` is doing all the work. A dedicated uid is better and costs nothing. **Still
   unanswered and still the most consequential open item here** — it decides whether the
   audit guarantee has two independent controls or one.
3. **Off-box anchoring.** Deferred, because it would introduce network access to a binary
   that otherwise has none. Worth revisiting if the threat model ever includes local root.
4. **Is the volume pin the right mechanism, and is `(dev, ino)` the right pin?** This is the
   one genuinely new design decision the measurements forced, and it replaces a rule that
   could not work. It should be reviewed on its merits rather than adopted because it was
   the first fix to hand. Specific things to push on: whether `ino` adds anything over `dev`
   alone; whether a remount mid-run could change `dev` underneath a long first run and what
   should happen if it does; and whether refusing *all* symlinks below the root is too blunt
   if a future device ships one legitimately.
5. **Should `list` and `fetch` be combinable?** A `fetch-many` reading paths from stdin
   would amortize spawn cost on a first-ever run. Explicitly *not* requested for v1 — the
   measurement above says it is a 3% effect — but it is the natural extension if a
   persistent mode is ever wanted. Note that it would need every path re-parsed through
   `ParseAuthorizedPath` individually, which is cheap. The terminal-`RECV`-`FAIL` finding
   strengthens the case slightly: a persistent mode would amortize reconnects too.
6. **A non-UTF-8 filename has never been observed on this device.** The `path_b64` rule is
   retained on prudence. If it ever matters it will matter silently, so there is nothing to
   watch for — this is recorded so the rule is not mistaken for a measured requirement.

**Answered and closed since the first draft:** whether `STAT_V2` offers sub-second `mtime`
(it does not — whole seconds only, so `mtime_nsec` is now MUST NOT); whether `LST2` follows
symlinks (it does not, `STA2` does); and whether the six roots exist (they do).
