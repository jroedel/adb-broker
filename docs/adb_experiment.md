# ADB Discovery Experiment

**Status:** complete, run 2026-07-30. Findings at the end; ten spec changes fall
out of them, one of which invalidates part of the confinement design.
**Purpose:** replace the assumptions in `docs/ADB_BROKER.md` with measurements.

The broker spec was written from protocol knowledge, not from this phone. Several
of its load-bearing claims are unverified, and at least two of them, if wrong,
change the design rather than the code. This experiment exists to find that out
before any Go is written.

Everything below is **read-only against the device**. Nothing in the plan writes
to the phone, installs anything, or changes a setting, with one clearly marked
exception in Phase 7 that will not run without a separate yes.

---

## What we already know (host-side, no device involved)

| Fact | Value |
|---|---|
| adb client | 1.0.41, `34.0.4-debian`, `/usr/lib/android-sdk/platform-tools/adb` |
| adb server | **already running**, pid 29995, listening `127.0.0.1:5037` |
| Host tools | `python3`, `nc`, `xxd`, `hexdump` |

The server being up already matters: the spec forbids the broker from ever
spawning one, and we can honour that for the whole experiment too.

---

## Method

A single throwaway Python script speaking the wire protocol over a raw TCP
socket to `127.0.0.1:5037`. **No adb client invocations, no `adb shell`, no
subprocess at all** — the point is to learn the protocol the broker will
actually speak, not the one the CLI wraps.

The script lives in the scratchpad, not the repo. It is an instrument, not a
deliverable. Only the findings come back into `docs/`.

Every exchange is captured as an annotated hex dump so the findings rest on
bytes rather than on my reading of them.

---

## Privacy and redaction rules

This is your personal phone. Filenames in `DCIM` and `Download` are personal
data and you said you don't want the directory structure pulled into context.
So, binding on the whole experiment:

- **Never record a filename.** Where a name is needed to prove something, record
  its **length in bytes**, its **byte class** (pure ASCII / contains
  non-ASCII / contains bytes invalid as UTF-8), and nothing else.
- **Never record file contents.** Phase 6 fetches one file; the finding is its
  size and SHA-256, not its bytes and not its name.
- **Directory listings are reported as aggregates** — entry count, mode
  histogram, size range. Never an enumeration.
- Serial numbers are recorded truncated (`EXAM…AL1`).

If a finding genuinely cannot be demonstrated under these rules, I'll say so and
ask rather than quietly widen them.

**Where this rule was broken, and the correction.** The findings below quote wire
output verbatim, and I recorded the device's real serial in full six times rather
than truncating it as this section requires. Every occurrence has since been
replaced with the placeholder `EXAMPLESERIAL1`, chosen at 14 characters to match
the original's length so the column alignment in the `host:devices-l` example
stays faithful. The real value is being purged from git history separately. The
rule was right and it was not followed; noting it here rather than silently
fixing it, because a redaction policy that is quietly violated is worse than one
that was never written.

---

## Phases

Each phase is gated on the previous one. I'll stop and report between phases if
anything contradicts a hypothesis, rather than pressing on to the end.

### Phase 0 — Host protocol, no device attached

Confirm the framing before a phone is anywhere near it.

**Hypothesis.** A client sends `%04x`-length-prefixed ASCII requests. The server
replies `OKAY` or `FAIL`, and payloads are themselves `%04x`-length-prefixed.

**Requests:** `host:version`, `host:features`, `host:devices-l`.

**What I want to learn**
- Exact framing, byte for byte.
- What `host:devices-l` returns with **nothing plugged in** — the empty-device
  case the broker must distinguish from a failure.
- Whether `host:features` (the *server's* features) is distinct from the
  device's feature set. The spec's hard-fail on `STAT_V2` depends on reading the
  right one.

**Falsifies:** the transport section's framing description, and the
`no_device` error path.

---

### Phase 1 — Device attached, before you tap "Allow"

**You plug the phone in. Do not dismiss or accept the trust dialog yet — tell
me when it's showing.**

This state is short-lived and hard to recreate, so it's worth capturing
deliberately rather than accidentally.

**Hypothesis.** `host:devices-l` lists the serial with state `unauthorized`, and
`host:transport:<serial>` fails with a distinguishable message.

**What I want to learn**
- The exact string for the `unauthorized` error code in the spec's taxonomy.
- Whether an unauthorized device is distinguishable from an absent one *without*
  a timeout — i.e. can the broker fail fast and tell the user which it is.

**Falsifies:** the `unauthorized` row of the error table.

---

### Phase 2 — Authorized, feature negotiation

You tap Allow. **Please do not tick "always allow"** unless you want to — the
experiment doesn't need it.

**Hypothesis.** `host-serial:<serial>:features` returns a comma-separated list
containing `stat_v2`, `ls_v2`, and `sendrecv_v2`.

**What I want to learn**
- Whether this device actually supports V2. **This is the assumption the whole
  spec rests on.** If it doesn't, the "hard-fail, never degrade to 32-bit sizes"
  decision has to be revisited, because the alternative is not backing up your
  phone.
- The full feature list, so we know what else the broker is choosing not to use.

**Falsifies:** the `unsupported` error path and the no-fallback decision.

---

### Phase 3 — Opening a sync channel

**Hypothesis.** `host:transport:<serial>` → `OKAY`, after which the same socket
carries a device stream; sending `sync:` → `OKAY` puts it in sync mode, and from
there the protocol is 4-byte ASCII IDs + 4-byte little-endian arguments.

**What I want to learn**
- Whether the socket is reusable for multiple sync commands or whether each
  operation needs a fresh connection. Directly determines the broker's
  connection lifecycle and its `list`-then-`fetch` cost.
- What `QUIT` / socket close does, and whether a half-finished `RECV` can be
  abandoned cleanly.

**Falsifies:** nothing in the spec — the spec is silent here, which is itself a
gap.

---

### Phase 4 — `LST2` on the allowlist roots

The first phase that touches real paths. Exactly nine `LST2` calls, no
enumeration:

```
/                      expect: denied by policy, but what does the device say?
/sdcard                parent-of-root — spec denies it outright
/sdcard/DCIM
/sdcard/Download
/sdcard/Movies
/sdcard/Music
/sdcard/Pictures
/sdcard/Recordings
/data/data             expect: permission error, not a crash
```

**Hypothesis.** `LST2` (`ID_LSTAT_V2`) sends `LST2` + `<u32le pathlen>` + path
and returns a fixed 72-byte reply: id(4) error(4) dev(8) ino(8) mode(4)
nlink(4) uid(4) gid(4) size(8) atime(8) mtime(8) ctime(8), little-endian.

**What I want to learn**
1. **Is `/sdcard` itself a symlink?** On most Android builds `/sdcard` →
   `/storage/self/primary` → `/storage/emulated/0`. If so, the spec's rule
   "refuse a symlink at every path component" **rejects every path we intend to
   allow**, and the confinement design needs rework before it's written, not
   after. I consider this the single highest-value question in the experiment.
2. Which of the six roots exist on this device. `Recordings` in particular is
   OEM-dependent. Reported as exists/absent only — no contents.
3. Whether `size` is genuinely 64-bit, and whether `mtime` is seconds or has
   sub-second precision available.
4. What a permission failure looks like: `error` field set, or a `FAIL` packet,
   or a hang. Determines whether `path_denied` and a device-side EACCES are
   distinguishable.
5. Whether the reply is exactly 72 bytes on this adbd build.

**Falsifies:** potentially the entire confinement section (item 1), the
no-fallback size decision (item 3), and the error taxonomy (item 4).

---

### Phase 5 — `LIS2` on one root

One non-recursive listing of **one** root, chosen as whichever of the six looks
smallest in Phase 4 — `Recordings` or `Movies` if present.

**Hypothesis.** `LIS2` returns a stream of `DNT2` records (stat_v2 fields +
`namelen` + name), terminated by `DONE`.

**What I want to learn**
- The dirent layout, byte for byte.
- Whether `.` and `..` appear (the broker must not recurse into them).
- Whether listing is one level only, confirming the broker owns recursion.
- Whether any name contains bytes that aren't valid UTF-8 — the spec's
  "filenames are bytes" rule needs at least one real example to justify itself,
  or an honest note that we didn't find one.
- Behaviour on a large directory: is there a cap, does it stream, does it block.

**Reported as:** entry count, mode histogram, size range, name-length
distribution, byte-class counts. **No names.**

---

### Phase 6 — `RECV` one file

A single fetch of the smallest regular file found in Phase 5.

**Hypothesis.** `RECV` + `<u32le pathlen>` + path returns `DATA` + `<u32le len>`
+ bytes, repeating, then `DONE`.

**What I want to learn**
- Chunk size, and whether `sendrecv_v2` / `RCV2` changes it.
- Whether the byte count matches the `size` from `LST2` exactly — the archiver's
  cheap-path comparison depends on it.
- What a mid-transfer failure looks like, if one occurs naturally.
- Throughput, roughly, for sizing expectations on a first full run.

**Reported as:** size, SHA-256, elapsed time. Not the name, not the bytes.

---

### Phase 7 — Negative tests and symlink behaviour

**7a — Malformed and out-of-policy paths (no approval needed).**

Send paths the broker will reject, to learn what the *device* does with them —
so we know whether the broker's own validation is the only thing standing
between us and a bad outcome:

```
/sdcard/DCIM/../../data      does adbd normalise .. server-side?
/sdcard/Download-private     segment-boundary confusion
/sdcard/DCIM/                trailing slash
/sdcard/DCIM/<NUL>x          embedded NUL
(empty string)
/storage/emulated/0/DCIM     the other spelling of an allowed path
```

The last one matters: the spec accepts only the `/sdcard/…` spelling and refuses
others without resolving them. If `/storage/emulated/0/…` reaches the same
files, we should know that we're relying on a *convention* rather than a
*boundary*, and say so in the spec.

**7b — Symlink behaviour (NEEDS YOUR EXPLICIT YES, separately).**

The spec claims `LST2` does not follow symlinks while `RECV` does, and calls the
gap between them an accepted TOCTOU risk. Confirming that needs a symlink on the
device to aim at.

- **If Phase 4 shows `/sdcard` is itself a symlink**, we get this test for free
  and 7b is unnecessary. I expect this is what happens.
- **Otherwise**, proving it requires creating a symlink under `/sdcard`, which
  requires `adb shell ln -s` — i.e. exactly the shell channel the broker is
  designed never to open. It would be me, running a write command, on your
  personal phone.

I am not going to do that on the strength of this document. If Phase 4 doesn't
hand us a natural symlink, I'll come back and ask, and "no" is a fine answer —
we'd record the claim as untested rather than pretend otherwise.

---

## Risks

| Risk | Mitigation |
|---|---|
| Writing to the phone | No `SEND`, no `adb shell`, no subprocess. Phase 7b is the only write and is separately gated. |
| Personal data in context | Redaction rules above; aggregates only; no names, no contents. |
| Leaving the phone in a debug state | We don't enable anything. You revoke USB debugging afterwards if you want; I'll remind you. |
| Hung socket blocking the adb server | Explicit socket timeouts; each phase opens and closes its own connection. |
| Trust dialog persisting | I'll ask you not to tick "always allow". |

---

## What success looks like

Not "it worked." Success is that every hypothesis above is either confirmed with
a hex dump or falsified, and that `docs/ADB_BROKER.md` gets an evidence-backed
revision. I specifically expect **Phase 4 item 1 to falsify part of the
confinement design**, and I'd rather find that now than in the middle of writing
`business/types/devicepath`.

**Outcome:** it did. `/sdcard` is a symlink, so the "no symlink at any path
component" rule rejects every path it was written to allow (§4.1). Phase 7b's
approval request became unnecessary as a side effect — the same symlink provided
the following-behaviour test for free, so no fixture was created and `adb shell`
was never invoked. Two findings nobody was looking for turned up as well: the
`host:host-features` false-positive (§1b) and NUL path truncation (§7a).

---

## Findings

Measured 2026-07-30. Device serial `EXAM…AL1`, `usb:1-1`, `transport_id:2`.

### Phase 0 — host framing: **confirmed**

Framing is exactly as hypothesised. Client sends `%04x`-length-prefixed ASCII;
server replies `OKAY`/`FAIL` followed by a `%04x`-length-prefixed payload.

```
--> b'000chost:version'
<-- b'OKAY' b'0004' b'0029'        # 0x29 = 41
```

The version payload is *itself* ASCII hex, so it is double-encoded: a 4-byte
length field `0004` wrapping the 4 characters `0029`. Worth noting because it is
an easy place to write a parser that reads the length as the value.

**No device attached** (measured later, phone unplugged — the gap flagged in the
first pass is now closed):

```
--> host:devices     <-- OKAY 0000  (empty payload)
--> host:devices-l   <-- OKAY 0000  (empty payload)
```

An empty device list is **`OKAY` with a zero-length payload, not a `FAIL`**. The
broker must treat "success with nothing in it" as the no-device case; anything
that keys off `FAIL` alone will misreport it.

The adb server also **survived the unplug** — still pid 29995 across the whole
experiment. The spec's "never spawn a server" rule costs nothing in practice:
the server outlives device churn.

### Phase 0b — framing robustness: **new error strings, one landmine**

Deliberately malformed requests, all with no device attached:

| Sent | Reply |
|---|---|
| `000ahost:bogus` | `FAIL` `unknown host service` |
| `0004host:version` (prefix too short) | `FAIL` `device offline (no transport)` |
| `0099host:version` (prefix too long) | **blocks forever, no reply** |
| `zzzzhost:version` (non-hex prefix) | socket closed, **empty reply** |
| `0000` (zero length) | socket closed, empty reply |
| `host:version` (no prefix) | socket closed, empty reply |
| `0005sync:` (no transport) | `FAIL` `device offline (no transport)` |

Three things the broker has to handle that the spec doesn't mention:

1. **A too-short length prefix is a landmine.** `0004host:version` makes the
   server read the request as `host`, which fails with `device offline (no
   transport)`. An off-by-one in our own framing would surface as a *device*
   error, sending whoever debugs it to the phone instead of to the encoder.
   Argues for framing being a single tested chokepoint in `foundation/adbwire`.
2. **A too-long prefix hangs.** The server blocks waiting for bytes that never
   come, and never replies. The broker needs its own read deadline on every
   exchange; the spec currently specifies no timeouts at all.
3. **Several malformed inputs get a silent close, not an error.** `EOF` with
   zero bytes read is a distinct outcome from `FAIL`, and must not be reported
   as a protocol error with an empty message.

`sync:` without a transport fails cleanly with `device offline (no transport)`,
confirming the sync service is transport-gated.

### Error strings observed so far

Four distinct messages, all prose, none machine-readable:

| Condition | Message |
|---|---|
| No device attached | `no devices/emulators found` |
| Named serial absent | `device 'EXAMPLESERIAL1' not found` |
| Device present, not trusted | `device unauthorized.\nThis adb server's $ADB_VENDOR_KEYS is not set\n…` |
| No transport selected | `device offline (no transport)` |

They *are* distinguishable, so mapping them to the spec's error taxonomy is
possible — but it means matching English that adb upstream is free to reword.
The `host:devices` state token is stable and structured; the prose is neither.

### Phase 1 — unauthorized state: **confirmed, plus one trap**

`host:devices-l` while the trust dialog was on screen:

```
'EXAMPLESERIAL1         unauthorized usb:1-1 transport_id:2\n'
```

All three of `host:transport-any`, `host:transport:<serial>`, and
`host-serial:<serial>:features` returned the **identical** `FAIL` payload:

```
device unauthorized.
This adb server's $ADB_VENDOR_KEYS is not set
Try 'adb kill-server' if that seems wrong.
Otherwise check for a confirmation dialog on your device.
```

Answers to the Phase 1 questions:

- **Fails fast, no timeout.** The broker can report `unauthorized` immediately.
- **But not distinguishable by which request failed** — the error is the same
  prose for every one of them. Parsing that English is fragile, and it embeds
  advice (`adb kill-server`) the broker must never take.

**Recommendation:** the broker should determine device state from
`host:devices`, not from a `FAIL` string. The short form is tab-separated and
trivial to parse:

```
'EXAMPLESERIAL1\tunauthorized\n'
```

versus the space-padded `host:devices-l`. **The spec currently specifies
`host:devices-l`; it should specify `host:devices`.** We need the state token,
not the long form, and column-padded output is a worse parse for no gain.

### Phase 1b — `host:features` is a trap: **spec bug found**

This is the important one, and it is not what the phase was looking for.

`host:features` **does not report the server's features.** It implicitly selects
a device, and with the phone unauthorized it failed:

```
--> b'000dhost:features'
<-- b'FAIL' 'device unauthorized. ...'
```

The server's own feature list is a *different* service, `host:host-features`,
and it **succeeded while the device was unauthorized** — returning, among
others, exactly the three features the spec's hard-fail check looks for:

```
shell_v2,cmd,stat_v2,ls_v2,fixed_push_mkdir,apex,abb,
fixed_push_symlink_timestamp,abb_exec,remount_shell,track_app,
sendrecv_v2,sendrecv_v2_brotli,sendrecv_v2_lz4,sendrecv_v2_zstd,
sendrecv_v2_dry_run_send,openscreen_mdns,push_sync
```

**Why this matters.** A broker that queried `host:host-features` to decide
whether `STAT_V2` is available would see `stat_v2,ls_v2,sendrecv_v2` and
conclude yes — **without a phone in the room**. The check would pass on an
unauthorized device, on a disconnected device, and on a device whose adbd
predates V2 entirely. The spec's whole "hard-fail rather than silently truncate
64-bit sizes to 32" guarantee would be resting on a constant.

That is a false-negative-proof check, which is the worst kind: it never fires,
so it never looks broken.

**Confirmed with no device at all.** Repeating the query with the phone
unplugged:

```
--> host:host-features   <-- OKAY  'shell_v2,cmd,stat_v2,ls_v2,…,sendrecv_v2,…'
--> host:features        <-- FAIL  'no devices/emulators found'
```

`host:host-features` still reports `stat_v2`, `ls_v2` and `sendrecv_v2` with
**nothing plugged in**. The hypothesis is no longer a worry, it is measured: a
broker wired to that service would pass its V2 capability check against an empty
USB bus.

The two lists are also genuinely different sets, not one a subset of the other —
the server's list has `push_sync`, which the device's lacks; the device's has
`devraw`, `app_info`, `server_status`, `track_mdns`, `delayed_ack` and
`devicetracker_proto_format`, which the server's lacks. They are separate facts
about separate things, and only one of them is about the phone.

**Recommendation:** the spec must name the service explicitly, and it must be
the per-device one — `host-serial:<serial>:features` — with a note that
`host:host-features` is the server's own list and is *not* evidence about the
device. Phase 2 confirms what the device itself reports.

### Phase 1c — port change (USB-C → USB-A): **reproduces exactly**

The unauthorized-state sweep was repeated after moving the phone to a USB-A
port, to separate protocol properties from properties of one connection. Only
two values changed:

| | USB-C | USB-A |
|---|---|---|
| `usb:` locator | `usb:1-1` | `usb:1-2` |
| `transport_id` | `2` | `3` |

Everything else was byte-identical, including all three 167-byte `FAIL` payloads
and the `unauthorized` state token.

**`transport_id` is a monotonic per-connection counter, not an identity.** It
incremented because the phone re-enumerated, not because anything about the
device changed. A broker that cached a `transport_id` would break across a
replug — and in the worse case would address a *different* device after one.
The serial is stable across ports and is the only safe handle. The spec already
keys on serial; this is the measurement that justifies it.

Corollary for the audit log: `usb:` path and `transport_id` are not durable
identifiers and should not be logged as though they identify a device.

### Phase 2 — device feature negotiation: **confirmed**

After authorization, `host:devices` reports the state token flipping from
`unauthorized` to `device`:

```
'EXAMPLESERIAL1\tdevice\n'
```

And the per-device feature list — the one that is actually evidence about the
phone — includes all three features the design depends on:

```
shell_v2,cmd,stat_v2,ls_v2,fixed_push_mkdir,apex,abb,
fixed_push_symlink_timestamp,abb_exec,remount_shell,track_app,
sendrecv_v2,sendrecv_v2_brotli,sendrecv_v2_lz4,sendrecv_v2_zstd,
sendrecv_v2_dry_run_send,openscreen_mdns,devicetracker_proto_format,
devraw,app_info,server_status,track_mdns,delayed_ack
```

**`stat_v2` ✓  `ls_v2` ✓  `sendrecv_v2` ✓**

So the spec's "hard-fail rather than degrade to 32-bit sizes" decision stands for
this device — we are not going to be forced into the fallback. Note also that
`shell_v2`, `cmd`, `abb`, `abb_exec` and `remount_shell` are all offered: the
capabilities the broker refuses to use are available, which is precisely why the
refusal has to be structural rather than a matter of not calling them.

### Phase 3 — sync channel: **confirmed, and reusable**

`host:transport:<serial>` → `OKAY`, then `sync:` → `OKAY`, then binary framing of
4-byte ASCII ID + 4-byte little-endian argument, as hypothesised.

**One socket carried nine consecutive `LST2` commands**, and later a mixed
sequence of `LIS2` and `RECV`. The channel is reusable and does not need
tearing down per operation — but see Phase 6c, which is the sharp edge.

### Phase 4 — `LST2` on the allowlist roots

**Wire format confirmed exactly.** 72-byte fixed reply, little-endian:

```
id(4) error(4) dev(8) ino(8) mode(4) nlink(4) uid(4) gid(4)
size(8) atime(8) mtime(8) ctime(8)
```

`size` is genuinely 64-bit — the largest file measured was 27,190,943 bytes and
round-tripped exactly. `mtime` is **whole seconds**, 64-bit; there is no
sub-second field, which settles the spec's open question: `mtime_nsec` is not
merely unimplemented, it is unavailable over this protocol.

**All six allowlist roots exist**, all directories, mode `0o2770` (setgid),
`uid=10269 gid=1023`, all on `dev=190`. `Recordings` is present but empty on this
device.

#### 4.1 — `/sdcard` is a symlink: **the confinement design is broken as written**

```
LST2 /sdcard    -> mode 0o120644  SYMLINK  size=21  dev=65034 ino=48
STA2 /sdcard    -> mode 0o42770   dir      size=3452 dev=190  ino=3252
```

The spec's rule is *"refuse a symlink at every path component."* `/sdcard` is
itself a symlink, so **that rule rejects every path the broker is meant to
allow.** This is the failure I flagged as most likely in the plan, and it is
confirmed.

The full chain, measured component by component:

| Path | Kind | dev | ino | Notes |
|---|---|---|---|---|
| `/storage` | dir `0o710` | 23 | 13 | |
| `/storage/self` | dir `0o755` | 23 | 14 | |
| `/storage/self/primary` | **SYMLINK** `0o120777` | 23 | 45 | size 19 |
| `/storage/emulated` | dir `0o550` | 190 | 129 | |
| `/storage/emulated/0` | dir `0o2770` | 190 | 3252 | |
| `/sdcard` | **SYMLINK** `0o120644` | 65034 | 48 | size 21 |

Symlink sizes are the target-string lengths and they identify the targets
exactly: 21 = `/storage/self/primary`, 19 = `/storage/emulated/0`. So there are
**two** symlinks in the `/sdcard/…` prefix, and both are fixed by Android's
storage layout rather than being anything a user or app created.

Note also `dev=65034` for `/sdcard` versus `dev=190` for its target: the symlink
lives on the root filesystem and the media volume is a different filesystem.

#### 4.2 — Three spellings reach the same inode

```
/sdcard/DCIM                  dev=190 ino=4812
/storage/self/primary/DCIM    dev=190 ino=4812
/storage/emulated/0/DCIM      dev=190 ino=4812
```

Identical `dev`+`ino`: these are not similar paths, they are **the same
directory**. The spec's "accept only the `/sdcard/…` spelling, refuse others
without resolving them" is therefore a **convention, not a boundary** — exactly
as the plan predicted.

That is not a reason to drop the rule. The broker only ever *sends* paths it
constructed itself from a compiled root, so a single accepted spelling keeps its
own code honest and keeps the audit log comparable. But the spec must stop
implying that refusing `/storage/emulated/0/…` denies access to anything.

#### 4.3 — There is no device-side confinement at all

```
/            error=0   dir 0o40755   dev=65034
/data/data   error=0   dir 0o40771   nlink=430
/data/misc   error=0   dir 0o41771
/init                error=13 (EACCES)
/proc/1/environ      error=13 (EACCES)
/data/data/com.android.providers.media   error=2 (ENOENT — exists, hidden)
```

The sync channel stats freely outside `/sdcard`. `/`, `/data/data` and
`/data/misc` all return `error=0`. **The broker's allowlist is the only thing
standing between this transport and the rest of the filesystem** — which is the
design premise, now measured rather than assumed. It also means the confinement
code is genuinely load-bearing and deserves the densest test file in the repo.

Note `/data/data/com.android.providers.media` reports `ENOENT` rather than
`EACCES`: adbd hides existence rather than admitting it. So `ENOENT` does not
prove absence, and the broker must not report "not found" as though it were.

**`error` is a plain errno and is machine-readable** — `0`, `2` (ENOENT), `13`
(EACCES). This is a much better basis for the error taxonomy than the host
layer's English prose.

### Phase 7a — malformed and policy-violating paths

| Sent | Result |
|---|---|
| `/sdcard/DCIM/..` | **error=0**, resolves to `dev=190 ino=3252` = `/storage/emulated/0` |
| `/sdcard/DCIM/../../data` | error=2 |
| `/sdcard/../sdcard/DCIM` | error=2 |
| `/sdcard/Download-private` | error=2 |
| `/sdcard/DCIM/` (trailing slash) | **error=0**, same inode as `/sdcard/DCIM` |
| `/sdcard/DCIM//` | **error=0**, same inode |
| `/sdcard/DCIM\x00x` | **error=0, same inode as `/sdcard/DCIM`** |
| `` (empty) | error=2 |
| `.` | **error=0**, `dev=65034 ino=2` = `/` |
| `sdcard/DCIM` (relative) | **error=0**, same inode as `/sdcard/DCIM` |
| `/mnt/sdcard/DCIM` | error=13 |

Four of these matter:

1. **A NUL byte silently truncates the path.** `/sdcard/DCIM\x00x` returns the
   inode for `/sdcard/DCIM` — adbd/the kernel treat it as a C string. This is the
   nastiest result in the experiment. If the broker validates a Go string
   containing a NUL and then sends it, **the device acts on a different path than
   the one that was validated and the one that gets written to the audit log.**
   The log would be a faithful record of something that never happened. The
   spec's NUL rejection was already there; it is now justified by measurement
   rather than by caution.
2. **`..` really does traverse**, and lands outside the root — `/sdcard/DCIM/..`
   resolves to the volume root. Resolution is physical (symlinks expanded first),
   not lexical, which is why `/sdcard/../sdcard/DCIM` fails while
   `/sdcard/DCIM/..` succeeds. Rejecting `..` is mandatory.
3. **Relative paths resolve**, with adbd's working directory at `/` — `.` returns
   the root inode and `sdcard/DCIM` returns the DCIM inode. Rejecting
   non-absolute paths is mandatory.
4. **Trailing and doubled slashes are accepted** by the device as equivalent. The
   broker must reject or canonicalize them *before* the allowlist check, or two
   spellings of one path produce two different audit records.

### Phase 7b — symlink following: **resolved with no shell needed**

The free test the plan hoped for materialised, because `/sdcard` is a symlink:

```
LST2 /sdcard        -> SYMLINK (0o120644)
STA2 /sdcard        -> dir     (0o42770)   <- DIFFER
LST2 /sdcard/DCIM   -> dir
STA2 /sdcard/DCIM   -> dir                 <- identical, as expected
```

**`LST2` does not follow symlinks; `STA2` does.** The spec's claim is confirmed
and no symlink had to be created on the phone — `adb shell` was never invoked,
and the Phase 7b approval I said I'd come back for is not needed.

`RECV` also follows symlinks, proven implicitly and unavoidably: every successful
read under `/sdcard/…` traverses two of them. So the TOCTOU gap the spec
documents between `LST2` and `RECV` is real.

Encouragingly, a bounded 12-directory walk over the media tree found **1778
regular files and zero symlinks**, all on `dev=190`. Refusing symlinks below the
root costs nothing on this device.

### Phase 5 — `LIS2`

`DNT2` record layout confirmed: the 72-byte stat body plus a 4-byte `namelen`
(76 bytes total with the ID), followed by `namelen` raw name bytes, stream
terminated by `DONE`.

**Framing trap, found the hard way:** `DONE` is not a bare 4-byte ID — it carries
a full zeroed 72-byte dent body. My first reader broke on the ID without
consuming it, leaving 72 stray zero bytes that desynced every subsequent command
on that channel and produced a convincing but entirely false "these directories
are all empty" result. Worth stating plainly because a Go implementation will hit
exactly this, and the failure mode is silent wrong answers rather than an error.

Other results:

- **`.` and `..` are not returned** by adbd. The broker does not have to filter
  them, though it should not rely on that.
- **Listing is one level only** — recursion is the broker's job, confirmed.
- All names in the sampled roots were **pure ASCII**; no invalid-UTF-8 name was
  found. The spec's "filenames are bytes" rule stays, but it is currently
  justified by prudence rather than by an example from this device. Recorded as
  such rather than overclaimed.
- **No regular files at the top level of any root** — all 7 `DCIM` entries and
  all 8 `Movies` entries are directories. A `list` that stops at depth 1 would
  report a phone with no photos on it.

Aggregates only, per the redaction rules; no filename was printed or recorded at
any point.

### Phase 6 — `RECV`

```
smallest file: 0 bytes      -> DONE immediately, ZERO DATA packets
largest file:  27,190,943 B -> 415 DATA chunks, max chunk 65536 (64 KiB)
                               byte count MATCHED dirent size exactly
                               0.657s, ~39.5 MiB/s
```

- **Chunk size is 64 KiB.**
- **The dirent size matched the received byte count exactly**, which is what the
  archiver's cheap-path comparison depends on. It holds.
- **A zero-byte file produces no `DATA` packets at all** — just an immediate
  `DONE`. An implementation that expects at least one `DATA`, or that treats "no
  data" as failure, will break on empty files. Its SHA-256 is the empty-input
  digest `e3b0c442…`, which is the value that appears in the spec's own example
  audit record.
- Throughput was measured on the **USB-A port**, and ~39.5 MiB/s is close to
  USB 2.0's practical ceiling, so this is likely a port limit rather than a
  device or protocol limit. Not a number to design against.

#### 6c — a sync `FAIL` is terminal: **connection lifecycle finding**

Each failure was re-tested on its own fresh channel, because the first attempt
gave three results that turned out to be an artifact of the channel already
being dead:

| `RECV` target | `FAIL` message | Channel afterwards |
|---|---|---|
| nonexistent path | `open failed: No such file or directory` | **dead** |
| `/init` | `open failed: Permission denied` | **dead** |
| `/sdcard/DCIM` (a directory) | `read failed: Is a directory` | **dead** |

By contrast, an `LST2` on a nonexistent path returns `error=2` **in band and the
channel survives** — two further commands succeeded on the same socket.

So the rule is: **`LST2`/`LIS2` errors are in-band and recoverable; any `RECV`
`FAIL` kills the sync session and requires a reconnect.** The spec says nothing
about this, and it directly shapes the fetch loop — on a first run over ~20k
files, every unreadable file costs a full transport re-establishment. Worth
designing for deliberately rather than discovering under load.

---

## What this changes in the spec

Ranked by how much they alter the design rather than the code.

1. **Confinement must be reformulated (4.1).** "No symlink at any path
   component" is unimplementable — `/sdcard` and `/storage/self/primary` are both
   symlinks. Proposal to discuss: resolve the root **once** per run with `STA2`,
   pin the resulting `(dev, ino)`, then require every entry beneath it to share
   that `dev` and refuse symlinks *below* the root. That converts a string
   convention into a filesystem-level boundary — a symlink escaping to `/data`
   lands on `dev=65088` and is detectable. Caveat: `dev` numbers are not stable
   across reboots, so the pin must be established per run and never compiled in.
2. **`host:features` must be named explicitly as `host-serial:<serial>:features`
   (1b).** `host:host-features` passes the V2 check with no phone attached.
3. **A `RECV` `FAIL` requires reconnecting (6c).** The fetch loop needs an
   explicit reconnect path; the spec currently implies one durable channel.
4. **Timeouts must be specified (0b).** A too-long length prefix hangs the
   exchange forever with no reply. The spec sets no deadlines anywhere.
5. **Read device state from `host:devices`' state token, not from `FAIL` prose
   (1, 0b).** Four prose strings were catalogued; `errno` from `LST2` and the
   state token are the only structured signals.
6. **NUL, `..`, relative paths, and trailing/doubled slashes are all live
   attack surface (7a)**, not theoretical. NUL truncation in particular makes the
   audit log describe an operation that did not occur.
7. **`mtime_nsec` is unavailable, not just unimplemented (4).** Close the open
   question.
8. **Empty files need an explicit case (6)** — zero `DATA` packets is success.
9. **`ENOENT` does not prove absence (4.3)** — adbd returns it for paths it can
   see but not read.
10. **Don't log `usb:` path or `transport_id` as device identity (1c).**

## Still untested

- Behaviour on a directory large enough to stress `LIS2` streaming; the biggest
  sampled had a few hundred entries.
- Any file with a non-UTF-8 name — none exists on this device to find.
- Mid-transfer failure of a `RECV` that has already sent `DATA` (e.g. media
  unmounted underneath it). Not reproducible without deliberately yanking
  storage.
- `RECV` on a path whose final component is a symlink pointing outside the root —
  the TOCTOU case. Needs a symlink that does not exist here, i.e. the Phase 7b
  fixture that was not needed for the following-behaviour question.
