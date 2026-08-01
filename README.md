# adb-broker

Read-only, audited access to a phone's media over the adb sync protocol.

`adb-broker` is a single Go binary with no dependencies outside the standard library. It
speaks the adb sync protocol directly to the local adb server — it never execs `adb`, never
opens a shell channel on the device, and never writes to the device. It reads six compiled-in
media roots and nothing else, and it records every operation, including every refusal, in a
hash-chained audit log.

It is installed once per host and invoked by any number of consumers. Every consumer gets
exactly the same six roots; nothing a consumer passes at runtime widens what the binary can
reach.

**This README is the integration guide. The normative contract is
[`docs/ADB_BROKER.md`](docs/ADB_BROKER.md)** — where the two disagree, that document wins, and
it explains *why* each rule exists. Every example below was produced by running the binary.

---

## Requirements

The broker arranges none of these and fails loudly on each:

1. **A running adb server** on `127.0.0.1:5037`. The broker never starts one — absence is
   `no_adb_server`. The address is compiled in and not configurable.
2. **The phone in file-transfer mode**, not "No data transfer".
3. **USB debugging authorized against the adb server's RSA key.** The trust is granted to
   `~/.android/adbkey` of the *account running the adb server*, not to the host, so
   authorizing one account grants nothing to another. This misreads as "USB debugging is
   off": the broker reports `unauthorized` in exactly this case.
4. **A device offering `STAT_V2`/`LIST_V2`.** Legacy `STAT` reports `size` as 32 bits, so a
   device without V2 is refused with `unsupported` rather than served a silently wrong size
   for a file over 4 GiB.

## Install

No root, no service account, no install script.

### From a release

Linux, `amd64` and `arm64`. Substitute the version you want — pin one, don't track `latest`.

```sh
curl -fsSLO https://github.com/jroedel/adb-broker/releases/download/v0.1.0-rc2/adb-broker-linux-amd64
curl -fsSLO https://github.com/jroedel/adb-broker/releases/download/v0.1.0-rc2/SHA256SUMS
sha256sum --ignore-missing -c SHA256SUMS
install -D -m 0755 adb-broker-linux-amd64 ~/.local/bin/adb-broker
adb-broker version
```

```
adb-broker-linux-amd64: OK
{"proto":1,"status":"ok","broker":"0.1.0-rc2","revision":"8e80245cf1146d9837f0ae345f16cfd01f4c50e9","modified":false}
```

> **`v0.1.0-rc1` is withdrawn — do not use it.** That build derives its audit log path from
> `$HOME` on any host whose uid has no passwd entry (LDAP, SSSD, AD, or a container with an
> unmapped uid), defeating the rule that no environment variable can move the log. Reproduced
> against the published artifact, not merely suspected. `v0.1.0-rc2` is the first usable tag;
> `zarf/repro-passwd-fallback.sh` distinguishes the two and needs no privileges.
>
> Its release and binaries are deleted, and it is `retract`ed in `go.mod` so `go get` and
> `go install` refuse it with that reason. Neither step is total: the version stays in
> proxy.golang.org's immutable cache, and its provenance attestation stays in a public
> transparency log. If you already hold an rc1 binary, replace it.

Two optional checks. The release carries a provenance attestation:

```sh
gh attestation verify adb-broker-linux-amd64 --repo jroedel/adb-broker
```

and the build is reproducible — clone the repo, `git checkout v0.1.0-rc2`, `make dist
VERSION=0.1.0-rc2`, and you get the published bytes exactly. That one requires trusting nobody
at all, which is why it is worth knowing about even if you never run it.

There is no macOS or Windows build. Windows does not compile; macOS is left out deliberately,
because it has no journald and the audit anchor would silently never publish — leaving a broker
whose tamper-evidence is absent while everything still reports success.

### From source

```sh
make build
install -D -m 0755 bin/adb-broker ~/.local/bin/adb-broker   # or: make install
```

### Either way

**Install it at exactly one path.** Every audit anchor carries the publishing binary's
journald-stamped `_EXE`, and `verify` accepts only anchors bearing the running binary's own
path — so a second copy elsewhere splits the anchors into two identities that no single
`verify` run can see at once. Nothing errors when this happens; `verify` just quietly stops
covering half of the trail. In particular, do **not** ship a per-consumer copy beside a
consumer's own executable.

Discovery is the consumer's concern. `photos`, the originating consumer, looks at
`source.broker_path` in its config, then `adb-broker` on `PATH`.

**If your consumer installs the broker itself** rather than asking the user to, there is a short
contract it has to follow — one canonical path, an exact pinned version, an embedded SHA-256
verified before an atomic `rename(2)` into place, a refusal to downgrade, and a `probe` straight
afterwards. Each rule is there because breaking it fails silently. It is specified in
[`docs/ADB_BROKER.md`](docs/ADB_BROKER.md) → **The consumer install contract**.

On first run the binary creates its own audit log at
`~/.local/state/adb-broker/audit.log` (`0600`, in a `0700` parent) and anchors the empty
chain before contacting any device. The path is derived from the passwd entry for the running
uid — not `$HOME` — and no flag, environment variable or configuration file can move it. **No
environment variable is read for any purpose.**

---

## The stream contract

- **stdout carries JSON and nothing else.** No banners, no progress, no warnings.
- **stderr is for humans**, with exactly one machine-readable exception (see
  [A fetch that fails after the header](#a-fetch-that-fails-after-the-header)). Capture it at
  debug level.
- **Exit codes are a coarse signal; the JSON `status` member is authoritative.**

| Exit | Meaning |
|---|---|
| `0` | `status` was `ok` or `partial` — usable output was produced |
| `1` | the operation failed and produced no usable output |
| `2` | the invocation could not be interpreted: no subcommand, an unknown one, or unparseable flags |

An error object is written to stdout even for exit `2`, so a consumer never has to parse usage
text to find out it called the binary wrongly.

Every object that carries a version carries `"proto":1`. Check it once, at `probe` time, and
refuse to run against a major version you do not know.

## Subcommands

The four below take flags only — a stray positional argument is a usage error. `--serial <id>`
pins a device; `--client <name>` is a caller-asserted label recorded in the audit log (at most
64 bytes of `[A-Za-z0-9._-]`, rejected outright otherwise). `version`, described last, takes
nothing at all.

### `probe` — is a device reachable

```sh
adb-broker probe [--serial <id>] [--client <name>]
```

```json
{"proto":1,"status":"ok","serial":"EXAMPLESERIAL1","state":"device","broker":"0.1.0","adb":"1.0.41","attached_devices":1,"allowlist":["/sdcard/DCIM","/sdcard/Download","/sdcard/Movies","/sdcard/Music","/sdcard/Pictures","/sdcard/Recordings"]}
```

Call it once before a run. A disconnected phone makes every configured source unreachable,
and saying so once up front beats one identical failure per source. `probe` also pins the
device's storage volume, so a phone whose storage is not in the expected shape is discovered
here.

Three members are what a consumer actually acts on:

- **`allowlist`** — every root this binary can reach, sorted, always present and never empty.
  Validate your configured sources against it **at startup**. Without it, a misconfigured
  source is only discoverable by connecting to a phone and being refused, once per source —
  and `path_denied` is a configuration error reported far too late.
- **`attached_devices`** — the size of the whole device list. It is *not* filtered by
  `--serial` (probing with `--serial` while two phones are attached reports `2`), and it is
  *not* a count of devices the broker could serve, since an `unauthorized` or `offline` phone
  is attached and is counted. It answers exactly one question: **could an operation naming no
  device be ambiguous.** Read `1` and you may omit `--serial` on every `fetch`; read `2` or
  more and you must pass one. This matters for cost — see [`fetch`](#fetch--stream-one-file).
- **`state`** — the transport's own token, verbatim (`device`, `unauthorized`, `offline`, …).
  Treat anything but `device` as fatal. In practice a *successful* probe never reports
  anything else: a device in another state fails inside connection setup and produces an error
  object with `code` already set to `unauthorized`, `offline`, or another taxonomy value. The
  defensive branch is worth keeping anyway; just do not expect it to fire.

`adb` is the version of the *server* the broker is talking to, from `host:version`. No binary
on `PATH` is consulted. There is no `model` member and there never will be — reading a model
needs a shell, and this binary has none.

With no `--serial` and several devices attached, `probe` fails with `multiple_devices` and
never guesses.

### `list` — enumerate a tree

```sh
adb-broker list --root <path> [--max-depth <n>] [--serial <id>] [--client <name>]
```

`--max-depth 1` means immediate children only; omitted (or `0`) means unlimited. `--root` must
lie within the allowlist, or the command fails with `path_denied` **before any transport
connection is made**.

NDJSON on stdout, one record per regular file, streamed as discovered, terminated by exactly
one object carrying a `status` member:

```json
{"path":"/sdcard/DCIM/Camera/IMG_0182.JPG","path_b64":"L3NkY2FyZC9EQ0lNL0NhbWVyYS9JTUdfMDE4Mi5KUEc=","size":12,"mtime":1785540743}
{"path":"/sdcard/DCIM/Camera/empty.jpg","path_b64":"L3NkY2FyZC9EQ0lNL0NhbWVyYS9lbXB0eS5qcGc=","size":0,"mtime":1785540743}
{"proto":1,"status":"ok","files":2,"errors":[]}
```

| Member | Notes |
|---|---|
| `path` | absolute, as the device names it — **lossy**, for humans |
| `path_b64` | base64 of the raw path bytes — **authoritative**, always present |
| `size` | exact bytes, `int64` |
| `mtime` | Unix **seconds** (there is no `mtime_nsec`, and there must never be one — the protocol carries whole seconds only) |

A partial walk emits every record it did read, then a summary with `"status":"partial"`, the
per-path errors, and **exit `0`**:

```json
{"proto":1,"status":"partial","files":20397,"errors":[{"code":"permission_denied","path":"/sdcard/DCIM/Camera/locked","path_b64":"L3NkY2FyZC9EQ0lNL0NhbWVyYS9sb2NrZWQ="}]}
```

`files` is **exactly the number of records that preceded the summary on this stream** — that is
contract, so it is the integrity check for a consumer that counted records as it decoded them.
It is not a count of files on the device and not a count of what survived your own policy. A
disagreement is a defect in this binary, not a device condition.

If the walk fails outright, the terminator is an error object instead of a summary. **Discard
the records in that case** — a partial tree presented as a whole is the exact failure this tool
exists to prevent — and report the source as failed.

### `fetch` — stream one file

```sh
adb-broker fetch --path <path> [--serial <id>] [--client <name>]
```

Header line, raw bytes, trailer line:

```
{"proto":1,"op":"fetch","size":12}
hello world
{"status":"ok","bytes":12,"sha256":"a948904f2f0f479b8f8197694b30184b0d2ed1c1cd2a1ec0fb85d299a192a447"}
```

A zero-byte file is a success with no bytes between the two lines and the empty-input digest:

```
{"proto":1,"op":"fetch","size":0}
{"status":"ok","bytes":0,"sha256":"e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"}
```

`sha256` is the digest of the bytes the broker forwarded. It detects corruption between the
broker and you, and a bug in your own write path. It is **not** end-to-end device verification —
the broker never re-reads the device, and it will not hash on the phone, because that needs a
shell channel that does not exist.

The broker never writes to the local filesystem (the audit log excepted, append-only). Create
your own staging file with `O_EXCL`; that is where the refuse-to-overwrite guarantee lives.

**Pass `--serial` only when you need it.** `fetch` honours a pinned serial by running a full
`probe` first, which costs one extra audited operation and one extra audit record per file — on
a first run of ~20,000 files, 20,000 of each. Read `attached_devices` from one `probe` at the
top of the run instead, and omit `--serial` when it is `1`.

### `verify` — check the audit log against the anchors

```sh
adb-broker verify [--log <path>] --anchors <file|glob|->
```

This is the only check that detects a **truncated** audit log. The hash chain makes editing,
reordering and mid-file deletion detectable by recomputation, but whoever can write the file can
also recompute a shorter chain that verifies perfectly. Only the anchors published to the systemd
journal say which sequence number the log once held. Put `verify` in monitoring; do not save it
for when something already looks wrong.

```sh
adb-broker verify --anchors '/var/log/journal/*/user-'"$(id -u)"'.journal'
journalctl -o json MESSAGE_ID=8f3c1d7a5e4b42c9b1d06a2f7c93e5a4 | adb-broker verify --anchors -
```

Both forms work unprivileged. The first reads this user's own journal file directly (systemd
grants that by ACL); the second suits a scripted run or a host whose journal is configured
differently.

**Run it as the account that runs the backups, never as root.** It accepts only anchors whose
journald-stamped `_UID` equals its own and whose `_EXE` is the running binary's path, so a root
invocation matches nothing and reports a confident pass over an empty set.

```json
{"proto":1,"status":"ok","log":"…/audit.log","records":11,"last_seq":11,"last_hash":"e60cacdf…","anchors":37,"anchor_seq":11,"anchor_hash":"e60cacdf…"}
```

Read the outcome like this:

| Result | Meaning |
|---|---|
| `"status":"ok"`, exit `0` | the chain verified and a trustworthy anchor agreed with its head |
| `"status":"partial"`, exit `0` | the chain verified but **no trustworthy anchor was found** — the truncation check never ran. **Treat this as a failure**, not a clean bill: the likely causes are the wrong user, a binary at a different path, or a log path no anchor names |
| `"code":"audit_unavailable"`, exit `1` | a divergence — a truncated tail, an altered record, or a log that cannot be read |

`verify` is the one subcommand exempt from the fail-closed startup check: gating the tool that
diagnoses a damaged log on that log opening cleanly would make it refuse precisely when it is
needed. It never appends, touches no device, and opens nothing for writing.

### `version` — what is this binary

```sh
adb-broker version
```

```json
{"proto":1,"status":"ok","broker":"1.2.0","revision":"7db15f766ed07bc512633453f1a9d8d0a85e9760","modified":false}
```

Takes no flags, reads no log, contacts no device, and answers before the fail-closed check — so
it works on a fresh host, and on one whose audit log is missing or damaged. That matters if you
automate installs: the version of the binary already at `~/.local/bin/adb-broker` may have been
put there by a different consumer, and this is the only way to read it. **Comparing SHA-256
digests cannot tell you whether the installed copy is older** — a mismatch says "different" and
never "older" — and the build stamp is invisible from outside the process, since `go version -m`
records the commit but not the version.

`broker` is the release the binary was built from. A build you made yourself reports
`0.0.0+dev`, which sorts below every real tag and can never be confused with one; a fixture
binary appends `+fixture`. `revision` and `modified` describe the build, not the release, and
are always present — `revision` is empty for a build made from an extracted archive rather than
a checkout, and, measured, for one made in a linked `git worktree`.

---

## Four reading rules that are easy to get wrong

Each of these was a real defect found by the first consumer or by running the binary.

**1. Discriminate on the presence of a `status` member — never on the absence of `path`.**
Inside a `list` stream, a record never carries `status` and a terminator always does. A
terminating *error* object does carry `path` when the failure names one, so a consumer keying
off "no path member" decodes it as a file record with an empty `path_b64`, a zero `size`, and
no `code`:

```json
{"proto":1,"status":"error","code":"path_denied","path":"/sdcard/NOPE","path_b64":"L3NkY2FyZC9OT1BF","message":"root: path denied: \"/sdcard/NOPE\" is not within the allowlist (…)"}
```

The same rule applies to a `fetch`'s first stdout line: it is either a header (no `status`) or
an error object (one). Both subcommands discriminate identically, so one check covers both.
`probe` is different — it has no records, and a *successful* probe carries `"status":"ok"`, so
there you branch on the **value**.

**2. Require the trailer even when the header says `size: 0`.** A failed `fetch` that is
misread as a header yields `size` `0`, and a legitimate empty file also reports `0` with no
bytes following — and there is a zero-byte file on the target device. What separates them is
that the real empty file is still followed by a trailer. Take the "no bytes to read, so no need
to look for a trailer" shortcut and you will report a failed transfer as a success, with an
empty staging file and the digest of nothing to agree with it.

```go
// Both halves, in the order that matters.
var first map[string]json.RawMessage
if err := dec.Decode(&first); err != nil { /* … */ }
if _, failed := first["status"]; failed {
    // an ErrorResponse: branch on code, no payload follows
}
// a header: read exactly size bytes, then REQUIRE a trailer — even if size is 0
```

**3. `path_b64` is the authoritative path; `path` may be lossy.** Android filenames are byte
strings that need not be valid UTF-8, and JSON strings must be, so `path` is coerced for
display. Act on `path_b64` — in file records, in a summary's `errors[]`, and in the top-level
error object, where it is present exactly when `path` is. Fetching the string you read from
`path` can mean asking for a file that does not exist.

**4. Report `mtime` exactly as the device gives it.** Do not normalize, do not adjust for a
timezone, do not reconcile it with anything. On the measured device it means different things
for different files — camera files sit a whole UTC offset from the true capture instant while
screenshots are correct epochs — because the producing application decides. The only property
worth relying on is that the same file reports the same value on two runs. "Fixing" it breaks
that comparison for every file and silently disables the cheap incremental path, whose only
symptom is that runs become inexplicably slow.

### Absence from a listing is ambiguous, by design

A refused entry is **omitted silently, with no `errors[]` entry**, and the listing still
terminates `"status":"ok"`. Symlinks, sockets, FIFOs, block and character devices, and any entry
whose filesystem is not the pinned storage volume are all dropped without a record. They are not
failures — they are confinement decisions about entries that were never going to be served.

So: **absence means "not a regular file on the pinned volume, or not there at all", and this
contract does not distinguish the two.** A `--max-depth 1` listing adds a third reason for the
same silence.

### `--max-depth 1` is a trap, and an inconsistent one

Measured on the target device:

| Root | Regular files at depth 1 |
|---|---|
| `/sdcard/DCIM` | 0 |
| `/sdcard/Movies` | 0 |
| `/sdcard/Music` | 0 |
| `/sdcard/Recordings` | 0 |
| `/sdcard/Download` | **503** |
| `/sdcard/Pictures` | **47** |

A depth-limited configuration therefore *appears* to work — `Download` and `Pictures` produce
files — while silently archiving nothing from `DCIM`, the root that matters most. Do not write a
test asserting that a depth-1 listing of an arbitrary root is empty: that asserts a property of
one phone's layout, not of this code.

---

## Error taxonomy

Every failure — a whole operation, or one path within a listing — carries a machine-readable
`code`. `message` is free-form, for humans only; log it and never branch on it.

```json
{"proto":1,"status":"error","code":"not_a_regular_file","path":"/sdcard/DCIM/Camera","path_b64":"L3NkY2FyZC9EQ0lNL0NhbWVyYQ==","message":"not_a_regular_file: \"/sdcard/DCIM/Camera\" is not a regular file, and only regular files are transferred"}
```

| `code` | Meaning | Suggested handling |
|---|---|---|
| `no_device` | no device answers what was asked — nothing attached, *or* a named `--serial` that is not among the attached devices (other phones may well be plugged in) | abort the run |
| `unauthorized` | USB debugging not accepted for this account's key | abort, with instructions |
| `offline` | attached but not usable | abort |
| `multiple_devices` | ambiguous without `--serial` | abort; never guess |
| `no_adb_server` | nothing listening on `127.0.0.1:5037` | abort; the host must start it |
| `path_denied` | outside the allowlist, a rejected spelling, or off the pinned volume | abort **that source** — a configuration error, not a device condition |
| `audit_unavailable` | the audit log cannot be opened, appended to, or recomputed | abort the run, before any device contact |
| `volume_unresolved` | `/sdcard` does not resolve to a directory, or stopped resolving to the pinned volume mid-listing | abort the run — a remount invalidates every other source too |
| `root_not_found` | the named tree could not be read | skip that source, continue |
| `not_a_directory` | the listing root is a file (or a symlink) | skip that source |
| `not_a_regular_file` | a `fetch` target exists and is not a regular file | per-file failure, run continues — a listing emits regular files only, so the kind changed after the listing |
| `permission_denied` | a path could not be read | per-path: warn, continue |
| `path_not_found` | a file vanished between `list` and `fetch` | per-file failure, run continues |
| `transfer_failed` | the stream ended early or was corrupt | per-file failure, run continues |
| `device_disconnected` | the device went away mid-operation | abort |
| `unsupported` | operation or flag not implemented, or the device lacks `STAT_V2` | abort, with the version |
| `internal` | anything else | abort |

**New codes may be added. Treat an unrecognized code as `internal`** — fatal, which is the safe
direction.

### The handling column is scoped, and the scope changes what it means

The same code means two different things depending on where you read it:

- **As an entry in a summary's `errors[]`**, it describes one path inside a listing that
  otherwise succeeded. The column applies as written: `permission_denied` there means warn and
  carry on, and the records that arrived are a usable if incomplete enumeration.
- **As the `code` of a terminating error object, or of a failed `probe` or `fetch`**, the same
  value means *this operation failed and produced no usable output.* Whatever the column says
  about continuing applies to the run, never to the operation. "Warn and continue" is correct
  only for a per-path entry — never for a terminator.

That distinction is not hypothetical. A `list` whose root itself answers `EACCES` terminates with
`permission_denied`, zero records, and exit `1`; a consumer that followed the column literally
would archive nothing from that source and report success.

`ENOENT` does not prove absence — `adbd` returns `error=2` for paths it merely hides. So word
`root_not_found` to a human as "the root could not be read", not "it does not exist".

### A `fetch` that fails after the header

Once the header is on stdout, **nothing else is written there except the trailer.** The header
commits to an exact byte count, so anything appended after a short payload would be read as the
tail of the file. So the stream simply ends, and a missing trailer is already the signal for a
failed transfer.

Both `RECV` failures this binary can reach land here, because the header is written between the
preflight stat and the transfer — a file deleted in that window, and a file `adbd` can stat but
not read. The classification therefore goes to stderr, and this one line is contract:

```
adb-broker: transfer failed after the header was sent; the stream ends without a trailer
adb-broker: code=transfer_failed path=/sdcard/DCIM/Camera/IMG_0182.JPG: transfer_failed: …
```

**Only the `code=` token is parseable. Do not attempt the rest of the line.**

- The path is not quoted or escaped, and device filenames contain spaces, so there is no token
  boundary between it and the `: <message>` that follows.
- The path has already been coerced to valid UTF-8, so it is not the bytes that failed.
- A device filename may contain a **newline**, so it can forge additional stderr lines,
  including a plausible second `code=` claiming a fatal code. **Take the first `code=` match in
  the buffer** — forged text can only appear inside the genuine line's `path=` value, which is
  by construction after the genuine token.

There is no `path_b64=` on this line, deliberately: a `fetch` names exactly one path, which you
supplied, so the path is never news. The classification is the only thing you cannot get
elsewhere.

Note the codes here are `transfer_failed`, not `path_not_found` or `permission_denied`: a sync
`FAIL` carries prose and no errno, and the broker will not classify by matching adb's English
outside one isolated table. If you need to know whether the file is still there, run `probe` —
which is also the documented recovery step, since the real question after a truncated transfer
is whether the device is still attached.

---

## Testing your integration

A separate fixture binary serves a local directory as though it were the device. Same wire
format, same error codes, no hardware.

```sh
make build-fixture
bin/adb-broker-fixture --fixture /path/to/tree list --root /sdcard/DCIM
```

`/sdcard/…` paths map to `<tree>/sdcard/…`, `probe` reports a synthetic serial with
`"state":"device"` and `"attached_devices":1` (the unambiguous-device case, so tests take the
same branch as one real attached phone). The allowlist and the volume pin both still apply,
against the virtual paths, so confinement tests exercise the real confinement code. The audit
log and its fail-closed check are real too — they just live inside the fixture directory.

Two hooks make your error handling testable, since your branching on these codes is the
difference between skipping one file and abandoning a run:

```sh
bin/adb-broker-fixture --fixture ./tree --inject-error permission_denied list --root /sdcard/DCIM
bin/adb-broker-fixture --fixture ./tree --fail-after 5 fetch --path /sdcard/DCIM/Camera/IMG_0182.JPG
```

Global flags come **before** the subcommand. `--inject-error` rejects a code it does not
recognize rather than degrading it to `internal`.

**The fixture build is absent from the release binary, by build tag.** `--fixture DIR` remaps
`/sdcard/…` onto an arbitrary local directory, which is an allowlist bypass by construction; one
that shipped in production would be a bypass usable without building anything. A fixture binary
in a production path is visible rather than indistinguishable: it is named `adb-broker-fixture`
and reports a `broker` version with a `+fixture` suffix, in the first `probe` response and in
every audit record it writes.

## What the broker will not do

Not policy, but structure — most of it enforced by the compiled protocol vocabulary and by
types rather than by discipline:

- **No writes to the device.** No push, delete, rename or chmod; `SEND`, `shell:` and `exec:`
  are never sent.
- **No process execution at all** — no `exec`, no `fork`, no `PATH` lookup, including for `adb`
  itself. It will not run `adb start-server`.
- **No network access** other than TCP to `127.0.0.1:5037`.
- **No local filesystem writes** other than stdout, stderr, and appends to the audit log.
- **No content filtering, sorting or deduplication.** Extension and hidden-file policy is
  yours — duplicating it here is how two transports drift apart. Sort your own listings if
  determinism matters to you.
- **No metadata parsing.** No EXIF, no thumbnails, no image decoding.

## Audit log

You do not need to interact with it, but three facts affect how a deployment is operated:

- One record per operation, no sampling, **denials included** — including a refusal at the flag
  boundary that never reaches the device. A design where the interesting events go unwritten is
  not an audit trail.
- `caller_uid` comes from the kernel; `client_asserted` is your `--client` label and is **not
  evidence of anything** — it exists so a human can read the log without mapping uids by hand.
  A caller that lies about its name has that lie preserved in the chain.
- The broker runs as whoever invokes it, so the log is that account's own file and that account
  can delete or rewrite it. **Detection, via the journal anchors, is the whole guarantee** —
  which is why `verify` belongs in monitoring. `docs/THREAT_MODEL.md` §5.5 states exactly what
  that is and is not worth.

## Compatibility

- Every versioned object carries `"proto"`. Check it at `probe` time.
- **Adding a member is compatible. Removing or repurposing one is a `proto` bump.**
- **New `code` values are compatible**, because an unrecognized code degrades to `internal`,
  which is fatal — a consumer cannot be broken by a value it fails safe on.
- `proto` is currently `1`.
- `broker` (on `probe` and on `version`) is the binary's own release, stamped at build time. It
  is not the protocol version and is not what you check compatibility against — `proto` is.

## Building and testing

```sh
make build              # binary into bin/; VERSION=1.2.0 sets what `version` reports
make build-release      # the exact configuration a published artifact is built in
make dist               # every published artifact plus SHA256SUMS, into dist/
make build-fixture      # fixture binary, absent from the release build
make test               # unit tests, fixture build, lint, dependency and vuln checks
make test-integration   # adds tests needing a running adb server, no device attached
make test-device        # requires a phone attached; skipped elsewhere
make deps-check         # asserts the build graph is the standard library only
```

`go.mod` has no `require` block and `make deps-check` keeps it that way. Lint and vulnerability
tooling is pinned in the `Makefile` via `go run pkg@version` so it never enters the module
graph — for a binary whose whole purpose is to be a narrow, auditable boundary, third-party code
in the production build would be working against the point.

## Further reading

- [`docs/ADB_BROKER.md`](docs/ADB_BROKER.md) — the normative interface specification, and the
  reasoning behind every rule above.
- [`docs/THREAT_MODEL.md`](docs/THREAT_MODEL.md) — assets, adversaries, controls, and what each
  control does *not* buy.
- [`docs/adb_experiment.md`](docs/adb_experiment.md) — the protocol measurements the design
  rests on.
- [`docs/audit_experiment.md`](docs/audit_experiment.md) — the host-side audit measurements.
