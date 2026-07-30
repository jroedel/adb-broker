# Audit Infrastructure Experiment

Host-side counterpart to `adb_experiment.md`. That document measured the phone and the adb
protocol; this one measures the machine the broker runs on — the service account, the
append-only log, and the journald anchor path.

Run 2026-07-31 on the target host. No device was attached and none was needed: nothing here
touches the phone.

**Why measure this at all.** The audit design rests on properties of the host that the broker
cannot establish for itself and cannot check from inside: file ownership, an append-only
attribute the kernel has to honour, and a journal sink written by another process. Every one
of those is an assumption until it is run. Two turned out to be wrong as specified, and one
threat had not been modelled.

---

## Host

| | |
|---|---|
| systemd | 255 (255.4-1ubuntu8.16) |
| `/var/log` filesystem | ext4 on `/dev/mapper/ubuntu--vg-ubuntu--lv` |
| Journal storage | persistent (`/var/log/journal` present, `Storage` unset → `auto`) |
| machine-id | `d4d68cd90bbb458f987e1a6c4608b722` |
| Journal file ownership | `root:systemd-journal 0640` |
| Go | 1.26.5 |
| adb server | running, pid 29995, as uid 1003 |
| Broker uid, after install | 995 |

`chattr`, `lsattr`, `runuser` and `install` are all present. `golangci-lint` and `govulncheck`
are **not** installed, which is why the `Makefile` pins them via `go run pkg@version` rather
than expecting them on `PATH`.

---

## 1. Install and verify the audit identity

`zarf/install.sh` created the account, the caller group, the log directory and the log, then
verified every property. Result: all checks passed.

| Property | Measured |
|---|---|
| `adb-broker` account | uid 995, system, own group, `/usr/sbin/nologin`, no home |
| Membership | **not** a member of `adb-broker-clients` |
| Caller group | `adb-broker-clients` exists; `agy_user` (uid 1003) added |
| Uid separation | caller 1003 ≠ broker 995 |
| `/var/log/adb-broker` | `root:root 0755` |
| `audit.log` | `adb-broker:adb-broker 0640` |
| Attributes | `-----a--------e-------` — append-only set |
| Append as broker | permitted |
| Write to log directory as broker | refused |

Both controls the design depends on — ownership and `chattr +a` — were therefore confirmed
independently, on this filesystem, before any Go existed to rely on them.

### 1.1 `+a` is genuinely enforced, not merely set

Setting an attribute and having the kernel honour it are different claims. Tested against a
throwaway replica configured identically to the real log:

```
truncation by the file's owner   -> refused (EPERM)
append by the file's owner       -> permitted
unlink from a root-owned dir     -> refused (EACCES)
```

### 1.2 Finding: the obvious verification is destructive

The first draft of these checks ran `: > audit.log` to prove truncation is refused and
`rm -f audit.log` to prove unlink is refused. **Both destroy the audit log in precisely the
case where they fail** — a missing `+a` means the truncation test truncates, and a
misconfigured directory means the unlink test unlinks. The check would have been most
dangerous exactly when it mattered most.

So `verify-install` never attempts either against the real log. It inspects ownership, mode
and attributes; it opens the log `O_APPEND` and writes **zero bytes**; and it proves `+a`
enforcement against the replica above. Directory writability is checked with `test -w` rather
than by attempting a deletion.

A related trap: the expected refusals print `Operation not permitted` and `Permission denied`
to stderr, which makes a passing run look broken. Suppressing stderr would be worse — a
command failing for an *unrelated* reason would then register as a pass — so the refusals are
captured and asserted to be permission errors specifically.

### 1.3 Finding: `4750` on the binary is wrong; `4550` is correct

The spec specified the installed binary as `root:root 0755`. That does not work at all:
`exec` does not change uid, so a consumer executing a `0755` broker runs it as the
*consumer's* uid, which cannot open a log owned by the broker. The separation the design
argues for never happened.

setuid fixes it, but setuid takes its uid from the file's **owner**, so the binary must be
owned by `adb-broker` — and `4750` would then leave the broker able to rewrite its own setuid
binary while keeping the uid. `4550` removes the owner write bit. Root performs installs, so
the owner never needs write.

This was caught by the verification check `broker cannot write to its own setuid binary`,
which failed against the mode originally specified. Worth noting as evidence for writing the
assertion before trusting the value.

---

## 2. The journald anchor round-trips

One datagram was sent to `/run/systemd/journal/socket` from an ordinary uid — no library, no
`exec`, no reply — carrying the native protocol's newline-separated `KEY=value` pairs. This is
the entire write path the broker will use.

Sent: 272 bytes, `MESSAGE_ID=8f3c1d7a5e4b42c9b1d06a2f7c93e5a4`, plus `ADB_BROKER_SEQ`,
`ADB_BROKER_HASH`, `ADB_BROKER_LOG`, `MESSAGE`, `PRIORITY`, `SYSLOG_IDENTIFIER`.

Read back with `journalctl MESSAGE_ID=… -o json-pretty`: **all custom fields survived
verbatim**, `_TRANSPORT=journal` confirming the socket path.

The socket is mode `0666`, so no group membership is required to write an anchor. The broker
therefore needs nothing granted for this.

### 2.1 journald stamps provenance the sender does not assert

Present on the entry without having been sent:

```
_UID=1003   _GID=1003   _PID=101216   _AUDIT_LOGINUID=1003   _CAP_EFFECTIVE=0
_COMM=python3   _EXE=/usr/bin/python3.12   _CMDLINE=…   _BOOT_ID=…   _MACHINE_ID=…
```

journald derives these from the sending socket's credentials, so a sender cannot influence
them. In production an anchor will carry uid 995, `_COMM=adb-broker` and
`_EXE=/usr/local/bin/adb-broker` without the broker claiming any of it. `_AUDIT_LOGINUID` is
the most interesting for forensics: it survives a setuid exec and names the login session
behind it.

### 2.2 Finding: anchors are forgeable, and only `_UID` distinguishes a real one

Because the socket is world-writable, **any local process can publish a well-formed anchor
carrying the broker's `MESSAGE_ID` with a fabricated `seq` and `hash`.** That is exactly what
the datagram above was: an ordinary uid, a real `MESSAGE_ID`, invented values. It is now in
this host's journal permanently, because journal entries cannot be removed.

The consequence is direct. An adversary who truncates the audit log can also publish an anchor
matching the shortened chain, and a verifier comparing on `MESSAGE_ID` alone would accept it —
the anchor control would invert into a confident pass.

**So `verify` accepts only anchors whose `_UID` equals the broker's uid and whose `_EXE` is the
installed path.** This is tracked as T31 in `THREAT_MODEL.md`. The forged anchor is left in
place deliberately: the first real `verify` must discard it on exactly that rule, which makes
the rule testable against something that actually happened.

### 2.3 Journal format flags, and what each costs the reader

The broker may not `exec journalctl`, and the Go standard library has no journal reader, so
`verify` must parse journal files directly. `journalctl --header` reports, on every file:

```
Compatible flags:   TAIL_ENTRY_BOOT_ID
Incompatible flags: COMPRESSED-ZSTD KEYED-HASH COMPACT
```

| Flag | Consequence |
|---|---|
| `KEYED-HASH` | Hash tables are keyed with SipHash-2-4, which is not in the standard library. The reader walks the header's global entry-array chain instead. `O(all journal files)` per `verify`; the hash-table path would mean implementing SipHash and is deferred until the walk is shown to be too slow. |
| `COMPACT` | Entry items and entry-array offsets narrow to 32 bits. Both layouts must be supported. Starting from the global entry array means `DataObject` back-references are never read, keeping the compact surface to two structures. |
| `COMPRESSED-ZSTD` | **zstd is not in the standard library either, so the reader cannot decompress.** journald compresses payloads above 512 bytes; anchor fields are ~30, so it never arises — but that is an invariant to enforce, not a coincidence to rely on. The *writer* caps every anchor field at a compile-time constant well under the threshold, making it structurally incapable of emitting an anchor the reader cannot read. |

Any unrecognized incompatible flag must be a hard error. Returning "no anchors found" on a
format the reader does not understand is indistinguishable from tampering.

### 2.4 Reading the journal needs a grant the broker does not get

Journal files are `root:systemd-journal 0640`, and `systemd-journal` has no members on this
host. Reading them requires root or membership in that group — which grants read access to
*every* service's logs.

**Decided: the broker is not granted it.** It writes anchors and never reads them. `verify` is
run by an operator or from monitoring, with journal access of their own. The cost is named
rather than hidden: the startup fail-closed check can then re-hash the tail but cannot detect a
*truncated* tail, because a shorter chain recomputes cleanly. Truncation detection is `verify`'s
job, which is the argument for running it on a schedule.

---

## 3. Bypass does not require root

`ADB_BROKER.md` originally excluded "an adversary who is already root and reads the phone with
their own copy of `adb`". Measured:

```
ss -ltnp  ->  LISTEN 127.0.0.1:5037  users:(("adb",pid=29995,fd=9))
```

The adb server runs as **uid 1003, not root**. Two clients completed a `host:version`
exchange against it:

```
as uid 1003        ->  OKAY     (the server's own owner)
as nobody (65534)  ->  OKAY     (no relationship to the owner)
```

`nobody` settles it: this is not a same-uid effect. adb performs no peer-credential check on a
TCP socket and nothing in its protocol authenticates a client, so **any local process can
speak the sync protocol directly** and read whatever the device serves. The original wording
overstated the barrier by describing it as root-only; there is no barrier.

Two things follow that are easy to get backwards. It weakens no control — none was protecting
the phone from the host — but it bounds what the caller group buys: restricting execution to
`adb-broker-clients` restricts who can produce a *broker-attributed* read and who can append
to the audit log, not who can read the phone. And the bypass is closable, though not by this
binary: `ADB_SERVER_SOCKET=unix:…` would put file permissions in front of the server, which
collides with the spec's compiled-in address. Tracked as `THREAT_MODEL.md` §8.6.

The corollary is relied on elsewhere: since the socket needs no group membership, the broker's
uid needs none either, which is why `install.sh` grants it nothing for adb access.

---

## What this changes in the spec

1. **The binary must be setuid `4550`** (§1.3). `root:root 0755` never delivered the uid
   separation it was specified to deliver.
2. **Verification must not be destructive** (§1.2). Two of the obvious checks destroy the log
   in the failure case.
3. **`verify` must filter anchors on `_UID`** (§2.2). A new threat, T31, not previously
   modelled; without the filter the anchor control accepts the adversary's own anchors.
4. **The startup check does not consult the journal** (§2.4), and therefore does not detect
   truncation. Named as a gap rather than papered over.
5. **The anchor writer caps field sizes** (§2.3), so it cannot emit a record the reader is
   unable to parse.
6. **The bypass exclusion is not root-only — it is not privileged at all** (§3). Any local uid
   can drive the adb server, so the exclusion in `ADB_BROKER.md` is corrected from "an
   adversary who is already root" to "any local process", and what the caller group is
   credited with is narrowed to match.

---

## Still untested

- Whether the linear entry-array walk is fast enough for `verify` on ~30 files of 8–64 MB.
- journald retention on this host, which sets an unquantified horizon on the truncation
  guarantee: an anchor that has been rotated away proves nothing.
- Behaviour when the journal is volatile-only (`/run/log/journal`), where anchors do not
  survive a reboot. Persistent storage is present here, so this is untested rather than
  handled.
- The setuid install itself. There is no binary yet, so `install.sh` skipped step 6 and the
  binary checks reported "not installed". Re-running after the first build is step 9 of the
  build order.
