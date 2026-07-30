# Build-Out Execution Plan

How the codebase gets from where it is now to fully built with tests, and how that work is
split across subagents.

This is an execution plan, not a design document. `ADB_BROKER.md` is the specification,
`THREAT_MODEL.md` says what the controls buy, and the two experiment files hold the
measurements. Nothing here restates those; where a number appears it is a pointer back to
one of them.

---

## 1. Where we are

Done and committed:

| | |
|---|---|
| `docs/` | Spec, threat model, and two experiment records. 8.1 answered and closed. |
| `zarf/install.sh` | Written, run, verified. Broker uid 995, both audit controls confirmed on ext4. |

Done, uncommitted, from the go-ahead to lay foundations:

| | |
|---|---|
| `go.mod` | `github.com/jroedel/adb-broker`, `go 1.26`, no `require` block. |
| `Makefile` | Targets below. Tooling pinned via `go run pkg@version` so the module graph stays empty. |
| `foundation/errs` | `FieldError`, `FieldErrors`, `Add`/`Addf`/`Empty`/`Fields`/`Error`/`Unwrap`/`ErrorOrNil`, plus `IsFieldErrors`. Tests pass, `staticcheck` clean. |

`make` targets: `build build-fixture vet fmt lint vuln-check deps-check test-unit
test-integration test-fixture test-device test cover install verify-install clean`.

`deps-check` fails the build if anything non-stdlib enters the graph. That is the
stdlib-only rule made mechanical rather than remembered.

**Not started:** every other package.

---

## 2. What "done" means for iteration 1

A binary that runs `probe`, `list`, `fetch` and `verify` against a real phone, with:

- `go vet ./...`, `make test-unit`, `make test-fixture`, `make lint`, `make deps-check` all clean.
- `make test-integration` clean against a running adb server with **no device attached**.
- `make test-device` written and compiling, skipped for want of hardware, ready to run in one
  command when the phone is back.
- `make build-fixture` producing a working fixture binary, and fixture-mode tests covering the
  whole path end to end without hardware.

Explicitly **not** in iteration 1: `--prune`, `--fail-after`, `--inject-error`, `fetch-many`,
persistent mode, off-box anchoring. All are spec-parked.

---

## 3. Constraints that shape the delegation

1. **No phone.** Everything phone-dependent is either fixture-backed or tagged `device` and
   skipped. This is the single largest driver: fixture mode moves from "nice to have" (spec
   step 7) to load bearing, because it is the only way to test traversal and fetch end to end
   tonight.
2. **No root.** Unit tests must not need `/var/log/adb-broker`. `foundation/audit` tests
   operate on temp files; the installed log is exercised only by manual runs.
3. **Stdlib only.** No agent may add a dependency. `deps-check` enforces it.
4. **Agents get one page.** So the *interfaces* must be decided before any agent starts, not
   negotiated between them. That is §4, and it is the load-bearing part of this plan.
5. **Model tiering.** Reserve the strong model for protocol framing, confinement, the binary
   journal format, and traversal. Type wrappers, the decorator, and fixture plumbing are
   transcription against a frozen API once the brief is precise.
6. **Agents must not run module-wide commands.** While five agents work in one tree,
   `go vet ./...` reports other agents' half-written packages. Each brief scopes verification
   to its own package; module-wide gates are mine, at wave boundaries.

---

## 4. The API freeze

Every exported signature below is fixed before any agent starts. An agent implements to it and
may not change it; if one is wrong, the agent reports back rather than improvising, because a
unilateral change breaks a sibling that is already building against it.

Two layering decisions are settled here rather than left to an agent:

**`adbwire` returns sentinel errors, not error codes.** The spec says the `FAIL`→code table
lives at one chokepoint in `foundation/adbwire`. Taken literally that would make a
`foundation` package import `business/types/errcode`, which the layering rules do not permit.
So `adbwire` owns the prose matching — the quarantine the spec actually cares about — and maps
to its own exported sentinels. Business maps sentinels to `errcode.Code`. The English still
appears in exactly one table with a test per string.

**`devicepath.ResolveVolume` takes a stat callback.** The volume pin needs `STA2` on the
compiled `/sdcard` constant, but `business/types` must not import `foundation/adbwire`. So the
resolver accepts a function. The compiled constant and the "only deliberate symlink traversal"
both stay in `devicepath`, and the resolver is testable with no transport at all.

### 4.1 `foundation/adbwire`

```go
const ServerAddr = "127.0.0.1:5037" // compiled in, not configurable

type Conn struct{ /* unexported */ }

func Dial(ctx context.Context) (*Conn, error)
func (c *Conn) Close() error

// The complete host-service vocabulary. There is no method that sends anything else.
func (c *Conn) ServerVersion(ctx context.Context) (string, error)          // host:version
func (c *Conn) Devices(ctx context.Context) ([]DeviceEntry, error)         // host:devices
func (c *Conn) DeviceFeatures(ctx context.Context, serial string) ([]string, error)
func (c *Conn) TransportSerial(ctx context.Context, serial string) error
func (c *Conn) TransportAny(ctx context.Context) error
func (c *Conn) Sync(ctx context.Context) (*SyncConn, error)

type DeviceEntry struct {
    Serial string
    State  string // verbatim from the state token: device, unauthorized, offline, …
}

type SyncConn struct{ /* unexported */ }

func (s *SyncConn) Close() error
func (s *SyncConn) Lstat(ctx context.Context, path string) (Stat, error) // LST2, does not follow
func (s *SyncConn) Stat(ctx context.Context, path string) (Stat, error)  // STA2, follows
func (s *SyncConn) List(ctx context.Context, path string, fn func(Dirent) error) error
func (s *SyncConn) Recv(ctx context.Context, path string, w io.Writer) (int64, error)

type Stat struct {
    Errno            uint32 // 0, 2 (ENOENT), 13 (EACCES) — the primary error source
    Dev, Ino         int64  // reinterpreted from unsigned; high bit set is a decode error
    Mode             uint32
    Nlink, UID, GID  uint32
    Size             int64
    Atime, Mtime, Ctime int64 // whole seconds; there is no sub-second field
}

type Dirent struct {
    Stat
    Name []byte // raw bytes, never coerced to UTF-8
}

// Sentinels. The FAIL-prose table maps to these and nothing else.
var (
    ErrNoServer        error // nothing listening on ServerAddr
    ErrNoDevices       error // "no devices/emulators found", or OKAY with an empty list
    ErrDeviceNotFound  error // "device '<serial>' not found"
    ErrUnauthorized    error // "device unauthorized. …"
    ErrOffline         error // "device offline (no transport)"
    ErrUnknownService  error // "unknown host service"
    ErrProtocol        error // framing violation, short read, silent close
    ErrSyncSessionDead error // returned after a RECV FAIL; the channel must be rebuilt
)

type FailError struct {
    Service string
    Message string // adb's prose, for humans and for the audit trail
}
func (e FailError) Error() string
func (e FailError) Unwrap() error // the sentinel it mapped to
```

Deadlines are per-exchange and internal, not a parameter: `Dial` sets them from the context
and every read and write carries one. There is no way to construct a `Conn` without them.

### 4.2 `business/types/devicepath`

```go
const VolumeRoot = "/sdcard" // the one accepted spelling, and the pin target

type AuthorizedPath struct{ /* unexported; no non-zero value constructible elsewhere */ }

func ParseAuthorizedPath(s string) (AuthorizedPath, error)
func MustParseAuthorizedPath(s string) AuthorizedPath // tests and package vars only
func (a AuthorizedPath) String() string
func (a AuthorizedPath) Bytes() []byte
func (a AuthorizedPath) Base64() string
func (a AuthorizedPath) IsZero() bool

// Child joins one directory-entry name during traversal. It rejects a name containing
// '/' or NUL, and rejects "." and "..", so the walk cannot construct a path the
// constructor would have refused.
func (a AuthorizedPath) Child(name []byte) (AuthorizedPath, error)

func Roots() []string                    // copy of the compiled allowlist
func Narrow(subset []string) error       // may only remove; a non-subpath entry is an error

var ErrPathDenied error

type Volume struct{ /* unexported */ }

// StatFunc is what ResolveVolume needs from a transport, and all it needs.
type StatFunc func(path string) (dev, ino int64, mode uint32, err error)

// ResolveVolume stats VolumeRoot once and pins the result. This is the only place the
// broker deliberately follows a symlink, and it does so against a compiled constant.
func ResolveVolume(stat StatFunc) (Volume, error)

func (v Volume) Dev() int64
func (v Volume) Ino() int64          // provenance only; compared by nothing
func (v Volume) IsZero() bool
func (v Volume) Contains(dev int64) bool // the only comparison; tests dev, never ino

var ErrVolumeUnresolved error
```

### 4.3 `business/types/{mtime,filekind,serial,errcode}`

```go
// mtime — seconds only. No time.Time, no arithmetic, no timezone anything.
type Mtime struct{ /* unexported int64 */ }
func ParseMtime(sec int64) Mtime
func (m Mtime) Seconds() int64
func (m Mtime) String() string

// filekind
type Kind uint8
const (KindRegular Kind = iota + 1; KindDir; KindSymlink; KindOther)
func ParseKind(mode uint32) Kind
func (k Kind) String() string
func (k Kind) IsRegular() bool
func (k Kind) IsDir() bool

// serial
type Serial struct{ /* unexported */ }
func ParseSerial(s string) (Serial, error)   // [A-Za-z0-9:._-]{1,64}
func MustParseSerial(s string) Serial
func (s Serial) String() string
func (s Serial) IsZero() bool

// errcode — the taxonomy, exactly the 15 codes in the spec's table
type Code string
const (
    CodeNoDevice Code = "no_device"; CodeUnauthorized Code = "unauthorized"
    CodeOffline Code = "offline"; CodeMultipleDevices Code = "multiple_devices"
    CodeNoADBServer Code = "no_adb_server"; CodePathDenied Code = "path_denied"
    CodeAuditUnavailable Code = "audit_unavailable"; CodeVolumeUnresolved Code = "volume_unresolved"
    CodeRootNotFound Code = "root_not_found"; CodeNotADirectory Code = "not_a_directory"
    CodePermissionDenied Code = "permission_denied"; CodePathNotFound Code = "path_not_found"
    CodeTransferFailed Code = "transfer_failed"; CodeDeviceDisconnected Code = "device_disconnected"
    CodeUnsupported Code = "unsupported"; CodeInternal Code = "internal"
)
func ParseCode(s string) Code   // unknown degrades to CodeInternal, per the spec
func (c Code) String() string
func (c Code) Fatal() bool      // does the archiver abort the run
```

`ParseMtime` and `ParseKind` cannot fail, so they return one value. That deviates from the
house `Parse<Type>(s string) (T, error)` shape in both parameter type and arity — see §11.

### 4.4 `foundation/audit`

```go
const (
    MessageID           = "8f3c1d7a5e4b42c9b1d06a2f7c93e5a4"
    MaxAnchorFieldBytes = 256 // below journald's 512-byte compression threshold, so the
                              // writer cannot emit an anchor foundation/journal can't read
)

type VolumeRef struct{ Dev, Ino int64 }

// Record field order IS the canonical serialization order. Reordering this struct changes
// every hash in the chain.
type Record struct {
    Seq            uint64
    TS             time.Time
    Op             string
    CallerUID      int
    ClientAsserted string
    Serial         string
    PathB64        string
    Decision       string // allow | deny
    Result         string // ok | error code
    Bytes          int64
    SHA256         string
    Volume         VolumeRef
    Prev           string
    Hash           string // excluded from its own input
}

func Canonical(r Record) ([]byte, error) // byte-exact, compact, no HTML escaping
func HashRecord(prev [32]byte, r Record) ([32]byte, error)

type Log struct{ /* unexported */ }

// Open fails closed: it opens O_WRONLY|O_APPEND, confirms appendability, reads the tail and
// recomputes its hash. It does NOT consult the journal — see THREAT_MODEL.md 5.6.
func Open(path string) (*Log, error)
func (l *Log) Append(r Record) (Record, error) // assigns Seq, Prev, Hash; returns the stored record
func (l *Log) Close() error

func TailRecord(path string) (Record, error)
func VerifyChain(r io.Reader) (Summary, error) // first divergence, or a clean summary
type Summary struct{ Records int; LastSeq uint64; LastHash string }

type Anchor struct{ Seq uint64; Hash string; LogPath string }
func WriteAnchor(a Anchor) error // one unixgram datagram to /run/systemd/journal/socket

var ErrAuditUnavailable error
```

### 4.5 `foundation/journal`

```go
// Filter has no optional fields. An entry is a candidate anchor only if every one matches,
// and there is no way to express "any UID" — the same reasoning as AuthorizedPath, applied
// to the one field the anchor's trustworthiness rests on. See THREAT_MODEL.md 5.5.
type Filter struct {
    MessageID string
    UID       int
    Exe       string
}

type Entry struct {
    Fields       map[string]string
    UID, GID, PID int
    Comm, Exe    string
    LoginUID     int
    RealtimeUsec int64
    Cursor       string
}

type Reader struct{ /* unexported */ }

func DefaultPaths() []string // /var/log/journal/*/*.journal then /run/log/journal/*/*.journal
func Open(paths []string) (*Reader, error) // O_RDONLY only
func (r *Reader) Close() error
func (r *Reader) Entries(f Filter) ([]Entry, error) // ascending by seqnum

var (
    ErrUnsupportedFormat error // an unrecognized incompatible flag — hard error, never "none found"
    ErrCompressed        error // a needed object is compressed; zstd is not in the stdlib
    ErrPermission        error // journal files are root:systemd-journal 0640
)
```

### 4.6 `business/domain/device/devicebus`

```go
type Device struct {
    Serial        serial.Serial
    State         string
    Model         string
    BrokerVersion string
    ServerVersion string
    Features      []string
}

type FileRecord struct {
    Path  devicepath.AuthorizedPath
    Size  int64
    Mtime mtime.Mtime
    Kind  filekind.Kind
}

type ListInput struct {
    Root     devicepath.AuthorizedPath
    Serial   serial.Serial
    MaxDepth int // 0 = unlimited, 1 = immediate children only
}

type PathError struct {
    Path devicepath.AuthorizedPath
    Code errcode.Code
}

type ListSummary struct {
    Files          int
    RefusedEntries int // non-regular or off-volume, so the symlink rule's cost is visible
    Errors         []PathError
}

type FetchResult struct{ Bytes int64; SHA256 string }

type Storer interface {
    Probe(ctx context.Context, s serial.Serial) (Device, error)
    ResolveVolume(ctx context.Context) (devicepath.Volume, error)
    List(ctx context.Context, in ListInput, vol devicepath.Volume, fn func(FileRecord) error) (ListSummary, error)
    Fetch(ctx context.Context, p devicepath.AuthorizedPath, vol devicepath.Volume, w io.Writer) (FetchResult, error)
}

// ExtBusiness is the seam. Every method an extension can wrap.
type ExtBusiness interface {
    Probe(ctx context.Context, s serial.Serial) (Device, error)
    List(ctx context.Context, in ListInput, fn func(FileRecord) error) (ListSummary, error)
    Fetch(ctx context.Context, p devicepath.AuthorizedPath, w io.Writer) (FetchResult, error)
}

type Extension func(ExtBusiness) ExtBusiness

func NewBusiness(store Storer, extensions ...Extension) ExtBusiness
```

Note the seam hides `ResolveVolume` and the `Volume` parameter: `Business` resolves the volume
itself and threads it to the `Storer`, so no extension and no caller can express an operation
without a pin. `Volume` never reaches App, exactly as the spec requires.

### 4.7 `stores/adbsyncdb`, `extensions/deviceaudit`, `app/broker`, `cmd/adb-broker`

```go
// adbsyncdb
func NewStore(brokerVersion string) *Store // satisfies devicebus.Storer
// unexported: reconnect after a terminal RECV FAIL; toSyncPath; toBusFileRecord

// deviceaudit
func NewExtension(log *audit.Log, callerUID int, clientAsserted string) devicebus.Extension

// app/broker
type ProbeRequest struct{ Serial, Client string }
type ListRequest struct{ Root, Serial, Client string; MaxDepth int }
type FetchRequest struct{ Path, Serial, Client string }
type VerifyRequest struct{ LogPath string }
// wire response structs: primitives only, exactly the spec's JSON
// converters: toBusProbeRequest, toBusListRequest, toBusFetchRequest,
//             fromBusDeviceResponse, fromBusFileRecordResponse, fromBusListSummaryResponse
func Main(args []string, stdout, stderr io.Writer) int // testable entry point
```

`app/broker.Main` taking argv and writers rather than reading `os.Args` is what makes the
subcommands testable without a subprocess, which is most of how fixture mode gets exercised.

---

## 5. Delegation

Ten agents, four waves. Waves exist because of compile dependencies, not preference — within
a wave the packages are disjoint, so agents never touch the same file.

### Wave 1 — five agents in parallel, nothing depends on anything

| Agent | Package | Model | Why this model |
|---|---|---|---|
| `wire` | `foundation/adbwire` | Opus | Binary framing with three measured landmines and a hang case. Every other package sits on it. |
| `path` | `business/types/devicepath` | Opus | Both halves of confinement. The spec calls for the densest test file in the repo. |
| `types` | `business/types/{mtime,filekind,serial,errcode}` | Sonnet | Four small wrappers, fully specified in §4.3. Transcription plus doc comments. |
| `audit` | `foundation/audit` | Opus | Byte-exact canonical serialization and a hash chain — subtle, and a writer/verifier disagreement is indistinguishable from tampering. |
| `journal` | `foundation/journal` | Opus | Undocumented-in-Go binary format, three incompatible flags, and real files to validate against. Hardest single piece. |

### Wave 2 — one agent

| Agent | Package | Model | Depends on |
|---|---|---|---|
| `bus` | `business/domain/device/devicebus` | Sonnet | `path`, `types` |

Sonnet because §4.6 freezes every type and the seam shape comes from the
`business-layer-extensions` skill. It is declarations, the reverse-apply loop, and volume
threading. I review it closely before wave 3, since everything downstream inherits the seam.

### Wave 3 — two agents in parallel

| Agent | Package | Model | Depends on |
|---|---|---|---|
| `store` | `.../stores/adbsyncdb` | Opus | `wire`, `path`, `types`, `bus` |
| `ext` | `.../extensions/deviceaudit` | Sonnet | `bus`, `audit` |

`store` is where traversal, per-dirent `dev` checks, re-parsing device-supplied paths, and
reconnect-after-`RECV`-`FAIL` all live. `ext` is a decorator against a skill-specified pattern.

### Wave 4 — two agents, then one

| Agent | Package | Model | Depends on |
|---|---|---|---|
| `app` | `app/broker` + `cmd/adb-broker` | Opus | everything |
| `fixture` | fixture `Storer` + build tag | Sonnet | `bus`, `path` |
| `devicetests` | `*_device_test.go` across packages | Sonnet | everything |

`app` and `fixture` can run in parallel — `fixture` writes only tagged files in its own
directory. `devicetests` runs last because it needs the finished surface to write against.

### Model split

Opus: `wire`, `path`, `audit`, `journal`, `store`, `app` — protocol, confinement, crypto-ish
serialization, binary parsing, traversal, and the wire contract.

Sonnet: `types`, `bus`, `ext`, `fixture`, `devicetests` — transcription against a frozen API,
a decorator with a skill to follow, and test scaffolding.

---

## 6. The brief template

One page each, same seven sections. No agent gets the whole spec; each gets the extracted
facts it needs, which is what keeps context small.

1. **Package and purpose** — one sentence, plus the file list to create.
2. **Frozen API** — verbatim from §4. "Do not change these signatures. If one is wrong,
   stop and report rather than adjusting it."
3. **Measured facts you must honour** — only the ones relevant to this package, with numbers.
   For `wire` that is the `DONE` 72-byte body, the double-encoded `host:version`, the
   over-long-prefix hang, empty-list-is-`OKAY`, and the four `FAIL` strings. For `path` it is
   the NUL truncation, `..`, relative paths, trailing slashes, `Download-private`, the three
   spellings, and the `dev` values.
4. **Required test cases, by name** — the spec already enumerates most of these. An agent may
   add more; it may not skip a listed one.
5. **Scope fence** — do not create or edit files outside your directory; do not add a
   dependency; do not modify `go.mod`; do not run module-wide `go vet ./...` or `go test ./...`,
   because siblings are mid-write. Verify with `go test ./<your-package>/...` only.
6. **Skills to load** — `use-modern-go` always; `layered-architecture-types` for anything
   under `app/`, `business/domain/`, or a store; `business-layer-extensions` for `ext` and
   `bus`; `branching-logic-flow` where there is branching.
7. **Definition of done** — its own package builds, `go test -race` passes, `staticcheck` on
   that package is clean, every listed test case exists, and every exported symbol has a doc
   comment saying *why* where the reason is not obvious.

---

## 7. Integration gates

I run these; agents do not.

| Gate | After | Checks |
|---|---|---|
| G1 | Wave 1 | `go build ./...`, `make test-unit`, `make lint`, `make deps-check`. API conformance against §4, by reading the exported surface rather than trusting reports. |
| G2 | Wave 2 | G1 plus: the seam matches the skill, `Volume` appears in no App-facing type. |
| G3 | Wave 3 | G1 plus `make test-integration` against the live adb server with no device. |
| G4 | Wave 4 | Everything, plus `make build`, `make build-fixture`, and a fixture-mode end-to-end run of all four subcommands. |

Any gate failure is fixed before the next wave starts. If an agent returns something that
does not match §4, I fix the seam myself rather than re-briefing — cheaper than a round trip,
and it keeps the frozen API actually frozen.

---

## 8. Test strategy

Four build configurations, because they need genuinely different things present.

| Tag | Command | Needs | Covers |
|---|---|---|---|
| *(none)* | `make test-unit` | nothing | Framing against synthetic bytes, every path rule, chain and canonical serialization, journal parsing against synthetic files, converters. The bulk. |
| `integration` | `make test-integration` | adb server, **no device** | Real `host:version` double encoding, empty-list-is-`OKAY`, all four `FAIL` strings, malformed-prefix cases, the over-long-prefix hang hitting our deadline. The discovery experiment showed this is the productive place to start. |
| `fixture` | `make test-fixture` | nothing | Traversal, recursion, `dev` checks, symlink refusal, fetch framing, truncation, NDJSON, all four subcommands end to end. **The substitute for hardware.** |
| `device` | `make test-device` | a phone | §9. |

Three test techniques worth naming, because they are what make the phone-free coverage real:

- **A recorded-bytes server for `adbwire`.** A `net.Listener` on loopback replaying byte
  sequences taken verbatim from `adb_experiment.md`. This is how the `DONE`-with-72-zero-bytes
  desync gets a regression test: feed a `LIS2` stream, assert the next command on the same
  channel still works. That bug produced a confident wrong answer, so the test asserts on the
  *following* command, not on the listing.
- **A synthetic journal file writer for `foundation/journal`.** Construct headers with each
  flag combination — including `COMPACT` on and off — so both entry layouts are covered without
  needing a host that produces both. Then a read-only pass over the real
  `/var/log/journal/*.journal` files, tagged `integration` since it needs group membership.
- **Fixture symlink escapes.** One symlink inside the fixture tree pointing at `/tmp`
  (different filesystem on most hosts, so the `dev` check fires) and one pointing within the
  same filesystem (so the kind check fires, and only the kind check can). The spec already
  warns that a same-filesystem target makes the `dev` half pass for the wrong reason, so these
  assert on the *refusal reason*, not merely the refusal.

---

## 9. Device test manifest

Written now, tagged `device`, skipped tonight, run in one command when the phone is back.
Each is a claim from the experiment record that only hardware can confirm end to end.

| Test | Asserts |
|---|---|
| `TestDeviceProbeReportsDeviceState` | `host:devices` state token is `device`; `stat_v2`/`ls_v2`/`sendrecv_v2` present via `host-serial:<serial>:features` |
| `TestDeviceFeaturesNotServerFeatures` | The device list differs from `host:host-features` — device has `devraw`, server has `push_sync` |
| `TestDeviceVolumePinResolves` | `STA2 /sdcard` yields a directory; pinned `dev` is the media volume |
| `TestDeviceAllSixRootsExist` | All six allowlist roots present, directories, same `dev` |
| `TestDeviceRootsHaveNoRegularFilesAtDepthOne` | Depth-1 listing of every root is empty — the silent-success trap |
| `TestDeviceListCameraMatchesStat` | `LIS2` sizes and mtimes equal per-file `LST2` |
| `TestDeviceFetchLargestFileByteExact` | Byte count equals the listing size exactly |
| `TestDeviceFetchZeroByteFile` | No `DATA` packets, `DONE` immediately, digest is `e3b0c442…` |
| `TestDeviceRecvFailIsTerminal` | After a failed `RECV` the channel is dead and the store reconnects |
| `TestDeviceLstatDoesNotFollowSymlink` | `LST2 /sdcard` is a symlink, `STA2 /sdcard` is a directory |
| `TestDeviceNulPathIsRefusedBeforeSend` | The broker rejects it; nothing reaches the device |
| `TestDeviceOffVolumePathDenied` | `/data/data` refused by the allowlist before any transport |
| `TestDeviceAuditRecordsMatchOperations` | One record per operation, chain verifies, `verify` clean against a real anchor |

Two of these are the ones I most want on hardware: `TestDeviceRecvFailIsTerminal`, because the
reconnect path is otherwise only fixture-tested, and `TestDeviceRootsHaveNoRegularFilesAtDepthOne`,
because its failure mode is a successful run reporting an empty phone.

---

## 10. Commits and review

One commit per package, message in the established style — what changed, why, and which
measurement forced it. Commit at each gate, not per agent, so the tree is always buildable.
Push to `feature/adb-broker-plan` as we go; single PR at the end, per your earlier choice.

Expected sequence: `foundation/errs` + `go.mod` + `Makefile` (already written) → five wave-1
packages → `devicebus` → `adbsyncdb` + `deviceaudit` → `app` + `cmd` → fixture mode → device
tests.

---

## 11. Decisions I need from you

None of these block tonight — I have a default for each and will note which I took. The
`layered-architecture-types` skill says the type choices are yours, so they are listed rather
than assumed silently.

1. **`ParseMtime(sec int64) Mtime` and `ParseKind(mode uint32) Kind` cannot fail**, so they
   return one value and take a non-string parameter. That is a double deviation from the house
   `Parse<Type>(s string) (T, error)` shape. The alternative is a vestigial `error` that is
   always nil, which every call site then has to pretend to check. **Default: no error.**
2. **`errcode.Code` is a `string`, not an integer enum.** It appears in JSON as its own text
   and the archiver treats unknown values as `internal`, so a string is the honest
   representation and `ParseCode` needs no table lookup to round-trip. **Default: string.**
3. **`ListSummary.Errors` is `[]PathError` with a strong `Path`**, and flattens to primitives
   only in `fromBusListSummaryResponse`. **Default: as written in §4.6.**
4. **`app/broker.Main(args []string, stdout, stderr io.Writer) int`** rather than reading
   `os.Args` and `os.Exit` directly, so subcommands are testable in-process. **Default: as
   written.**
5. **`foundation/journal.Filter` has no optional fields** — no "any UID" is expressible. This
   makes the security-critical filter unforgettable but means a debugging session cannot
   easily dump all anchors. **Default: keep it closed**; a separate `--all` path can be added
   to `verify` later if it proves annoying.

---

## 12. Risks

| Risk | Handling |
|---|---|
| An agent invents a different API and a sibling breaks | §4 is frozen and quoted verbatim into each brief. Mismatches are fixed by me at the gate, not renegotiated. |
| Agents confused by siblings' half-written packages | Briefs forbid module-wide commands; verification is per-package. |
| The journal reader is the deepest unknown | Self-contained, validated against real files, and `verify` is the only consumer — a failure there does not block `probe`/`list`/`fetch`. If it overruns, it is the one piece that can land in iteration 2 without holding anything up. |
| Fixture mode carrying more weight than the spec intended | It is the only end-to-end coverage available without a phone, so its own tests must exercise real confinement code against virtual paths, never a bypass. Called out in the `fixture` brief. |
| Device tests written blind against hardware that disagrees | They are written from `adb_experiment.md`'s recorded values, so a disagreement is a real finding rather than a broken test. Expect at least one to fail for an interesting reason. |
| `chattr +a` and the real log absent in CI | Unit tests use temp files. The installed log is exercised only by manual runs and by `verify-install`. |
