package broker

// This file is the whole stdout contract, in one place. Nothing else in the package
// declares a field a consumer parses.
//
// Every type here holds primitives only — strings, ints and slices of them. No
// business/types strong type may appear in a request or a response: requests are parsed
// into strong types by the toBus* converters in convert.go, and responses are built from
// strong types by the fromBus*Response converters there, field by field. That is not
// ceremony. It is what keeps a strong type's MarshalJSON from silently becoming the wire
// format, which is how a field nobody chose ends up in a contract.

// proto is the protocol version every object that carries a version carries. A consumer
// checks it at probe time and refuses to run against a major version it does not know, so
// it is compiled in and is not settable at runtime.
//
// Note that not every stdout object carries it: a list record and a fetch trailer do not.
// See ListSummaryResponse and FetchTrailer, where the reason is recorded.
//
// proto stayed at 1 when ProbeResponse.Model was removed (see ProbeResponse), and that is a
// one-time exception, not a precedent. Removing a member is normally exactly what a major
// bump exists to record: a consumer must be able to tell "this field never existed" from
// "this field existed and vanished out from under me", and only a version number carries
// that distinction. The exception held here only because nothing has ever consumed this
// contract — the first consumer is being written now — so proto 1 had no installed base to
// protect and no reader who had ever depended on Model. A version number recording the
// removal of a member no consumer ever read would be noise every future reader has to
// decode. The next member removed from this contract, once a consumer exists, does not get
// this exception: bump proto.
const proto = 1

// The three values of the status field. status is authoritative and the process exit code
// is a coarse signal derived from it — never the other way round.
const (
	statusOK      = "ok"
	statusPartial = "partial"
	statusError   = "error"
)

// ProbeRequest is the probe subcommand's flags.
//
// Primitives only: --serial arrives as a string and becomes a serial.Serial in
// toBusProbeRequest, never here. Client is the caller-asserted --client label and stays a
// string at every layer, because it is recorded as untrusted — promoting it to a validated
// type would suggest the value means something.
type ProbeRequest struct{ Serial, Client string }

// ListRequest is the list subcommand's flags. Primitives only; --root becomes a
// devicepath.AuthorizedPath in toBusListRequest.
//
// MaxDepth has exactly two meanings, matching devicebus.ListInput: 0 is unlimited and 1 is
// immediate children only.
type ListRequest struct {
	Root     string
	Serial   string
	Client   string
	MaxDepth int
}

// FetchRequest is the fetch subcommand's flags. Primitives only; --path becomes a
// devicepath.AuthorizedPath in toBusFetchRequest.
type FetchRequest struct{ Path, Serial, Client string }

// VerifyRequest is the verify subcommand's flags.
//
// LogPath defaults to the compiled-in audit log path; the flag exists because verify reads
// a log rather than writing one, and an operator investigating a copy of a log must be able
// to name it. AnchorsPath is a journal file or glob, or "-" for newline-delimited JSON
// anchors on stdin.
type VerifyRequest struct{ LogPath, AnchorsPath string }

// ProbeResponse is the single object probe writes to stdout.
//
// State is the transport's own state token, reported VERBATIM — "device",
// "unauthorized", "offline", "bootloader", … A consumer treats anything other than
// "device" as fatal and needs the raw token to say why, so it is never mapped here.
//
// The pinned storage volume is deliberately absent. It goes to the audit log and nowhere
// else: a consumer has no use for it, and giving it one would invite reasoning about the
// phone's storage layout, which is this binary's job and not its consumer's.
//
// There is no Model member and there must never be one. Reading a device's model requires
// a shell, and this binary has none and never will — see adbsyncdb.Store.Probe and
// fixturedb.Store.Probe, where that is the measured reason both stores leave it out. This is
// the same call already made for FileRecordResponse's mtime_nsec: a field that can never be
// populated does not belong in a contract inviting someone to try, so the rule is documented
// as MUST NOT rather than always-empty.
//
// The last two members are the only ones a consumer reads in order to decide how to CALL
// this binary rather than to learn about the phone. Both replace something a consumer could
// otherwise only discover by connecting to a device and being refused.
type ProbeResponse struct {
	Proto  int    `json:"proto"`
	Status string `json:"status"`
	Serial string `json:"serial"`
	State  string `json:"state"`
	Broker string `json:"broker"`
	ADB    string `json:"adb"`

	// AttachedDevices is how many devices the transport reported as attached, and it is the
	// one member here that is easy to misread. It counts EVERY device the adb server listed:
	// it is NOT the number matching --serial — probing with --serial while two phones are
	// plugged in reports 2 — and it is NOT a count of devices this broker could serve, since
	// a phone in state "unauthorized" or "offline" is attached and is counted.
	//
	// The single question it answers is whether an operation that names no device could be
	// ambiguous. That is worth a member of its own because a fetch cannot be given a serial
	// for free: devicebus.ExtBusiness.Fetch takes no serial by design, so the only way this
	// binary can honour `fetch --serial` is to run a full probe first, and on a first run of
	// ~20,000 files that is 20,000 extra audited operations and 20,000 extra audit records
	// (see runFetch). A consumer that reads 1 here can omit --serial on every fetch and pay
	// none of it. A consumer that reads 2 must pass one, whatever the second phone's state.
	AttachedDevices int `json:"attached_devices"`

	// Allowlist is every root this binary can reach on the device, sorted — the compiled
	// allowlist as devicepath.Roots reports it.
	//
	// It is reported because path_denied for a misconfigured source is a CONFIGURATION error,
	// and without this member a consumer can only discover one by connecting to a phone and
	// being refused, once per configured source. With it, a consumer validates its sources at
	// startup and fails fast.
	//
	// Reporting it widens nothing, which is why it is safe to report at all: the allowlist is
	// compiled in, no flag, environment variable or config key adds to it, and devicepath's
	// Narrow can only take roots away. The list is a statement about THIS BINARY and not about
	// the device — which is why it does not travel out through the Business layer the way the
	// pinned volume does; see fromBusDeviceResponse.
	//
	// Always present and never empty: devicepath.Roots returns a copy of a non-empty list, so
	// a consumer never distinguishes an absent member from an empty one.
	Allowlist []string `json:"allowlist"`
}

// FileRecordResponse is one NDJSON record in a list stream: one regular file, written as it
// is discovered.
//
// It carries no proto member, unlike the summary that terminates the stream. That is the
// format as specified, and it is also the right shape: proto belongs on the object a
// consumer inspects once, not on each of twenty thousand records.
//
// PathB64 IS THE AUTHORITATIVE PATH FIELD. Android filenames are byte strings that need
// not be valid UTF-8, while a JSON string must be, so Path is a lossy rendering for humans
// and PathB64 is the base64 of the raw device bytes. A consumer that fetches the path it
// read from Path may be asking for a file that does not exist; one that decodes PathB64
// cannot. The coercion happens exactly once, in fromBusFileRecordResponse.
//
// There is no mtime_nsec member and there must never be one. The sync protocol's
// STAT_V2/LIST_V2 reply carries atime, mtime and ctime as whole seconds with no sub-second
// companion — sub-second precision is unavailable over this transport, not merely
// unimplemented — and a field that can never be populated does not belong in a contract
// inviting someone to try.
type FileRecordResponse struct {
	Path    string `json:"path"`
	PathB64 string `json:"path_b64"`
	Size    int64  `json:"size"`
	Mtime   int64  `json:"mtime"`
}

// PathErrorResponse is one per-path failure in a list summary: a path the walk could not
// read, paired with its classification, so a consumer can decide from Code alone whether to
// warn and carry on.
//
// PathB64 exists for the same reason FileRecordResponse's does, and its absence here was a
// defect rather than a deliberate omission: Android filenames are byte strings that need
// not be valid UTF-8, and this is the one place in the contract a consumer might want to ACT
// on a path rather than merely display it — retry it, key a log by it, exclude it from a
// later run. Giving that one place only the lossy rendering, while every other path member
// in this contract is authoritative-by-base64, made it the one path a consumer could not
// safely use. Path stays for the human-readable line; PathB64 is what a consumer round-trips
// through, populated the same way fromBusFileRecordResponse populates a record's.
type PathErrorResponse struct {
	Code    string `json:"code"`
	Path    string `json:"path"`
	PathB64 string `json:"path_b64"`
}

// ListSummaryResponse is the single object that terminates a list stream when the walk
// finished, successfully or partially.
//
// It is NOT distinguished from a record by the absence of a path member — that was the
// originally specified rule and it is unsafe. A list stream can also terminate with an
// ErrorResponse instead of a summary (see runList), and ErrorResponse DOES carry a path
// when the failure names one, e.g.
// {"proto":1,"status":"error","code":"path_denied","path":"/sdcard/NOPE",...}. A consumer
// that decodes "no path member present" as "this is a file record" reads that error object
// as a record with an empty path, zero size and zero mtime, and silently loses Code — a
// collision that depends on which error fired, so it survives hand-testing and only shows
// up in production. The safe discriminator is the presence of a status member: every
// terminator, summary or error alike, carries one, and FileRecordResponse never does. That
// is why status has no omitzero here or on ErrorResponse — a terminator's status is never
// allowed to disappear from the wire.
//
// Status is "ok" when nothing failed and "partial" when some paths failed but records were
// still produced. A partial listing exits 0: the consumer needs to tell "nothing was
// listed, so the root is wrong" from "some paths failed, so warn and carry on", and an
// exit status that conflated them would take that away.
//
// Errors is always present, as [] when there were none, so a consumer never has to
// distinguish an absent member from an empty one.
//
// Files is exactly the number of records that preceded this summary on the same stream —
// contract, not an implementation detail. It is what a consumer that counted records as it
// decoded them compares against, and the specification left it unstated until the first
// consumer performed that comparison and had to treat any disagreement as unactionable. It is
// not a count of files on the device and not a count of what a consumer's own policy kept: the
// broker applies no content filtering, so the only sound comparison is against this stream.
type ListSummaryResponse struct {
	Proto  int                 `json:"proto"`
	Status string              `json:"status"`
	Files  int                 `json:"files"`
	Errors []PathErrorResponse `json:"errors"`
}

// FetchHeader is the line that precedes a fetch payload. It is framing rather than a
// converted Business value: Size states exactly how many raw bytes follow, which is what
// lets a consumer read that many and then require a trailer.
//
// It carries no status member, and that absence is load bearing: a fetch that fails BEFORE the
// header writes an ErrorResponse in its place (see runFetch), so the first line of a fetch is
// either this struct or that one, discriminated exactly as a list terminator is — by the
// presence of status. A consumer that assumes a header unconditionally decodes an error object
// into this struct, reads Size as 0, and cannot then tell a failed fetch from the zero-byte file
// that exists on the target device. Requiring the trailer even for a zero-size header is the
// second half of what closes that; both halves are in the specification.
type FetchHeader struct {
	Proto int    `json:"proto"`
	Op    string `json:"op"`
	Size  int64  `json:"size"`
}

// FetchTrailer is the line that follows a fetch payload, and its presence is the whole
// point of the framing: a stream that ends without a trailer is a failure whatever the byte
// count said.
//
// It carries no proto member, matching the specified format — the header of the same
// exchange already carried one, and a consumer has read it before it can reach this line.
//
// SHA256 is the digest of the bytes this broker forwarded. Be precise about what that
// buys: it detects corruption between the broker and the consumer, and a bug in the
// consumer's own write path. It is not end-to-end device verification, because the broker
// never re-reads the device. A zero-byte file is a success with no bytes between the two
// lines and the empty-input digest here.
type FetchTrailer struct {
	Status string `json:"status"`
	Bytes  int64  `json:"bytes"`
	SHA256 string `json:"sha256"`
}

// VerifyResponse is the single object verify writes to stdout when it found no divergence.
//
// Status is "ok" when the chain verified and a trustworthy anchor agreed with its head, and
// "partial" when the chain verified but no trustworthy anchor was available to compare
// against — the tail-truncation check is the one thing the chain cannot do for itself, so a
// run that could not perform it must not claim it did.
type VerifyResponse struct {
	Proto      int    `json:"proto"`
	Status     string `json:"status"`
	Log        string `json:"log"`
	Records    int    `json:"records"`
	LastSeq    uint64 `json:"last_seq"`
	LastHash   string `json:"last_hash"`
	Anchors    int    `json:"anchors"`
	AnchorSeq  uint64 `json:"anchor_seq"`
	AnchorHash string `json:"anchor_hash"`
}

// ErrorResponse is the single object a failed operation writes to stdout.
//
// Code comes from errcode.From — the classification the failing layer already decided on,
// read through the errcode.Coder contract. It is never derived from Message, and Message is
// never parsed: a second mapping of failures to codes, subtly different from the first, is
// the exact failure this broker exists to remove.
//
// Path is omitted when the failure names no path, because "" is not a path and a consumer
// logging the member would print an empty one. PathB64 is omitted under exactly the same
// condition — present whenever Path is, absent otherwise, via the same omitzero tag — so a
// consumer never has to work out whether a missing PathB64 means "no path" or "the broker
// forgot to encode it".
//
// PathB64 must be built from the SAME raw path bytes as Path, never derived from Path
// itself. Path is a display rendering: every call site that produces an ErrorResponse
// receives a path that has already been coerced to valid UTF-8 by displayBytes, because a
// rejected path may itself contain bytes that are not valid UTF-8 and a report that cannot
// be encoded is not a report. Base64-encoding that coerced string would encode the U+FFFD
// replacement character in place of whatever byte sequence was actually rejected — a value
// that LOOKS authoritative and is not, which is worse than PathB64 being absent. See
// fromBusErrorResponse in convert.go, which is the one place both members are built,
// each from the same raw string, so they cannot drift apart.
type ErrorResponse struct {
	Proto   int    `json:"proto"`
	Status  string `json:"status"`
	Code    string `json:"code"`
	Path    string `json:"path,omitzero"`
	PathB64 string `json:"path_b64,omitzero"`
	Message string `json:"message"`
}
