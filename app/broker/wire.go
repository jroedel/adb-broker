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
type ProbeResponse struct {
	Proto  int    `json:"proto"`
	Status string `json:"status"`
	Serial string `json:"serial"`
	State  string `json:"state"`
	Model  string `json:"model"`
	Broker string `json:"broker"`
	ADB    string `json:"adb"`
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
// Path here is the lossy human rendering with no authoritative companion, because the
// contract specifies these two members and only these two. A per-path error naming a
// filename that is not valid UTF-8 is therefore not round-trippable — see the note in the
// package's README-level docs; it is a weakness of the specified shape rather than of this
// converter.
type PathErrorResponse struct {
	Code string `json:"code"`
	Path string `json:"path"`
}

// ListSummaryResponse is the single object that terminates a list stream.
//
// It is distinguished from a record by having NO path member — that is the documented
// discriminator, so no member named path may ever be added here.
//
// Status is "ok" when nothing failed and "partial" when some paths failed but records were
// still produced. A partial listing exits 0: the consumer needs to tell "nothing was
// listed, so the root is wrong" from "some paths failed, so warn and carry on", and an
// exit status that conflated them would take that away.
//
// Errors is always present, as [] when there were none, so a consumer never has to
// distinguish an absent member from an empty one.
type ListSummaryResponse struct {
	Proto  int                 `json:"proto"`
	Status string              `json:"status"`
	Files  int                 `json:"files"`
	Errors []PathErrorResponse `json:"errors"`
}

// FetchHeader is the line that precedes a fetch payload. It is framing rather than a
// converted Business value: Size states exactly how many raw bytes follow, which is what
// lets a consumer read that many and then require a trailer.
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
// logging the member would print an empty one.
type ErrorResponse struct {
	Proto   int    `json:"proto"`
	Status  string `json:"status"`
	Code    string `json:"code"`
	Path    string `json:"path,omitzero"`
	Message string `json:"message"`
}
