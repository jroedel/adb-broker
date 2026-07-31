package broker

import (
	"encoding/base64"
	"fmt"
	"strings"

	"github.com/jroedel/adb-broker/business/domain/device/devicebus"
	"github.com/jroedel/adb-broker/business/types/devicepath"
	"github.com/jroedel/adb-broker/business/types/errcode"
	"github.com/jroedel/adb-broker/business/types/serial"
	"github.com/jroedel/adb-broker/foundation/audit"
	"github.com/jroedel/adb-broker/foundation/errs"
)

// The App layer's converters. Every crossing of the App/Business boundary goes through one
// of these, in one direction, by name:
//
//	App → Business   toBus<Type>Request        parses and validates, accumulating errs.FieldErrors
//	Business → App   fromBus<Type>Response     converts each strong field explicitly
//
// ALL parsing and validation lives on this side. A request struct carries strings; a
// converter turns them into devicepath.AuthorizedPath and serial.Serial and reports every
// invalid flag at once, because a caller that passed three bad flags should learn about
// three bad flags in one run rather than one invocation at a time.
//
// The reverse direction is explicit field by field, never a strong type's MarshalJSON: a
// response member must already be a primitive by the time encoding/json sees it, or the wire
// format silently becomes whatever that method happens to do.

// maxClientBytes is the hard limit on the --client label.
//
// The label is bounded rather than sanitized: at most this many bytes, drawn from
// [A-Za-z0-9._-], and anything else is rejected outright at the flag boundary. Sanitizing
// would mean the audit log recorded a value the caller never sent, which is a small lie in
// the one file whose whole purpose is being believed.
const maxClientBytes = 64

// probeInput is what probe needs once its flags have been validated: a Business serial, and
// the caller-asserted label the audit extension records.
//
// The label stays a primitive string. It is untrusted by design and is recorded verbatim, so
// there is no strong type to promote it to — a validated-label type would suggest the value
// means something.
type probeInput struct {
	serial serial.Serial
	client string
}

// listInput pairs the Business ListInput with the caller-asserted label.
type listInput struct {
	list   devicebus.ListInput
	client string
}

// fetchInput is what fetch needs: the authorised path, the optional device to pin, and the
// caller-asserted label.
type fetchInput struct {
	path   devicepath.AuthorizedPath
	serial serial.Serial
	client string
}

// verifyInput is what verify needs. It crosses no Business boundary — verify reads the audit
// log and the journal and touches no device — so it is deliberately not named toBus*: there
// is no Business type on the other side to convert into.
type verifyInput struct {
	logPath     string
	anchorsPath string
	fromStdin   bool
}

// toBusProbeRequest parses and validates probe's flags.
func toBusProbeRequest(req ProbeRequest) (probeInput, error) {
	var fieldErrors errs.FieldErrors

	ser, err := toBusSerial(req.Serial)
	fieldErrors.Add("serial", err)

	client, err := toClientLabel(req.Client)
	fieldErrors.Add("client", err)

	if !fieldErrors.Empty() {
		return probeInput{}, fieldErrors
	}

	return probeInput{serial: ser, client: client}, nil
}

// toBusListRequest parses and validates list's flags.
//
// --root goes through devicepath.ParseAuthorizedPath, which is the only way a caller-supplied
// string becomes a path the storage layer will accept: it applies the compiled allowlist and
// every rejected path form. A denied root therefore fails HERE, before a bus exists and
// before any transport connection is attempted.
func toBusListRequest(req ListRequest) (listInput, error) {
	var fieldErrors errs.FieldErrors

	root := toBusRoot("root", req.Root, &fieldErrors)

	ser, err := toBusSerial(req.Serial)
	fieldErrors.Add("serial", err)

	client, err := toClientLabel(req.Client)
	fieldErrors.Add("client", err)

	if req.MaxDepth < 0 {
		// devicebus refuses a negative depth too, but reporting it here keeps it with the
		// other flag problems in one message rather than arriving after a device connection.
		fieldErrors.Addf("max-depth", "%d has no meaning: 0 is unlimited and 1 is immediate children only", req.MaxDepth)
	}

	if !fieldErrors.Empty() {
		return listInput{}, fieldErrors
	}

	return listInput{
		list: devicebus.ListInput{
			Root:     root,
			Serial:   ser,
			MaxDepth: req.MaxDepth,
		},
		client: client,
	}, nil
}

// toBusFetchRequest parses and validates fetch's flags, --path through the same
// devicepath.ParseAuthorizedPath the listing root goes through.
func toBusFetchRequest(req FetchRequest) (fetchInput, error) {
	var fieldErrors errs.FieldErrors

	path := toBusRoot("path", req.Path, &fieldErrors)

	ser, err := toBusSerial(req.Serial)
	fieldErrors.Add("serial", err)

	client, err := toClientLabel(req.Client)
	fieldErrors.Add("client", err)

	if !fieldErrors.Empty() {
		return fetchInput{}, fieldErrors
	}

	return fetchInput{path: path, serial: ser, client: client}, nil
}

// toVerifyInput validates verify's flags. See verifyInput for why this is not a toBus* name.
func toVerifyInput(req VerifyRequest) (verifyInput, error) {
	var fieldErrors errs.FieldErrors

	if req.LogPath == "" {
		fieldErrors.Addf("log", "is empty; omit the flag to verify the compiled-in audit log")
	}

	if req.AnchorsPath == "" {
		// Required rather than defaulted to the system journal: the anchor comparison is the
		// only check that can detect a truncated tail, and an operator who did not say where
		// the anchors are must not be told the log verified.
		fieldErrors.Addf("anchors", `is required: "-" reads newline-delimited JSON anchors from stdin, which is the only form that works on a setuid install (pipe "journalctl -o json MESSAGE_ID=`+audit.MessageID+`" run as root); a journal file or glob is accepted only where this process can read the journal files`)
	}

	if !fieldErrors.Empty() {
		return verifyInput{}, fieldErrors
	}

	return verifyInput{
		logPath:     req.LogPath,
		anchorsPath: req.AnchorsPath,
		fromStdin:   req.AnchorsPath == "-",
	}, nil
}

// toBusRoot parses one path flag, distinguishing "you did not give me one" from "the one you
// gave me is denied".
//
// The distinction is not cosmetic: an absent flag is a usage error and a denied path is a
// confinement decision, and they map to different codes on the wire. An empty string would
// otherwise be refused by the path rules and reported as path_denied, which reads as "that
// location is forbidden" to a caller that simply forgot an argument.
// It accumulates into fieldErrors rather than returning an error, so that a caller cannot
// forget to record the failure and proceed with the zero path — which authorises nothing,
// but would reach the Business layer as "the zero path names nothing" instead of as the
// caller's actual mistake.
func toBusRoot(field, raw string, fieldErrors *errs.FieldErrors) devicepath.AuthorizedPath {
	if raw == "" {
		fieldErrors.Addf(field, "is required")

		return devicepath.AuthorizedPath{}
	}

	p, err := devicepath.ParseAuthorizedPath(raw)
	fieldErrors.Add(field, err)

	return p
}

// toBusSerial parses the optional --serial.
//
// An empty flag is not an error: it means "the one attached device", which the Business
// layer expresses as the zero Serial. With several devices attached the store refuses with
// multiple_devices rather than picking one, which is where that decision belongs.
func toBusSerial(raw string) (serial.Serial, error) {
	if raw == "" {
		return serial.Serial{}, nil
	}

	return serial.ParseSerial(raw)
}

// toClientLabel validates the caller-asserted --client label and returns it unchanged.
//
// Rejected outright, never sanitized: see maxClientBytes. The check is over BYTES rather
// than runes because the limit the audit record and the journal anchor care about is a byte
// length, and because every accepted byte is ASCII by construction.
func toClientLabel(raw string) (string, error) {
	switch {
	case raw == "":
		return "", nil

	case len(raw) > maxClientBytes:
		return "", fmt.Errorf("label is %d bytes, and at most %d are accepted", len(raw), maxClientBytes)
	}

	for i := range len(raw) {
		if !isClientByte(raw[i]) {
			return "", fmt.Errorf("byte %d is %q, and only [A-Za-z0-9._-] is accepted", i, raw[i:i+1])
		}
	}

	return raw, nil
}

// isClientByte reports whether b is one of the bytes a --client label may contain.
func isClientByte(b byte) bool {
	switch {
	case b >= 'A' && b <= 'Z', b >= 'a' && b <= 'z', b >= '0' && b <= '9':
		return true
	case b == '.', b == '_', b == '-':
		return true
	default:
		return false
	}
}

// fromBusDeviceResponse converts a probed Device into probe's response object.
//
// State is copied verbatim: it is the transport's own token and a consumer needs the raw
// value to say why a device is unusable. Device.Volume is deliberately not represented —
// there is no App-side representation of the pinned volume anywhere in this package, which
// is what makes "the volume never crosses into the App layer" a fact rather than a rule to
// remember.
//
// Allowlist is the one member that does NOT come from dev, and that is the deliberate part.
// devicepath.Roots reports what THIS BINARY compiled in — nothing the phone said, nothing a
// Storer measured — so routing it through devicebus.Device would have both stores populate a
// compiled constant neither of them learned from a device: two chances to derive one list
// differently, and a value the audit extension would then record on every probe as though it
// were device state. Contrast the pinned Volume, which travels outward precisely because only
// the Storer can know it. The allowlist is readable identically from every layer, so it is
// read here, at the one edge that reports it.
//
// Roots already returns a sorted copy of the allowlist in force, so this must not sort,
// filter or re-derive it — and it must never be built from a second list of roots kept here,
// which would be a copy free to drift from the one ParseAuthorizedPath enforces.
//
// AttachedDevices is copied through as the int the Storer counted. See ProbeResponse for what
// it counts, which is not what a reader expects.
func fromBusDeviceResponse(dev devicebus.Device) ProbeResponse {
	return ProbeResponse{
		Proto:           proto,
		Status:          statusOK,
		Serial:          dev.Serial.String(),
		State:           dev.State,
		Broker:          dev.BrokerVersion,
		ADB:             dev.ServerVersion,
		AttachedDevices: dev.AttachedDevices,
		Allowlist:       devicepath.Roots(),
	}
}

// fromBusFileRecordResponse converts one discovered file into one NDJSON record.
//
// THIS IS THE ONE PLACE A DEVICE PATH IS COERCED TO UTF-8, and it happens only for the
// human-readable Path member. A filename on the device is a byte string that need not be
// valid UTF-8, while a JSON string must be, so PathB64 — the base64 of the raw bytes — is
// the authoritative member and Path is lossy. Coercing here, explicitly, is what keeps the
// coercion from happening twice or somewhere less visible: by the time encoding/json sees
// Path it is already valid UTF-8, so the encoder changes nothing.
//
// FileRecord.Kind is not represented. Only regular files are ever emitted, so a kind member
// would be a constant, and a constant on the wire invites a consumer to branch on it.
func fromBusFileRecordResponse(rec devicebus.FileRecord) FileRecordResponse {
	return FileRecordResponse{
		Path:    displayPath(rec.Path),
		PathB64: rec.Path.Base64(),
		Size:    rec.Size,
		// Whole Unix seconds, exactly as the device reported them. Not normalized, not
		// adjusted for a timezone, not reconciled with anything: the consumer's incremental
		// fast path depends only on the same file reporting the same value on two runs, and
		// any "helpful" correction breaks that for every file the moment it disagrees with
		// itself. There is no companion nanosecond member because the transport has none.
		Mtime: rec.Mtime.Seconds(),
	}
}

// fromBusListSummaryResponse converts the finished walk into the summary that terminates the
// stream.
//
// Status is partial when any path failed and ok otherwise. ListSummary.RefusedEntries — the
// symlinks, sockets and off-volume entries the walk omitted — does NOT make a listing
// partial and is not represented: those are confinement decisions about entries that were
// never going to be served, not failures to read something that should have been readable,
// and reporting them as errors would have a consumer warning about a phone that is behaving
// exactly as expected.
//
// Errors is always a non-nil slice, so the member is present as [] rather than null.
func fromBusListSummaryResponse(sum devicebus.ListSummary) ListSummaryResponse {
	pathErrors := make([]PathErrorResponse, len(sum.Errors))
	for i, pe := range sum.Errors {
		pathErrors[i] = PathErrorResponse{
			Code:    pe.Code.String(),
			Path:    displayPath(pe.Path),
			PathB64: pe.Path.Base64(),
		}
	}

	status := statusOK
	if len(pathErrors) > 0 {
		status = statusPartial
	}

	return ListSummaryResponse{
		Proto:  proto,
		Status: status,
		Files:  sum.Files,
		Errors: pathErrors,
	}
}

// fromBusFetchResultResponse converts a completed transfer into the fetch trailer.
//
// FetchResult.Serial and FetchResult.Volume are not represented. Both travel outward for the
// audit log's benefit — the log records which phone and which filesystem the bytes came
// from — and neither is part of the stdout contract.
func fromBusFetchResultResponse(result devicebus.FetchResult) FetchTrailer {
	return FetchTrailer{
		Status: statusOK,
		Bytes:  result.Bytes,
		SHA256: result.SHA256,
	}
}

// fromBusErrorResponse builds the error object writeError puts on stdout, from rawPath —
// the RAW bytes of the path the failing operation named, never a value that has already
// been through displayBytes.
//
// This is the one place both Path and PathB64 are built, and it exists because they must
// be built from the SAME string. writeError's callers (fail, failCode, failUsage,
// denyBeforeBus, all in broker.go) sit on the far side of the App/Business boundary from a
// device path's raw bytes, and the historical shortcut was to coerce to display form once,
// close to where the path was obtained, and hand that single string all the way down to
// ErrorResponse. That shortcut is exactly what would make PathB64 wrong: Base64-encoding an
// already-coerced string encodes U+FFFD in place of whatever byte sequence was actually
// rejected, producing a value that looks authoritative and is not. Threading rawPath down to
// this converter instead of re-deriving one string from the other is the only way both
// members describe the same bytes.
//
// rawPath == "" means the failure names no path at all, not an empty one. Path and PathB64
// both come out as their zero value in that case, and ErrorResponse omits both via the same
// omitzero tag, so a consumer never has to tell "no path" from "the empty path".
func fromBusErrorResponse(code errcode.Code, rawPath string, err error) ErrorResponse {
	return ErrorResponse{
		Proto:   proto,
		Status:  statusError,
		Code:    code.String(),
		Path:    displayBytes(rawPath),
		PathB64: base64.StdEncoding.EncodeToString([]byte(rawPath)),
		Message: err.Error(),
	}
}

// displayPath renders an authorised path for a human-readable member. It is lossy; see
// fromBusFileRecordResponse.
func displayPath(p devicepath.AuthorizedPath) string {
	return displayBytes(p.String())
}

// displayBytes coerces raw path bytes to valid UTF-8 for a human-readable member, replacing
// each run of invalid bytes with the U+FFFD replacement character.
//
// It is used for the path member of an error object as well as for a record's, because the
// path a caller was refused may itself contain bytes that are not valid UTF-8 — a rejected
// path is reported back, and a report that cannot be encoded is not a report.
func displayBytes(raw string) string {
	return strings.ToValidUTF8(raw, "�")
}

// requestCode classifies a converter failure for the wire.
//
// A validation failure that carries a classification keeps it — devicepath's rejections
// carry path_denied through the errcode.Coder contract, so a denied root is reported as
// path_denied without this package deciding anything. A validation failure that carries no
// classification is an unknown flag or an unacceptable value, which the taxonomy calls
// unsupported.
//
// errcode.From returns internal for an unclassified error, and internal is the right answer
// for a failure that is NOT a caller's input problem — so the override below is confined to
// errs.FieldErrors, which is by construction exactly the set of caller input problems.
func requestCode(err error) errcode.Code {
	code := errcode.From(err)

	if _, ok := errs.IsFieldErrors(err); ok && code == errcode.CodeInternal {
		code = errcode.CodeUnsupported
	}

	return code
}
