package broker

import (
	"bufio"
	"cmp"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"slices"
	"strconv"
	"strings"

	"github.com/jroedel/adb-broker/business/types/errcode"
	"github.com/jroedel/adb-broker/foundation/audit"
	"github.com/jroedel/adb-broker/foundation/journal"
)

// The journald-stamped field names verify matches an anchor on, and the three the broker
// itself publishes. The first three are added by journald from the sending socket's
// credentials and cannot be set by a client; the last three are the anchor's payload.
const (
	messageIDField = "MESSAGE_ID"
	uidField       = "_UID"
	exeField       = "_EXE"

	anchorSeqField  = "ADB_BROKER_SEQ"
	anchorHashField = "ADB_BROKER_HASH"
	anchorLogField  = "ADB_BROKER_LOG"
)

// hashHexLen is the length of a chain hash in the hex form both the log and an anchor carry.
const hashHexLen = 64

// emptyChainHead is the chain head of a log with no records: 32 zero bytes, hex-encoded. It
// is what an anchor published against a fresh install carries, and audit.Summary reports the
// same state as an empty LastHash — so the two have to be reconciled before they are
// compared, or a fresh install would look like a divergence.
var emptyChainHead = strings.Repeat("0", hashHexLen)

// runVerify reads the audit log and the published anchors and reports the first divergence.
//
// It takes no device and no network. It is the only check that can detect a TRUNCATED audit
// log: the hash chain makes editing, reordering and removing records from the middle
// detectable by recomputation, but an adversary who can write the file can recompute a
// shorter chain that verifies perfectly. Only the anchor — published to a log the broker's
// uid cannot rewrite — says which sequence number the file once held.
//
// Both anchor sources work unprivileged, and that is new. Under the withdrawn setuid install
// this process ran at a service account's euid that was deliberately outside systemd-journal,
// so the --anchors <file|glob> form could not read what it was pointed at and a pipe from a
// root journalctl was the only path that worked. Running as the invoking user removes the
// obstacle: systemd grants a user read access to its own journal file by ACL, and this user's
// own anchors are exactly the ones the trust filter accepts. Measured 2026-08-01 on this host,
// as uid 1003 with no adm and no systemd-journal membership.
//
// It MUST be run as the account whose backups it is verifying, and running it as root is the
// mistake to expect. anchorFilter selects on the uid this process is running as, so a root run
// looks for _UID=0, matches none of the anchors the broker ever published, and reports a
// confident pass over nothing.
func runVerify(e env, args []string) int {
	var req VerifyRequest

	fs := newFlagSet("verify", e.stderr)
	fs.StringVar(&req.LogPath, "log", "", "the audit log to verify (default: this user's own)")
	fs.StringVar(&req.AnchorsPath, "anchors", "",
		`a journal file or glob to read anchors from, or "-" for newline-delimited JSON on stdin as `+
			`"journalctl -o json MESSAGE_ID=`+audit.MessageID+`" emits it. Both work unprivileged: this `+
			`process runs as the invoking user, whose own anchors are in a journal file that user can read`)

	if exit, ok := e.bindFlags(fs, args); !ok {
		return exit
	}

	// Resolved after parsing rather than as the flag's default, so that an explicit --log
	// still works on a host where this user's own path cannot be determined at all.
	if req.LogPath == "" {
		path, err := auditLogPath()
		if err != nil {
			return e.failCode(errcode.CodeAuditUnavailable, "", err)
		}

		req.LogPath = path
	}

	in, err := toVerifyInput(req)
	if err != nil {
		return e.failCode(requestCode(err), "", err)
	}

	sum, err := verifyChain(in.logPath)
	if err != nil {
		// A *audit.ChainError names the offending record by sequence number and line, which
		// is the answer an operator needs, and it reaches Message unchanged.
		return e.failCode(errcode.CodeAuditUnavailable, in.logPath, err)
	}

	anchors, err := readAnchors(in)
	if err != nil {
		return e.failCode(errcode.CodeAuditUnavailable, in.anchorsPath, err)
	}

	head := sum.LastHash
	if sum.Records == 0 {
		head = emptyChainHead
	}

	res := VerifyResponse{
		Proto:    proto,
		Status:   statusOK,
		Log:      in.logPath,
		Records:  sum.Records,
		LastSeq:  sum.LastSeq,
		LastHash: head,
		Anchors:  len(anchors),
	}

	if len(anchors) == 0 {
		// Reported as partial rather than ok. The chain verified, but the one thing the chain
		// cannot check for itself was not checked, and a verify that says "ok" for a
		// truncation check it never ran is exactly the confident pass an adversary wants.
		fmt.Fprintf(e.stderr, "adb-broker: %s verified %d record(s), but no anchor published by uid %d from %s was found in %s, "+
			"so a truncated tail could not be ruled out\n",
			in.logPath, sum.Records, os.Geteuid(), executablePath(), in.anchorsPath)

		res.Status = statusPartial

		return e.emit(res)
	}

	newest := slices.MaxFunc(anchors, func(a, b audit.Anchor) int { return cmp.Compare(a.Seq, b.Seq) })
	res.AnchorSeq, res.AnchorHash = newest.Seq, newest.Hash

	switch {
	case newest.Seq > sum.LastSeq:
		return e.failCode(errcode.CodeAuditUnavailable, in.logPath, fmt.Errorf(
			"%s holds %d record(s) ending at seq %d, but an anchor published seq %d: the tail has been truncated",
			in.logPath, sum.Records, sum.LastSeq, newest.Seq))

	case newest.Seq == sum.LastSeq && newest.Hash != head:
		return e.failCode(errcode.CodeAuditUnavailable, in.logPath, fmt.Errorf(
			"%s ends at seq %d with chain head %s, but the anchor for that sequence published %s: the record was altered",
			in.logPath, sum.LastSeq, head, newest.Hash))

	case newest.Seq < sum.LastSeq:
		// Not a divergence: the log has grown since the newest anchor this reader could see.
		// The anchor's own record cannot be re-hashed from here, because foundation/audit
		// exposes whole-chain verification and the tail, not the hash of an arbitrary
		// sequence number — so what is reported is that the comparison was partial in that
		// direction, and the numbers to see it.
		fmt.Fprintf(e.stderr, "adb-broker: the newest anchor covers seq %d and %s now ends at seq %d; "+
			"no anchor claims a record the log is missing\n", newest.Seq, in.logPath, sum.LastSeq)
	}

	return e.emit(res)
}

// verifyChain recomputes every hash in the log at path, in order, and reports the first
// divergence.
func verifyChain(path string) (audit.Summary, error) {
	f, err := os.Open(path)
	if err != nil {
		return audit.Summary{}, fmt.Errorf("open the audit log: %w", err)
	}
	defer func() { _ = f.Close() }()

	return audit.VerifyChain(f)
}

// readAnchors returns every anchor that can be trusted to have come from this binary, for the
// log being verified.
func readAnchors(in verifyInput) ([]audit.Anchor, error) {
	filter, err := anchorFilter()
	if err != nil {
		return nil, err
	}

	fieldSets, err := anchorFields(in, filter)
	if err != nil {
		return nil, err
	}

	var anchors []audit.Anchor
	for _, fields := range fieldSets {
		anchor, err := toAnchor(fields)
		if err != nil {
			// An entry that passed the trust filter carries this binary's own uid and path,
			// so a malformed anchor payload in one is not noise to skip past — nothing else
			// publishes under that identity.
			return nil, err
		}

		// An anchor names the log it describes. On a host with more than one install, "some
		// log had this head" answers nothing, so an anchor for another file is not evidence
		// about this one.
		if anchor.LogPath != in.logPath {
			continue
		}

		anchors = append(anchors, anchor)
	}

	return anchors, nil
}

// anchorFields collects the candidate entries' fields from whichever source was named.
func anchorFields(in verifyInput, filter journal.Filter) ([]map[string]string, error) {
	if in.fromStdin {
		return readAnchorLines(stdinReader, filter)
	}

	r, err := journal.Open([]string{in.anchorsPath})
	if err != nil {
		return nil, fmt.Errorf("read anchors from %s: %w", in.anchorsPath, err)
	}
	defer func() { _ = r.Close() }()

	// journal.Entries applies the filter itself, and its Filter type has no way to express
	// "any uid" — which is the point of using it rather than matching MESSAGE_ID here.
	entries, err := r.Entries(filter)
	if err != nil {
		return nil, fmt.Errorf("read anchors from %s: %w", in.anchorsPath, err)
	}

	fieldSets := make([]map[string]string, len(entries))
	for i, entry := range entries {
		fieldSets[i] = entry.Fields
	}

	return fieldSets, nil
}

// anchorFilter builds the only anchor filter this binary will use.
//
// TWO STAMPED FIELDS MAKE AN ANCHOR TRUSTWORTHY, and since 2026-08-01 only one of them
// discriminates on this host. /run/systemd/journal/socket is mode 0666, so any local process
// can publish a well-formed entry carrying the broker's MESSAGE_ID with a fabricated sequence
// number and hash — one such forged anchor is a permanent resident of this host's journal,
// published deliberately during an experiment, and journal entries cannot be removed. An
// adversary who truncates the audit log can publish an anchor matching the shortened chain.
// Filtering on MESSAGE_ID alone would be a check that accepts everything, which is worse than
// no check because it produces a confident pass.
//
// What an adversary cannot forge is _UID and _EXE, both derived by journald from the sending
// socket's credentials rather than from anything the sender says.
//
// The uid is os.Geteuid(), and it stays that way. The kernel fills a unix socket's credentials
// from the sender's EFFECTIVE uid, which under the withdrawn setuid install was the broker's
// service account and is now simply this process's uid — the two coincide, so nothing here had
// to change. Do not "simplify" it to os.Getuid(): they are equal today only because no setuid
// bit is involved, and the reason this one is effective is a property of the socket, not of
// the install. The audit record's caller_uid is the real uid, for the opposite reason.
//
// Exe is the running binary's own path, from /proc/self/exe, which journald recorded the same
// way. A verify run from a copy of the binary elsewhere finds no anchors and says so, rather
// than accepting anchors it cannot attribute to this install.
//
// BE CLEAR ABOUT WHAT THE FILTER IS NOW WORTH, because the measurement is unflattering and
// deleting it would leave the code looking stronger than it is. Counted 2026-08-01, of the
// 3,652 entries in this host's journal carrying this MESSAGE_ID, every single one bears
// _UID=1003 — the test-suite anchors, the fixture binary's, and the deliberate forgery from
// python3.12 — because they were all published by processes running as this user, and this
// user is now who verify runs as. The _UID half discards NOTHING here; _EXE discards all of
// them. Against a process running as any other uid the filter is as strong as it ever was.
// Against one running as this account it is not evidence at all, since that account owns the
// binary whose path _EXE names. See THREAT_MODEL.md §5.5, which accepts that deliberately.
//
// Neither half may be weakened for convenience. _EXE is now the only one doing work, and the
// forged anchor is retained as a test fixture precisely because it is the one entry that still
// exercises it.
func anchorFilter() (journal.Filter, error) {
	exe, err := os.Executable()
	if err != nil {
		return journal.Filter{}, fmt.Errorf("determine this binary's own path, which an anchor must have been published from: %w", err)
	}

	return journal.Filter{
		MessageID: audit.MessageID,
		UID:       os.Geteuid(),
		Exe:       exe,
	}, nil
}

// executablePath renders this binary's path for a human-facing message, or a placeholder when
// it cannot be determined. It is never used for a trust decision — anchorFilter reports that
// failure instead of papering over it.
func executablePath() string {
	exe, err := os.Executable()
	if err != nil {
		return "(unknown)"
	}

	return exe
}

// toAnchor reads one entry's anchor payload.
//
// Both fields are validated rather than trusted: the sequence number must be a plain decimal
// and the hash must be exactly the hex form audit publishes. An entry from this binary's own
// identity carrying something else is corruption, and corruption in the one file that answers
// "what did this binary read" is reported, not rounded off.
func toAnchor(fields map[string]string) (audit.Anchor, error) {
	rawSeq, ok := fields[anchorSeqField]
	if !ok {
		return audit.Anchor{}, fmt.Errorf("an anchor carries no %s", anchorSeqField)
	}

	seq, err := strconv.ParseUint(rawSeq, 10, 64)
	if err != nil {
		return audit.Anchor{}, fmt.Errorf("an anchor's %s is %q, which is not a sequence number: %w", anchorSeqField, rawSeq, err)
	}

	hash := fields[anchorHashField]
	if !isChainHash(hash) {
		return audit.Anchor{}, fmt.Errorf("the anchor for seq %d carries %s=%q, which is not %d hex characters", seq, anchorHashField, hash, hashHexLen)
	}

	return audit.Anchor{Seq: seq, Hash: hash, LogPath: fields[anchorLogField]}, nil
}

// isChainHash reports whether s is exactly hashHexLen lower-case hex characters, which is
// what audit writes and therefore the only form an anchor from this binary can carry.
func isChainHash(s string) bool {
	if len(s) != hashHexLen {
		return false
	}

	for _, c := range s {
		switch {
		case c >= '0' && c <= '9', c >= 'a' && c <= 'f':
		default:
			return false
		}
	}

	return true
}

// readAnchorLines reads newline-delimited JSON entries — journalctl -o json output — and
// returns the fields of the ones that pass the same trust filter journal.Entries applies.
//
// This form exists for a host where this process cannot read the journal files directly:
// /var/log/journal/*/*.journal is root:systemd-journal 0640, and only the per-user file is
// ACL-readable by its own uid. It was the ONLY workable form under the withdrawn setuid
// install, where the effective uid was a service account outside systemd-journal; since
// 2026-08-01 it is the scripted alternative to a form that now works unprivileged, not the
// primary path. The reader can be root or the user itself:
//
//	journalctl -o json MESSAGE_ID=8f3c1d7a5e4b42c9b1d06a2f7c93e5a4 | adb-broker verify --anchors -
//
// It is an alternative INPUT PATH, never a relaxation: the _UID and _EXE rules are applied
// here exactly as they are applied to a journal file, because a source of anchors that skipped
// them would be a way around the one rule that makes an anchor mean anything. Piping in
// entries as root does not make them trustworthy — journald stamped _UID and _EXE at publish
// time and this reader still requires both to be the broker's own.
func readAnchorLines(r io.Reader, filter journal.Filter) ([]map[string]string, error) {
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 0, 64<<10), maxAnchorLineBytes)

	var fieldSets []map[string]string

	for line := 1; sc.Scan(); line++ {
		raw := sc.Bytes()
		if len(strings.TrimSpace(string(raw))) == 0 {
			continue
		}

		fields, err := decodeAnchorLine(raw)
		if err != nil {
			return nil, fmt.Errorf("anchors line %d: %w", line, err)
		}

		if !matchesAnchorFilter(filter, fields) {
			continue
		}

		fieldSets = append(fieldSets, fields)
	}

	if err := sc.Err(); err != nil {
		return nil, fmt.Errorf("read anchors from stdin: %w", err)
	}

	return fieldSets, nil
}

// maxAnchorLineBytes caps one line of piped JSON. journalctl renders a whole entry per line,
// including its MESSAGE, so this is loose; it exists so a malformed stream cannot make this
// process allocate without bound.
const maxAnchorLineBytes = 1 << 20

// decodeAnchorLine extracts the six fields an anchor decision needs from one journalctl JSON
// object, and nothing else.
//
// Only those six are decoded on purpose. Every other member of the entry is irrelevant to
// both the trust filter and the anchor payload, and a member this reader cannot render — a
// binary MESSAGE, say — must not be able to fail a line that carries a perfectly readable
// anchor.
func decodeAnchorLine(line []byte) (map[string]string, error) {
	var raw map[string]json.RawMessage
	if err := json.Unmarshal(line, &raw); err != nil {
		return nil, fmt.Errorf("decode the journal entry: %w", err)
	}

	fields := make(map[string]string, len(anchorJSONFields))

	for _, name := range anchorJSONFields {
		value, ok := raw[name]
		if !ok {
			continue
		}

		text, err := journalFieldText(value)
		if err != nil {
			return nil, fmt.Errorf("field %s: %w", name, err)
		}

		fields[name] = text
	}

	return fields, nil
}

// anchorJSONFields is the complete set of members decodeAnchorLine looks at.
var anchorJSONFields = [...]string{
	messageIDField, uidField, exeField,
	anchorSeqField, anchorHashField, anchorLogField,
}

// journalFieldText renders one journalctl -o json value as text.
//
// journalctl renders a field value three ways: as a JSON string; as an array of byte values
// when the value is not valid UTF-8; and as an array when the entry carried the same field
// more than once. A field carrying two DIFFERENT values is refused rather than resolved,
// because picking a winner is exactly what an adversary shadowing _UID would be choosing for
// us — and journald appends the trusted fields itself and refuses client fields whose names
// begin with '_', so an entry with two _UIDs is not something it produces.
func journalFieldText(raw json.RawMessage) (string, error) {
	trimmed := strings.TrimSpace(string(raw))
	if trimmed == "" || trimmed == "null" {
		return "", nil
	}

	switch trimmed[0] {
	case '"':
		var s string
		if err := json.Unmarshal(raw, &s); err != nil {
			return "", err
		}

		return s, nil

	case '[':
		return journalArrayText(raw)

	default:
		// A number, which journalctl uses for nothing this reader needs but which costs one
		// line to render honestly rather than refuse.
		var n json.Number
		if err := json.Unmarshal(raw, &n); err != nil {
			return "", fmt.Errorf("value %s is neither a string, an array nor a number", trimmed)
		}

		return n.String(), nil
	}
}

// journalArrayText renders the array form of a journalctl field value.
func journalArrayText(raw json.RawMessage) (string, error) {
	var items []json.RawMessage
	if err := json.Unmarshal(raw, &items); err != nil {
		return "", err
	}

	if len(items) == 0 {
		return "", nil
	}

	// An array of numbers is one value journalctl could not render as UTF-8, given byte by
	// byte. It is decoded into ints rather than a []byte because encoding/json reads a []byte
	// from a base64 string, not from an array.
	var byteValues []int
	if err := json.Unmarshal(raw, &byteValues); err == nil {
		out := make([]byte, len(byteValues))
		for i, v := range byteValues {
			if v < 0 || v > 0xff {
				return "", fmt.Errorf("carries the byte value %d, which is not a byte", v)
			}

			out[i] = byte(v)
		}

		return string(out), nil
	}

	// Otherwise it is the same field repeated. Every element must agree.
	first, err := journalFieldText(items[0])
	if err != nil {
		return "", err
	}

	for _, item := range items[1:] {
		next, err := journalFieldText(item)
		if err != nil {
			return "", err
		}

		if next != first {
			return "", fmt.Errorf("carries two values (%q and %q), and choosing between them is not this reader's decision", first, next)
		}
	}

	return first, nil
}

// matchesAnchorFilter applies journal.Filter's three-field test to a piped entry.
//
// It is the same test, spelled out here because the piped path has no journal reader to apply
// it. See anchorFilter for why every one of the three is required and why none of them is
// optional.
func matchesAnchorFilter(filter journal.Filter, fields map[string]string) bool {
	if normalizeMessageID(fields[messageIDField]) != filter.MessageID {
		return false
	}

	uid, err := strconv.Atoi(fields[uidField])
	if err != nil || uid != filter.UID {
		// An absent or unparseable _UID never matches. It is not treated as uid 0, and it is
		// not treated as "unknown, so allow".
		return false
	}

	return fields[exeField] == filter.Exe
}

// normalizeMessageID puts a message id into the form journal.Filter requires: lower-case hex
// with no dashes. sd-id128 accepts the dashed and undashed spellings in either case, so two
// spellings of one 128-bit id have to compare equal.
func normalizeMessageID(value string) string {
	return strings.ToLower(strings.ReplaceAll(value, "-", ""))
}
