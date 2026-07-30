// Package audit is the broker's hash-chained, append-only audit log and the
// journald anchor writer that backs it.
//
// Every operation the broker performs is recorded somewhere the caller cannot
// reach, in a form where both alteration and deletion are detectable. The two
// halves divide the work:
//
//   - The hash chain (this file, plus record.go) makes editing a record,
//     reordering records and removing records from the middle detectable, by
//     binding each record to every record before it. It does NOT detect
//     truncation of the tail or deletion of the whole file: an adversary who
//     can write the file can recompute a shorter, internally valid chain.
//   - The journald anchor (anchor.go) is the control for that. Publishing
//     (seq, hash) to the journal — a log the broker's uid cannot rewrite —
//     means a later verifier can notice that the file no longer contains the
//     sequence number the journal says it once did.
//
// Nothing in this package claims a property it does not have. See
// TestVerifyChainCannotDetectTailTruncation, which exists specifically to
// document the gap.
package audit

import (
	"bufio"
	"bytes"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"sync"
	"syscall"
	"time"
)

// ErrAuditUnavailable reports that the audit trail cannot be maintained: the
// log cannot be opened or appended to, its tail does not verify, or the journal
// socket cannot be reached. Callers are expected to fail closed on it — an
// operation that cannot be recorded must not happen.
var ErrAuditUnavailable = errors.New("audit log unavailable")

// maxLineBytes caps the size of a single on-disk record line, for both tail
// scanning and verification. Records are a few hundred bytes; this is loose
// enough never to matter in practice and tight enough that a corrupt file
// cannot make a verifier allocate without bound.
const maxLineBytes = 1 << 20

// Log is an open handle on the audit log file, tracking the sequence number and
// chain head of the last record written. It is safe for concurrent use.
type Log struct {
	mu   sync.Mutex
	f    *os.File
	path string
	seq  uint64
	head [32]byte
}

// Open opens an existing audit log for appending and validates its tail.
//
// The file is opened O_WRONLY|O_APPEND and deliberately NOT O_CREATE. The
// installer creates /var/log/adb-broker/audit.log owned by a different uid with
// the append-only attribute (chattr +a) set; a process that can create its own
// audit log can also delete the real one and start a fresh chain, so the
// broker is given no way to bring a log into existence. A missing file is a
// deployment fault, not a condition to paper over.
//
// Open then confirms the descriptor is genuinely a writable, append-mode
// regular file, reads the last record and RECOMPUTES its hash, so an edited or
// corrupted tail is caught before the process does anything else. Any failure —
// cannot open, not appendable, tail does not verify — returns an error wrapping
// ErrAuditUnavailable.
//
// Only the tail is checked, not the whole chain: Open establishes that the
// record it is about to build on is intact, which is what the next append
// depends on. Whole-file verification is VerifyChain's job, run by the verify
// subcommand, where the result can be reported to an operator rather than
// deciding whether the broker starts.
//
// Open does NOT consult the systemd journal. An earlier design had it compare
// the tail against the newest anchor, which would require the broker's uid to
// be a member of systemd-journal: read access to every service's logs on the
// host, bought for a read-only check on a hot path. That trade was declined.
// Anchor comparison lives in the separate verify subcommand instead. The
// consequence is stated plainly: Open detects an EDITED tail but NOT a
// TRUNCATED one, because a truncated file's remaining tail is perfectly valid
// on its own. Only the journal anchor closes that gap.
//
// Open also does not require the append-only file attribute to actually be set.
// It cannot be honoured on every filesystem, and a check the tests could not
// satisfy would be turned off rather than fixed. The O_APPEND descriptor flag
// is checked because that one is always available and is what guarantees this
// process cannot seek back over earlier records.
func Open(path string) (*Log, error) {
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_APPEND, 0)
	if err != nil {
		return nil, fmt.Errorf("audit: %w: open %s: %w", ErrAuditUnavailable, path, err)
	}

	if err := confirmAppendable(f); err != nil {
		f.Close()

		return nil, fmt.Errorf("audit: %w: %s: %w", ErrAuditUnavailable, path, err)
	}

	tail, err := TailRecord(path)
	if err != nil {
		f.Close()

		return nil, fmt.Errorf("audit: %w: read tail of %s: %w", ErrAuditUnavailable, path, err)
	}

	l := &Log{f: f, path: path}

	// A zero tail means an empty file, which is the state a fresh install is
	// in: a valid chain of length zero, head of 32 zero bytes, next seq 1.
	if tail.Seq == 0 && tail.Hash == "" {
		return l, nil
	}

	prev, err := decodeHash(tail.Prev)
	if err != nil {
		f.Close()

		return nil, fmt.Errorf("audit: %w: tail of %s: prev: %w", ErrAuditUnavailable, path, err)
	}

	head, err := verifyRecord(prev, tail)
	if err != nil {
		f.Close()

		return nil, fmt.Errorf("audit: %w: tail of %s: %w", ErrAuditUnavailable, path, err)
	}

	l.seq, l.head = tail.Seq, head

	return l, nil
}

// confirmAppendable reports whether f is a regular file whose descriptor the
// kernel really opened for writing in append mode. Asking fcntl rather than
// trusting the flags handed to open keeps the check honest about what the
// kernel granted.
func confirmAppendable(f *os.File) error {
	fi, err := f.Stat()
	if err != nil {
		return fmt.Errorf("stat: %w", err)
	}

	if !fi.Mode().IsRegular() {
		return fmt.Errorf("not a regular file (mode %s)", fi.Mode())
	}

	flags, err := descriptorFlags(f)
	if err != nil {
		return err
	}

	if flags&syscall.O_APPEND == 0 {
		return errors.New("descriptor is not in append mode")
	}

	switch flags & syscall.O_ACCMODE {
	case syscall.O_WRONLY, syscall.O_RDWR:
		return nil
	default:
		return errors.New("descriptor is not open for writing")
	}
}

// descriptorFlags returns f's open flags via fcntl(F_GETFL).
func descriptorFlags(f *os.File) (int, error) {
	sc, err := f.SyscallConn()
	if err != nil {
		return 0, fmt.Errorf("syscall conn: %w", err)
	}

	var (
		flags   int
		callErr error
	)

	err = sc.Control(func(fd uintptr) {
		r, _, errno := syscall.Syscall(syscall.SYS_FCNTL, fd, uintptr(syscall.F_GETFL), 0)
		if errno != 0 {
			callErr = errno

			return
		}
		flags = int(r)
	})
	if err != nil {
		return 0, fmt.Errorf("fcntl control: %w", err)
	}

	if callErr != nil {
		return 0, fmt.Errorf("fcntl(F_GETFL): %w", callErr)
	}

	return flags, nil
}

// Append assigns r's Seq, Prev and Hash from the live chain state, writes it,
// and returns the record as stored.
//
// Whatever the caller put in Seq, Prev and Hash is ignored and overwritten: the
// chain is a property of the log, not something a caller may assert. TS is
// normalised to UTC milliseconds so the returned record matches the bytes on
// disk exactly. Nothing else is validated — refusing to record an operation
// because a field looked wrong would turn an audit log into a filter.
//
// Each record is written with a single Write of one complete line, and os.File
// is unbuffered, so nothing is held back across calls: a crash part-way through
// a twenty-thousand record run leaves a valid shorter chain rather than a
// corrupt one.
func (l *Log) Append(r Record) (Record, error) {
	l.mu.Lock()
	defer l.mu.Unlock()

	if l.f == nil {
		return Record{}, fmt.Errorf("audit: %w: log is closed", ErrAuditUnavailable)
	}

	r.TS = r.TS.UTC().Truncate(time.Millisecond)
	r.Seq = l.seq + 1
	r.Prev = hex.EncodeToString(l.head[:])
	r.Hash = ""

	sum, err := HashRecord(l.head, r)
	if err != nil {
		return Record{}, fmt.Errorf("audit: hash record %d: %w", r.Seq, err)
	}
	r.Hash = hex.EncodeToString(sum[:])

	line, err := encodeLine(r)
	if err != nil {
		return Record{}, fmt.Errorf("audit: encode record %d: %w", r.Seq, err)
	}

	if _, err := l.f.Write(line); err != nil {
		return Record{}, fmt.Errorf("audit: %w: write record %d: %w", ErrAuditUnavailable, r.Seq, err)
	}

	l.seq, l.head = r.Seq, sum

	return r, nil
}

// Close releases the underlying file. It is safe to call more than once.
func (l *Log) Close() error {
	l.mu.Lock()
	defer l.mu.Unlock()

	if l.f == nil {
		return nil
	}

	f := l.f
	l.f = nil

	return f.Close()
}

// Seq returns the highest sequence number written, or 0 for an empty log.
func (l *Log) Seq() uint64 {
	l.mu.Lock()
	defer l.mu.Unlock()

	return l.seq
}

// Head returns the current chain head: the raw hash of the last record, or 32
// zero bytes for an empty log. This is the value an anchor publishes.
func (l *Log) Head() [32]byte {
	l.mu.Lock()
	defer l.mu.Unlock()

	return l.head
}

// On-disk line format.
//
// One record per line. A line is the canonical form of the record (see
// Canonical) with its own hash appended as the final member, followed by a
// newline:
//
//	{"seq":1,...,"prev":"<64 hex>","hash":"<64 hex>"}\n
//
// Stripping the trailing "\n", the closing "}" and the final ,"hash":"…" member
// therefore yields exactly the bytes that were hashed. Verification does not
// depend on that textual surgery, though: a line is decoded into a Record and
// re-canonicalised, which means the chain covers the record's VALUES, not the
// raw bytes of the line. Cosmetic differences in a hand-edited line are not
// tamper signals; changed values are. To keep the gap between the two as small
// as possible, decoding rejects unknown members, so an adversary cannot smuggle
// extra data into a line that still verifies.

// encodeLine renders r in the on-disk line format documented above.
func encodeLine(r Record) ([]byte, error) {
	c, err := Canonical(r)
	if err != nil {
		return nil, err
	}

	if len(c) == 0 || c[len(c)-1] != '}' {
		return nil, errors.New("canonical form is not a JSON object")
	}

	line := c[:len(c)-1]
	line = append(line, `,"hash":`...)
	line = appendJSONString(line, r.Hash)

	return append(line, '}', '\n'), nil
}

// diskRecord mirrors the on-disk member names for DECODING only. The canonical
// encoder never consults these tags — it writes literal keys — so this struct
// cannot influence any hash. It exists so a stored line can be read back.
type diskRecord struct {
	Seq            uint64 `json:"seq"`
	TS             string `json:"ts"`
	Op             string `json:"op"`
	CallerUID      int    `json:"caller_uid"`
	ClientAsserted string `json:"client_asserted"`
	Serial         string `json:"serial"`
	PathB64        string `json:"path_b64"`
	Decision       string `json:"decision"`
	Result         string `json:"result"`
	Bytes          int64  `json:"bytes"`
	SHA256         string `json:"sha256"`
	Volume         struct {
		Dev int64 `json:"dev"`
		Ino int64 `json:"ino"`
	} `json:"volume"`
	Prev string `json:"prev"`
	Hash string `json:"hash"`
}

// decodeLine parses one on-disk line into a Record. Unknown members are an
// error: a member this package does not know about is not covered by the hash,
// so accepting one would leave a place to hide data inside a valid chain.
func decodeLine(line []byte) (Record, error) {
	dec := json.NewDecoder(bytes.NewReader(line))
	dec.DisallowUnknownFields()

	var dr diskRecord
	if err := dec.Decode(&dr); err != nil {
		return Record{}, fmt.Errorf("decode record: %w", err)
	}

	// Anything after the object is not covered by the hash either.
	if err := dec.Decode(new(json.RawMessage)); !errors.Is(err, io.EOF) {
		return Record{}, errors.New("decode record: trailing data after record")
	}

	ts, err := time.Parse(tsLayout, dr.TS)
	if err != nil {
		return Record{}, fmt.Errorf("decode record: ts: %w", err)
	}

	return Record{
		Seq:            dr.Seq,
		TS:             ts,
		Op:             dr.Op,
		CallerUID:      dr.CallerUID,
		ClientAsserted: dr.ClientAsserted,
		Serial:         dr.Serial,
		PathB64:        dr.PathB64,
		Decision:       dr.Decision,
		Result:         dr.Result,
		Bytes:          dr.Bytes,
		SHA256:         dr.SHA256,
		Volume:         VolumeRef{Dev: dr.Volume.Dev, Ino: dr.Volume.Ino},
		Prev:           dr.Prev,
		Hash:           dr.Hash,
	}, nil
}

// decodeHash parses a 64-character lower-case hex digest into raw bytes.
func decodeHash(s string) ([32]byte, error) {
	var out [32]byte

	b, err := hex.DecodeString(s)
	if err != nil {
		return out, fmt.Errorf("not hex: %w", err)
	}

	if len(b) != len(out) {
		return out, fmt.Errorf("want %d hash bytes, got %d", len(out), len(b))
	}

	return [32]byte(b), nil
}

// verifyRecord checks r against the running chain head prev and returns r's own
// hash. It checks both that r.Prev names prev and that r's stored hash is the
// one its contents produce; the comparison is on exact lower-case hex, which is
// what Append writes.
func verifyRecord(prev [32]byte, r Record) ([32]byte, error) {
	stated, err := decodeHash(r.Prev)
	if err != nil {
		return [32]byte{}, fmt.Errorf("prev: %w", err)
	}

	if stated != prev {
		return [32]byte{}, fmt.Errorf("prev %s does not match the running chain head %s", r.Prev, hex.EncodeToString(prev[:]))
	}

	sum, err := HashRecord(prev, r)
	if err != nil {
		return [32]byte{}, err
	}

	if got := hex.EncodeToString(sum[:]); got != r.Hash {
		return [32]byte{}, fmt.Errorf("hash mismatch: stored %s, recomputed %s", r.Hash, got)
	}

	return sum, nil
}

// TailRecord returns the last record in the log file at path.
//
// An empty file yields a zero Record and a nil error: a fresh install's log is
// empty, and that is a valid chain of length zero, not a fault. A partially
// written final line — the residue of a crash mid-write — is an error, because
// silently ignoring it would let a truncated write pass for a shorter chain.
func TailRecord(path string) (Record, error) {
	f, err := os.Open(path)
	if err != nil {
		return Record{}, err
	}
	defer f.Close()

	fi, err := f.Stat()
	if err != nil {
		return Record{}, fmt.Errorf("stat: %w", err)
	}

	size := fi.Size()
	if size == 0 {
		return Record{}, nil
	}

	// Read a window from the end, growing it until the start of the final line
	// is inside the window or the whole file has been read.
	for window := int64(64 << 10); ; window *= 2 {
		window = min(window, size)

		buf := make([]byte, window)
		if _, err := f.ReadAt(buf, size-window); err != nil {
			return Record{}, fmt.Errorf("read tail: %w", err)
		}

		trimmed := bytes.TrimRight(buf, "\n")
		switch {
		case len(trimmed) == 0 && window == size:
			// The file holds nothing but newlines; treat it as empty.
			return Record{}, nil
		case len(trimmed) == 0:
			// Keep growing.
		default:
			if i := bytes.LastIndexByte(trimmed, '\n'); i >= 0 {
				return decodeLine(trimmed[i+1:])
			}

			if window == size {
				return decodeLine(trimmed)
			}
		}

		if window == size {
			return Record{}, errors.New("read tail: no complete final line")
		}

		if window >= maxLineBytes {
			return Record{}, fmt.Errorf("read tail: final line exceeds %d bytes", maxLineBytes)
		}
	}
}

// Summary describes a chain that verified cleanly.
type Summary struct {
	Records  int
	LastSeq  uint64
	LastHash string
}

// ChainError reports the first divergence VerifyChain found, so a caller can
// name the record at fault without parsing an error string.
type ChainError struct {
	Line int    // 1-based line number in the input
	Seq  uint64 // sequence number of the offending record, 0 if undecodable
	Err  error
}

// Error names the offending record by sequence number, falling back to the line
// number when the record could not be decoded far enough to have one.
func (e *ChainError) Error() string {
	if e.Seq == 0 {
		return fmt.Sprintf("audit: chain diverges at line %d: %v", e.Line, e.Err)
	}

	return fmt.Sprintf("audit: chain diverges at seq %d (line %d): %v", e.Seq, e.Line, e.Err)
}

// Unwrap exposes the underlying cause to errors.Is and errors.AsType.
func (e *ChainError) Unwrap() error { return e.Err }

// VerifyChain reads records in order, recomputes every hash, and reports the
// FIRST divergence as a *ChainError naming the sequence number. Blank lines are
// skipped. On success it returns a Summary of what it verified.
//
// A clean Summary means the records present are internally consistent and in
// order. It does NOT mean the log is complete: records removed from the end
// leave a shorter chain that verifies perfectly. Compare LastSeq against the
// newest journal anchor to learn about that.
func VerifyChain(r io.Reader) (Summary, error) {
	var (
		sum  Summary
		head [32]byte
	)

	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 0, 64<<10), maxLineBytes)

	for line := 1; sc.Scan(); line++ {
		raw := sc.Bytes()
		if len(bytes.TrimSpace(raw)) == 0 {
			continue
		}

		rec, err := decodeLine(raw)
		if err != nil {
			return sum, &ChainError{Line: line, Err: err}
		}

		if want := sum.LastSeq + 1; rec.Seq != want {
			return sum, &ChainError{Line: line, Seq: rec.Seq, Err: fmt.Errorf("out of order: want seq %d", want)}
		}

		next, err := verifyRecord(head, rec)
		if err != nil {
			return sum, &ChainError{Line: line, Seq: rec.Seq, Err: err}
		}

		head = next
		sum.Records++
		sum.LastSeq = rec.Seq
		sum.LastHash = rec.Hash
	}

	if err := sc.Err(); err != nil {
		return sum, fmt.Errorf("audit: read chain: %w", err)
	}

	return sum, nil
}
