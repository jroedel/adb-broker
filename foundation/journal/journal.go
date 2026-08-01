// Package journal is a read-only parser for systemd journal files.
//
// It exists so an operator-run verify can read back the audit anchors the broker
// previously published to journald. The broker has no exec path at all, by
// design, so it cannot shell out to journalctl, and the Go standard library has
// no journal reader.
//
// # Read-only by construction
//
// Every file is opened O_RDONLY and is only ever touched through ReadAt. This
// package contains no code path that can modify a journal file: it never opens
// for writing, creates, truncates, renames, or unlinks anything; it never maps a
// file into memory, writably or otherwise; and it never touches the journal
// directory itself. There is no method here that takes a value to store.
//
// # What it deliberately cannot do
//
// Three constraints follow from the standard-library-only rule and from the
// format flags every file on the target host sets — COMPRESSED-ZSTD, KEYED-HASH
// and COMPACT.
//
// It does not look anything up by hash. KEYED-HASH means the hash tables are
// keyed with SipHash-2-4, which is not in the standard library, so this package
// walks the header's global entry array chain and inspects entries directly.
// That is O(every entry in every file) per call. Implementing SipHash to get an
// indexed lookup is a deliberate deferral, affordable because the only consumer
// is an operator-run subcommand rather than anything on a hot path.
//
// It does not decompress. journald compresses payloads over 512 bytes, with
// zstd on a current host. A compressed object that is not needed is passed over
// in silence; a compressed object that would have to be returned produces an
// error wrapping ErrCompressed. It never answers with the compressed field
// quietly missing, because a field that is absent because we could not read it
// and a field that is absent because nobody wrote it must not look alike.
//
// It does not tolerate an unrecognized incompatible flag. Such a file is
// refused with ErrUnsupportedFormat rather than parsed as far as it can be. The
// failure direction matters more than the failure rate here: silently returning
// "no anchors found" for a file this parser can no longer read is
// indistinguishable from an adversary having removed the anchors.
//
// It does support both the COMPACT and the pre-COMPACT item layouts, selected by
// the file's own incompatible flags, because a file rotated by an older systemd
// can sit in the same directory as one written by a current one.
package journal

import (
	"cmp"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"math"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
)

var (
	// ErrUnsupportedFormat reports a file this package refuses to interpret: a
	// bad signature, an implausible header, or — the case this sentinel exists
	// for — an incompatible flag it does not recognize.
	//
	// This is a hard error and never a quiet empty result. A future systemd
	// format change has to break loudly, because "I read every file and found
	// no anchors" is the same answer an attacker who deleted the anchors would
	// like a verifier to produce.
	ErrUnsupportedFormat = errors.New("unsupported journal file format")

	// ErrCompressed reports that a value this package would have had to return
	// lives in a compressed DATA object. journald compresses payloads over 512
	// bytes and zstd, lz4 and xz are all outside the Go standard library, which
	// this module is restricted to. This is a design constraint, not a gap: the
	// answer is to keep anchor fields small, which they are.
	ErrCompressed = errors.New("journal data object is compressed")

	// ErrPermission reports that not one journal file could be opened. Journal
	// files are root:systemd-journal 0640, so a reader needs membership in that
	// group; the wrapped message names it.
	ErrPermission = errors.New("permission denied reading journal files")
)

// errTruncated marks an object that runs past the written region of a file —
// the ordinary appearance of a journal journald is in the middle of appending
// to. It never escapes this package: a truncated trailing object ends a
// traversal rather than failing it.
var errTruncated = errors.New("journal object is truncated")

// journalGroup is the group that owns journal files, named in ErrPermission
// messages so the operator learns the fix and not just the symptom.
const journalGroup = "systemd-journal"

// The journald-stamped field names this package reads. Every one of these is
// set by journald itself from the sending socket's credentials, not by the
// client that sent the message.
const (
	messageIDField = "MESSAGE_ID"
	uidField       = "_UID"
	gidField       = "_GID"
	pidField       = "_PID"
	commField      = "_COMM"
	exeField       = "_EXE"
	loginUIDField  = "_AUDIT_LOGINUID"
)

// messageIDLen is the number of hex characters in a 128-bit message id.
const messageIDLen = 32

// Limits on what a single object may declare. A journal object far outside
// these is corrupt, and honouring its declared size would mean allocating
// whatever a malformed file asked for.
const (
	maxEntryBytes      = 1 << 20
	maxEntryArrayBytes = 1 << 24
	maxDataBytes       = 1 << 24
)

// dataCacheBudget bounds how many bytes of decoded DATA payloads are memoised
// per file. Beyond it objects are still read, just not remembered.
const dataCacheBudget = 32 << 20

// Filter selects candidate anchors. It has no optional fields: an entry matches
// only if every field matches, and there is deliberately no way to express "any
// UID".
//
// That closure is the point of the type. The journal socket
// (/run/systemd/journal/socket) is mode 0666, so any local process can publish a
// well-formed entry carrying our MESSAGE_ID with a fabricated sequence number
// and hash. One such forged anchor was published deliberately during an
// experiment and is now a permanent resident of this host's journal, because
// journal entries cannot be removed. An adversary who truncates the audit log
// can likewise publish an anchor matching the shortened chain.
//
// What such an adversary cannot forge is _UID, which journald derives from the
// sending socket's credentials and which the sender has no way to influence. So
// filtering on MessageID alone would be a check that accepts everything,
// including the adversary's anchor — the worst kind of check, because it never
// looks broken and produces a confident pass. Making UID optional would make
// "forgot to filter by UID" expressible, so it is not expressible.
//
// Entries validates that MessageID is 32 lowercase hex characters, that UID is
// non-negative, and that Exe is a non-empty absolute path, and refuses the call
// otherwise rather than treating a malformed filter as a permissive one.
type Filter struct {
	// MessageID is the 128-bit message id as 32 lowercase hex characters, with
	// no dashes.
	MessageID string

	// UID is the uid journald recorded for the sending process. This is the one
	// field the anchor's trustworthiness rests on.
	UID int

	// Exe is the absolute path of the executable journald recorded.
	Exe string
}

// validate reports every problem with a filter at once, so a caller with two
// bad fields learns about both.
func (f Filter) validate() error {
	var problems []error

	// Each problem names its field first, after a lowercase lead-in so that the
	// fragment reads correctly once joined behind "invalid filter:".
	if !isMessageID(f.MessageID) {
		problems = append(problems, fmt.Errorf("field MessageID %q: want exactly %d lowercase hex characters with no dashes",
			f.MessageID, messageIDLen))
	}

	if f.UID < 0 {
		problems = append(problems, fmt.Errorf("field UID %d: want a non-negative uid; a negative uid is not a wildcard, "+
			"and this filter has no way to mean \"any uid\"", f.UID))
	}

	if !filepath.IsAbs(f.Exe) {
		problems = append(problems, fmt.Errorf("field Exe %q: want a non-empty absolute path", f.Exe))
	}

	if len(problems) > 0 {
		return fmt.Errorf("journal: invalid filter: %w", errors.Join(problems...))
	}

	return nil
}

// Entry is one journal entry that matched a Filter.
type Entry struct {
	// Fields holds every field of the entry that could be decoded, keyed by
	// name, with the leading "NAME=" stripped. Compressed values are absent:
	// see ErrCompressed for why that is safe for the fields a Filter matches on
	// and why it is reported when it is not.
	//
	// A field name journald recorded more than once keeps its first value.
	Fields map[string]string

	// UID, GID and PID are the journald-stamped credentials of the sender.
	// GID and PID are -1 when the entry did not carry them; UID always equals
	// the Filter's UID, since nothing else could have matched.
	UID, GID, PID int

	// Comm and Exe are the journald-stamped command name and executable path.
	// Comm is empty when the entry did not carry it.
	Comm, Exe string

	// LoginUID is journald's _AUDIT_LOGINUID, or -1 when absent. It is the more
	// interesting of the two non-load-bearing credentials for forensics, since
	// it survives a setuid exec and names the login session behind it.
	LoginUID int

	// RealtimeUsec is the entry's wall-clock timestamp in microseconds since
	// the Unix epoch, as journald stamped it.
	RealtimeUsec int64

	// Cursor is the entry's cursor in sd_journal_get_cursor's format, so it can
	// be handed to journalctl --cursor to look the same entry up by hand.
	Cursor string
}

// journalFile is one open file and the part of its header this package needs.
type journalFile struct {
	path string
	file *os.File
	hdr  fileHeader

	// usedEnd is one past the last byte that may hold an object. journald
	// pre-allocates files, so the arena runs past what has actually been
	// written; this is clamped to the file so a read into the unwritten tail
	// reports truncation instead of decoding zeroes as an object.
	usedEnd uint64
}

// Reader reads entries from a set of journal files. It is not safe for
// concurrent use.
type Reader struct {
	files  []*journalFile
	closed bool
}

// DefaultPaths returns the glob patterns for the system journal, persistent
// directory first and volatile second. The order matters to a caller that reads
// them in sequence: /run/log/journal holds journals only while /var/log/journal
// does not exist, so on a host with persistent journals the first pattern names
// the real files.
func DefaultPaths() []string {
	return []string{
		"/var/log/journal/*/*.journal",
		"/run/log/journal/*/*.journal",
	}
}

// Open opens every journal file named by paths for reading. An element of paths
// containing glob metacharacters is expanded, which is what makes the patterns
// from DefaultPaths usable directly; an element without them is taken as a
// literal path so that naming one file reports that file's own error.
//
// Files are opened O_RDONLY and never in any other mode.
//
// A file that cannot be read for want of permission is skipped as long as some
// other file could be read, because a caller with access to part of the journal
// should get that part. If nothing at all could be read, the returned error
// wraps ErrPermission and names the group that would grant access. A file whose
// format is not understood is never skipped: it fails the whole call with
// ErrUnsupportedFormat.
func Open(paths []string) (*Reader, error) {
	if len(paths) == 0 {
		return nil, errors.New("journal: no paths given")
	}

	var (
		files    []*journalFile
		denied   []string
		otherErr error
	)

	for _, pattern := range paths {
		matches, err := expand(pattern)
		if err != nil {
			closeFiles(files)

			return nil, fmt.Errorf("journal: bad path pattern %q: %w", pattern, err)
		}

		for _, path := range matches {
			jf, err := openFile(path)

			switch {
			case err == nil:
				files = append(files, jf)

			case errors.Is(err, ErrUnsupportedFormat):
				closeFiles(files)

				return nil, err

			case errors.Is(err, fs.ErrPermission):
				denied = append(denied, path)

			default:
				otherErr = cmp.Or(otherErr, err)
			}
		}
	}

	if len(files) > 0 {
		return &Reader{files: files}, nil
	}

	switch {
	case len(denied) > 0:
		return nil, fmt.Errorf("journal: none of the %d matched journal file(s) could be read, starting with %s: "+
			"journal files are root:%s mode 0640, so membership in the %q group is required: %w",
			len(denied), denied[0], journalGroup, journalGroup, ErrPermission)

	case otherErr != nil:
		return nil, fmt.Errorf("journal: no readable journal files: %w", otherErr)

	default:
		return nil, fmt.Errorf("journal: no journal files matched %v", paths)
	}
}

// Close releases every open file. It is safe to call more than once.
func (r *Reader) Close() error {
	err := closeFiles(r.files)
	r.files = nil
	r.closed = true

	return err
}

// Entries returns every entry matching f, ascending by sequence number.
//
// The scan walks each file's global entry array chain and inspects entries
// directly, rather than looking the message id up in the file's DATA hash table.
// That is because KEYED-HASH is set on every file this targets: the tables are
// keyed with SipHash-2-4, which the Go standard library does not provide.
// Implementing SipHash for an indexed lookup is a deliberate deferral — the
// cost of not having it is a linear pass over every entry in every file, which
// an operator-run verify can afford.
//
// Sequence numbers are only comparable within one seqnum_id, which in practice
// is shared by every file of a machine's journal. Entries with equal sequence
// numbers are ordered by realtime timestamp and then by position, so the result
// is deterministic either way.
func (r *Reader) Entries(f Filter) ([]Entry, error) {
	if r.closed {
		return nil, errors.New("journal: reader is closed")
	}

	if err := f.validate(); err != nil {
		return nil, err
	}

	var found []match
	for i, jf := range r.files {
		matches, err := jf.match(f, i)
		if err != nil {
			return nil, fmt.Errorf("journal: %s: %w", jf.path, err)
		}

		found = append(found, matches...)
	}

	slices.SortFunc(found, func(a, b match) int {
		return cmp.Or(
			cmp.Compare(a.seqnum, b.seqnum),
			cmp.Compare(a.realtime, b.realtime),
			cmp.Compare(a.fileIndex, b.fileIndex),
			cmp.Compare(a.offset, b.offset),
		)
	})

	entries := make([]Entry, len(found))
	for i, m := range found {
		entries[i] = m.entry
	}

	return entries, nil
}

// match is an Entry plus the ordering keys that are not part of the exported
// shape.
type match struct {
	seqnum    uint64
	realtime  uint64
	fileIndex int
	offset    uint64
	entry     Entry
}

// expand resolves one element of Open's paths. A pattern is globbed and may
// legitimately match nothing; a literal path is passed through untouched, so a
// caller naming a specific file gets that file's own open error rather than a
// silent empty match.
func expand(pattern string) ([]string, error) {
	if !strings.ContainsAny(pattern, `*?[`) {
		return []string{pattern}, nil
	}

	matches, err := filepath.Glob(pattern)
	if err != nil {
		return nil, err
	}

	slices.Sort(matches)

	return matches, nil
}

// openFile opens one journal file read-only and decodes its header.
func openFile(path string) (*journalFile, error) {
	// O_RDONLY, and no other mode, ever. See the package doc comment.
	file, err := os.OpenFile(path, os.O_RDONLY, 0)
	if err != nil {
		return nil, err
	}

	hdr, size, err := readHeader(file)
	if err != nil {
		file.Close()

		return nil, fmt.Errorf("%s: %w", path, err)
	}

	return &journalFile{
		path:    path,
		file:    file,
		hdr:     hdr,
		usedEnd: min(hdr.headerSize+hdr.arenaSize, uint64(size)),
	}, nil
}

// readHeader reads and validates a file's header, returning it with the file's
// current size.
func readHeader(file *os.File) (fileHeader, int64, error) {
	info, err := file.Stat()
	if err != nil {
		return fileHeader{}, 0, err
	}

	size := info.Size()
	if size < 0 {
		return fileHeader{}, 0, fmt.Errorf("%w: file reports a negative size", ErrUnsupportedFormat)
	}

	buf := make([]byte, min(int64(maxHeaderSize), size))
	if len(buf) > 0 {
		if _, err := file.ReadAt(buf, 0); err != nil {
			return fileHeader{}, size, err
		}
	}

	hdr, err := parseFileHeader(buf)

	return hdr, size, err
}

// closeFiles closes every file, reporting all failures rather than the first.
func closeFiles(files []*journalFile) error {
	var errs []error
	for _, jf := range files {
		if jf.file == nil {
			continue
		}

		if err := jf.file.Close(); err != nil {
			errs = append(errs, err)
		}

		jf.file = nil
	}

	return errors.Join(errs...)
}

// match returns every entry in this file that satisfies f.
func (jf *journalFile) match(f Filter, fileIndex int) ([]match, error) {
	offsets, err := jf.entryOffsets()
	if err != nil {
		return nil, err
	}

	cache := newDataCache()

	var found []match
	for _, off := range offsets {
		m, err := jf.matchEntry(off, f, fileIndex, cache)
		if err != nil {
			return nil, err
		}

		if m != nil {
			found = append(found, *m)
		}
	}

	return found, nil
}

// entryOffsets walks the header's global entry array chain and returns the
// offset of every committed entry, in the order the chain lists them.
//
// The header's entry count bounds the walk, so a file journald is appending to
// right now yields its committed entries and not a half-linked tail.
func (jf *journalFile) entryOffsets() ([]uint64, error) {
	limit := jf.hdr.nEntries
	if limit == 0 {
		return nil, nil
	}

	var (
		offsets []uint64
		visited = make(map[uint64]bool)
	)

	for arrayOff := jf.hdr.entryArrayOffset; arrayOff != 0; {
		// A chain that revisits an array would otherwise spin forever. This is
		// corruption, not a live-file artefact, so it is reported.
		if visited[arrayOff] {
			return nil, fmt.Errorf("entry array chain revisits offset %d", arrayOff)
		}
		visited[arrayOff] = true

		obj, err := jf.readObject(arrayOff, objectEntryArray, maxEntryArrayBytes)
		if errors.Is(err, errTruncated) {
			// journald is mid-append: stop at the last whole object rather
			// than failing a scan of an otherwise readable file.
			return offsets, nil
		}
		if err != nil {
			return nil, err
		}

		array, err := parseEntryArray(obj, jf.hdr.compact())
		if err != nil {
			return nil, fmt.Errorf("entry array at %d: %w", arrayOff, err)
		}

		for _, off := range array.items {
			// These arrays are allocated with room to grow and filled in
			// order, so the first zero slot is the end of the written data and
			// not a hole. Offset 0 holds the file signature and can never name
			// an object, so this reading is safe even if a future systemd
			// stopped over-allocating.
			if off == 0 {
				return offsets, nil
			}

			offsets = append(offsets, off)

			if uint64(len(offsets)) >= limit {
				return offsets, nil
			}
		}

		arrayOff = array.next
	}

	return offsets, nil
}

// matchEntry reads the entry at off and returns it if it satisfies f, or nil if
// it does not.
func (jf *journalFile) matchEntry(off uint64, f Filter, fileIndex int, cache *dataCache) (*match, error) {
	obj, err := jf.readObject(off, objectEntry, maxEntryBytes)
	if errors.Is(err, errTruncated) {
		// An entry linked into an array but not yet fully written is at the
		// tail by construction. Passing over it loses nothing that was
		// committed.
		return nil, nil
	}
	if err != nil {
		return nil, err
	}

	entry, err := parseEntryObject(obj, jf.hdr.compact())
	if err != nil {
		return nil, fmt.Errorf("entry at %d: %w", off, err)
	}

	fields, compressed, err := jf.readFields(off, entry, cache)
	if err != nil {
		return nil, err
	}

	// MESSAGE_ID decides whether this entry is a candidate at all.
	//
	// A compressed DATA object can never be the MESSAGE_ID being looked for, so
	// passing over an entry whose readable fields lack a matching one cannot
	// pass over a real anchor: journald compresses only payloads over 512
	// bytes, and "MESSAGE_ID=" plus the 32 hex characters Filter requires is 43.
	if normalizeMessageID(fields[messageIDField]) != f.MessageID {
		return nil, nil
	}

	// _UID is the field the anchor's whole weight rests on. The same size
	// argument applies: "_UID=" plus a decimal uid cannot reach 512 bytes, so a
	// compressed object can never be a matching _UID either.
	if intField(fields, uidField) != f.UID {
		return nil, nil
	}

	// _EXE is the one filter field whose value has no small bound — a path can
	// approach PATH_MAX and would then be compressed. So if it is unreadable
	// and this entry carried any compressed object, we cannot rule out that the
	// compressed object was a matching _EXE, and we refuse rather than quietly
	// dropping a candidate anchor.
	exe, haveExe := fields[exeField]
	switch {
	case !haveExe && compressed.count > 0:
		return nil, fmt.Errorf("entry at %d matches %s=%s and %s=%d but carries no readable %s "+
			"alongside %d %s-compressed data object(s), so a matching %s cannot be ruled out: %w",
			off, messageIDField, f.MessageID, uidField, f.UID, exeField,
			compressed.count, compressed.algorithm, exeField, ErrCompressed)

	case !haveExe, exe != f.Exe:
		return nil, nil
	}

	if entry.realtime > math.MaxInt64 {
		return nil, fmt.Errorf("entry at %d: realtime timestamp %d does not fit in an int64", off, entry.realtime)
	}

	return &match{
		seqnum:    entry.seqnum,
		realtime:  entry.realtime,
		fileIndex: fileIndex,
		offset:    off,
		entry: Entry{
			Fields:       fields,
			UID:          f.UID,
			GID:          intField(fields, gidField),
			PID:          intField(fields, pidField),
			Comm:         fields[commField],
			Exe:          exe,
			LoginUID:     intField(fields, loginUIDField),
			RealtimeUsec: int64(entry.realtime),
			Cursor:       cursor(jf.hdr.seqnumID, entry),
		},
	}, nil
}

// compressedTally counts the DATA objects of one entry that could not be
// decoded, and names the algorithm the first of them used.
type compressedTally struct {
	count     int
	algorithm string
}

// readFields decodes every DATA object an entry points at.
//
// A compressed object is counted rather than decoded, and a payload with no '='
// is passed over: neither can be a field looked up by name, so neither can
// change which entries match. What they cannot do is disappear silently, which
// is why the count comes back to the caller.
func (jf *journalFile) readFields(entryOff uint64, entry entryObject, cache *dataCache) (map[string]string, compressedTally, error) {
	var compressed compressedTally

	fields := make(map[string]string, len(entry.dataOffsets))
	for _, off := range entry.dataOffsets {
		data, err := jf.dataAt(off, cache)
		if err != nil {
			return nil, compressedTally{}, fmt.Errorf("entry at %d: %w", entryOff, err)
		}

		switch {
		case data.compression != "":
			compressed.count++
			compressed.algorithm = cmp.Or(compressed.algorithm, data.compression)

			continue

		case data.malformed:
			continue
		}

		previous, duplicate := fields[data.name]
		if !duplicate {
			fields[data.name] = data.value

			continue
		}

		// journald appends the trusted fields itself and refuses client fields
		// whose names start with '_', so a single entry carrying two different
		// values for one of the fields a match is decided on is not something
		// it produces. Rather than pick a winner — and a winner is exactly what
		// an attacker shadowing _UID would be choosing for us — refuse.
		if previous != data.value && decidesMatch(data.name) {
			return nil, compressedTally{}, fmt.Errorf("entry at %d carries two values for %s (%q and %q)",
				entryOff, data.name, previous, data.value)
		}
	}

	return fields, compressed, nil
}

// decidesMatch reports whether a field name is one a Filter matches on, and so
// one whose value must not be ambiguous.
func decidesMatch(name string) bool {
	switch name {
	case messageIDField, uidField, exeField:
		return true
	default:
		return false
	}
}

// readObject reads one whole object, its header included, checking that it is
// the expected type and lies inside the written region of the file.
func (jf *journalFile) readObject(off uint64, want uint8, maxSize uint64) ([]byte, error) {
	if off < jf.hdr.headerSize || off%objectAlignment != 0 {
		return nil, fmt.Errorf("offset %d is not an aligned offset inside the object arena", off)
	}

	if off > jf.usedEnd || jf.usedEnd-off < objectHeaderSize {
		return nil, errTruncated
	}

	var raw [objectHeaderSize]byte
	if _, err := jf.file.ReadAt(raw[:], int64(off)); err != nil {
		return nil, readError(err)
	}

	header := parseObjectHeader(raw)

	// Pre-allocated but unwritten space reads back as zeroes, which decodes as
	// a type-0 object. That is the end of the written data, not corruption.
	if header.typ == objectUnused {
		return nil, errTruncated
	}

	switch {
	case header.typ != want:
		return nil, fmt.Errorf("object at %d is a %s where a %s was expected",
			off, objectTypeName(header.typ), objectTypeName(want))

	case header.size < objectHeaderSize:
		return nil, fmt.Errorf("%s object at %d declares size %d, below its own %d-byte header",
			objectTypeName(want), off, header.size, objectHeaderSize)

	case header.size > maxSize:
		return nil, fmt.Errorf("%s object at %d declares size %d, above the %d bytes this reader accepts",
			objectTypeName(want), off, header.size, maxSize)

	case jf.usedEnd-off < header.size:
		return nil, errTruncated
	}

	obj := make([]byte, header.size)
	if _, err := jf.file.ReadAt(obj, int64(off)); err != nil {
		return nil, readError(err)
	}

	return obj, nil
}

// dataAt reads and decodes the DATA object at off, memoising the result.
//
// journald stores one DATA object per distinct field=value pair and points every
// entry carrying that pair at the same offset, so a handful of offsets recur
// across a whole file. Without the memo, a scan would re-read the same
// MESSAGE_ID object once per entry.
func (jf *journalFile) dataAt(off uint64, cache *dataCache) (dataObject, error) {
	if data, ok := cache.get(off); ok {
		return data, nil
	}

	// A DATA object reachable from an entry that is itself linked into an entry
	// array was committed before that link was written, so truncation here is
	// corruption rather than a live-file artefact, and is reported as such
	// instead of being passed over — passing over it could drop the very field
	// that decides a match.
	obj, err := jf.readObject(off, objectData, maxDataBytes)
	if err != nil {
		return dataObject{}, fmt.Errorf("data object at %d: %w", off, err)
	}

	data, err := parseDataObject(obj, jf.hdr.compact())
	if err != nil {
		return dataObject{}, fmt.Errorf("data object at %d: %w", off, err)
	}

	cache.put(off, data)

	return data, nil
}

// dataCache memoises decoded DATA objects for one file, under a byte budget so
// that a large file cannot be turned into a large allocation.
type dataCache struct {
	byOffset map[uint64]dataObject
	budget   int
}

func newDataCache() *dataCache {
	return &dataCache{byOffset: make(map[uint64]dataObject), budget: dataCacheBudget}
}

func (c *dataCache) get(off uint64) (dataObject, bool) {
	data, ok := c.byOffset[off]

	return data, ok
}

func (c *dataCache) put(off uint64, data dataObject) {
	// A rough per-entry overhead, so the budget bounds real memory rather than
	// just payload bytes.
	const overhead = 64

	cost := len(data.name) + len(data.value) + overhead
	if cost > c.budget {
		return
	}

	c.budget -= cost
	c.byOffset[off] = data
}

// cursor renders an entry's cursor exactly as sd_journal_get_cursor does, so the
// value can be handed to journalctl --cursor.
func cursor(seqnumID [id128Size]byte, entry entryObject) string {
	return fmt.Sprintf("s=%s;i=%x;b=%s;m=%x;t=%x;x=%x",
		formatID128(seqnumID), entry.seqnum, formatID128(entry.bootID),
		entry.monotonic, entry.realtime, entry.xorHash)
}

// intField returns a field parsed as an int, or -1 when it is absent or does not
// parse. -1 rather than 0 because 0 is root: an absent _UID must never be
// mistaken for uid 0.
func intField(fields map[string]string, name string) int {
	raw, ok := fields[name]
	if !ok {
		return -1
	}

	value, err := strconv.Atoi(raw)
	if err != nil {
		return -1
	}

	return value
}

// normalizeMessageID puts an on-disk MESSAGE_ID value into the form Filter
// requires: lowercase hex with no dashes.
//
// journald stores the message id as the text the client sent, and sd-id128
// accepts both the dashed and the undashed spelling in either case, so two
// spellings of one 128-bit id have to compare equal. A value that is not a
// 128-bit id at all comes back unchanged and simply fails to match a validated
// filter.
func normalizeMessageID(value string) string {
	return strings.ToLower(strings.ReplaceAll(value, "-", ""))
}

// isMessageID reports whether s is exactly 32 lowercase hex characters.
func isMessageID(s string) bool {
	if len(s) != messageIDLen {
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

// readError maps a short read at the end of a file onto errTruncated.
//
// This is not what guards a file journald is still writing. That case never reaches a
// short read at all: jf.usedEnd is a snapshot taken once, at Open, and every read is
// bounds-checked against it before this function ever runs (readObject's two range
// checks) — an append-only file that has grown since Open just has more bytes past
// usedEnd that this reader does not look at yet, and a still-unwritten object inside the
// pre-allocated arena reads back as zeroes, which the type-0 check just above turns into
// errTruncated on its own, with no read error involved.
//
// What this guards instead is narrower: the file shrinking after that snapshot was
// taken — an external truncation of the still-open inode, racing between the bounds
// check and the ReadAt call this wraps. journald itself never does this; rotation
// unlinks or renames a file rather than truncating one still open, and POSIX keeps an
// open fd's bytes intact regardless. Nothing in this codebase truncates it either. The
// branch stays anyway, because this function is parsing a file this process does not
// control, and asserting a narrower failure mode than the platform allows is the kind of
// assumption that costs nothing to avoid.
//
// io.ErrUnexpectedEOF specifically is not reachable today: jf.file is a *os.File, whose
// ReadAt converts a short read at EOF to io.EOF and never returns ErrUnexpectedEOF (that
// value comes from io.ReadFull/ReadAtLeast, which nothing here calls). It is matched
// anyway rather than dropped, on the same reasoning as the paragraph above: a defensive
// check earns its keep by staying honest about what it guards, not by being provably
// exercised.
func readError(err error) error {
	if errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) {
		return errTruncated
	}

	return err
}
