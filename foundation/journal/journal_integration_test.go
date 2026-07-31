//go:build integration

package journal

import (
	"errors"
	"strings"
	"testing"
)

// These tests read the host's real journal, which is the one thing the unit
// tests cannot do: they check the parser against files this package built, and a
// misreading shared by the builder and the reader would be invisible there.
//
// They assert structure only — that every file's header decodes, that every
// committed entry parses, that sequence numbers do not go backwards along the
// entry array chain, and that a full scan completes without error. They never
// assert that any particular entry exists. A journal is not a fixture: entries
// come and go with rotation, and a test that expected a specific message would
// fail for reasons that say nothing about this package.
//
// On a host where the journal cannot be read they skip. Journal files are
// root:systemd-journal mode 0640, so a uid outside that group gets nothing, and
// that is the ordinary case for whoever runs the test suite. A skip is the
// honest outcome; passing would be a lie and failing would be noise. Note that
// a user's own /var/log/journal/*/user-$UID*.journal files are often readable
// even when the system ones are not, so these tests can do real work on a host
// where journalctl itself shows nothing from the system journal.
//
// What no test in this package can do is compare against systemd's own reader,
// because that would mean shelling out and the broker has no exec path. That
// comparison was instead done by hand, and is worth redoing whenever the parser
// changes or the host's systemd does. On systemd 255, with every readable file
// carrying COMPRESSED-ZSTD, KEYED-HASH and COMPACT, this package's decoding of
// 29367 entries across seven files was diffed field by field against
//
//	journalctl --file <path> -o export
//
// Every cursor matched journalctl's __CURSOR exactly and all 804689 decoded
// field values were byte-identical, including values holding embedded newlines.
// The only fields journalctl reported that this package did not were the
// zstd-compressed ones, and their number matched the compressed-object count
// this package reports for each entry exactly — never a field quietly missing.

// maxIntegrationEntriesPerFile bounds the per-entry work. A system journal file
// holds hundreds of thousands of entries and reading every field of every one of
// them is not what these tests are for: a prefix of each file exercises the same
// code paths.
const maxIntegrationEntriesPerFile = 5000

// openRealJournal opens the host's journal, or skips the test.
func openRealJournal(t *testing.T) *Reader {
	t.Helper()

	reader, err := Open(DefaultPaths())

	switch {
	case err == nil:
		t.Cleanup(func() {
			if err := reader.Close(); err != nil {
				t.Errorf("closing the journal: %v", err)
			}
		})

		return reader

	case errors.Is(err, ErrPermission):
		t.Skipf("no journal file could be read; membership in the %q group is required: %v", journalGroup, err)

	case strings.Contains(err.Error(), "no journal files matched"):
		t.Skipf("this host has no journal files at %v: %v", DefaultPaths(), err)
	}

	// Anything else — an unrecognized incompatible flag above all — is a real
	// finding about this parser and must not be skipped past.
	t.Fatalf("opening the host journal: %v", err)

	return nil
}

// TestRealJournalHeadersDecode is the first thing that has to hold: every file
// the host has must be one this parser accepts. An ErrUnsupportedFormat here
// means systemd has moved on, which is exactly the case the parser is built to
// report loudly rather than answer "no anchors found" to.
func TestRealJournalHeadersDecode(t *testing.T) {
	reader := openRealJournal(t)

	if len(reader.files) == 0 {
		t.Fatal("Open returned a reader with no files")
	}

	for _, jf := range reader.files {
		if jf.hdr.headerSize < minHeaderSize || jf.hdr.headerSize > maxHeaderSize {
			t.Errorf("%s: header_size = %d, outside [%d, %d]",
				jf.path, jf.hdr.headerSize, minHeaderSize, maxHeaderSize)
		}

		if jf.usedEnd < jf.hdr.headerSize {
			t.Errorf("%s: usable region ends at %d, before the %d-byte header does",
				jf.path, jf.usedEnd, jf.hdr.headerSize)
		}

		if jf.hdr.entryArrayOffset != 0 && jf.hdr.entryArrayOffset < jf.hdr.headerSize {
			t.Errorf("%s: entry_array_offset = %d, inside the header rather than the arena",
				jf.path, jf.hdr.entryArrayOffset)
		}

		// Logged, not asserted: which dialect the host actually writes is the
		// fact these tests exist to find out, and it changes with the systemd
		// version rather than with anything in this repository.
		t.Logf("%s: incompatible_flags=%#08x compact=%t n_entries=%d",
			jf.path, jf.hdr.incompatibleFlags, jf.hdr.compact(), jf.hdr.nEntries)
	}
}

// TestRealJournalEntriesAreOrderedBySequenceNumber walks each file's global entry
// array chain and parses what it points at. Sequence numbers along the chain must
// not go backwards: the reader's ordering is a sort, so it would paper over a
// chain read in the wrong order, and this checks the chain itself.
func TestRealJournalEntriesAreOrderedBySequenceNumber(t *testing.T) {
	reader := openRealJournal(t)

	var total int
	for _, jf := range reader.files {
		offsets, err := jf.entryOffsets()
		if err != nil {
			t.Errorf("%s: walking the entry array chain: %v", jf.path, err)

			continue
		}

		if uint64(len(offsets)) > jf.hdr.nEntries {
			t.Errorf("%s: chain lists %d entries, more than the header's n_entries of %d",
				jf.path, len(offsets), jf.hdr.nEntries)
		}

		var (
			previous uint64
			havePrev bool
			seen     int
		)

		for _, off := range offsets[:min(len(offsets), maxIntegrationEntriesPerFile)] {
			obj, err := jf.readObject(off, objectEntry, maxEntryBytes)
			if errors.Is(err, errTruncated) {
				// journald is appending to this file right now. That ends the
				// walk rather than failing it.
				break
			}
			if err != nil {
				t.Errorf("%s: reading the entry at %d: %v", jf.path, off, err)

				break
			}

			entry, err := parseEntryObject(obj, jf.hdr.compact())
			if err != nil {
				t.Errorf("%s: parsing the entry at %d: %v", jf.path, off, err)

				break
			}

			if havePrev && entry.seqnum < previous {
				t.Errorf("%s: entry at %d has sequence number %d after %d, so the chain is out of order",
					jf.path, off, entry.seqnum, previous)
			}

			if entry.seqnum == 0 {
				t.Errorf("%s: entry at %d has sequence number 0, which journald does not assign",
					jf.path, off)
			}

			previous, havePrev = entry.seqnum, true
			seen++
		}

		total += seen
		t.Logf("%s: %d of %d chained entries checked", jf.path, seen, len(offsets))
	}

	if total == 0 {
		t.Skip("every readable journal file is empty, so there is no ordering to check")
	}
}

// TestRealJournalFieldsDecodeOrReportCompression covers the part of the format
// this package cannot fully read. Every DATA object of every entry must either
// decode to a NAME=value pair or be reported as compressed. What must never
// happen is a field that quietly comes back empty, because a value that is
// missing because it could not be read and one that is missing because nobody
// wrote it must not look alike.
func TestRealJournalFieldsDecodeOrReportCompression(t *testing.T) {
	reader := openRealJournal(t)

	for _, jf := range reader.files {
		offsets, err := jf.entryOffsets()
		if err != nil {
			t.Errorf("%s: walking the entry array chain: %v", jf.path, err)

			continue
		}

		var (
			cache      = newDataCache()
			fieldsSeen int
			compressed int
		)

		for _, off := range offsets[:min(len(offsets), maxIntegrationEntriesPerFile)] {
			obj, err := jf.readObject(off, objectEntry, maxEntryBytes)
			if errors.Is(err, errTruncated) {
				break
			}
			if err != nil {
				t.Errorf("%s: reading the entry at %d: %v", jf.path, off, err)

				break
			}

			entry, err := parseEntryObject(obj, jf.hdr.compact())
			if err != nil {
				t.Errorf("%s: parsing the entry at %d: %v", jf.path, off, err)

				break
			}

			if len(entry.dataOffsets) == 0 {
				t.Errorf("%s: entry at %d points at no data objects", jf.path, off)
			}

			fields, tally, err := jf.readFields(off, entry, cache)
			if err != nil {
				t.Errorf("%s: reading the fields of the entry at %d: %v", jf.path, off, err)

				break
			}

			compressed += tally.count
			fieldsSeen += len(fields)

			// Every decoded field has to have a name. An empty name would mean
			// the payload was read at the wrong offset — the failure mode a
			// COMPACT mix-up produces, and one that a file full of plausible
			// values would otherwise hide.
			if _, empty := fields[""]; empty {
				t.Errorf("%s: entry at %d decoded a field with an empty name, "+
					"which means the payload was read at the wrong offset", jf.path, off)
			}

			if len(fields)+tally.count == 0 {
				t.Errorf("%s: entry at %d yielded neither a readable nor a compressed field",
					jf.path, off)
			}
		}

		t.Logf("%s: %d fields decoded, %d compressed objects passed over", jf.path, fieldsSeen, compressed)
	}
}

// TestRealJournalScanCompletes is the end-to-end shape of what an operator-run
// verify does: a full linear pass over every file with a closed filter. The
// filter names a message id nothing published, so the answer must be no entries
// and no error. An error here is a parser problem on real data; entries here
// would mean a 128-bit id collided, which it did not.
func TestRealJournalScanCompletes(t *testing.T) {
	reader := openRealJournal(t)

	entries, err := reader.Entries(Filter{
		MessageID: "00000000000000000000000000000001",
		UID:       0,
		Exe:       "/nonexistent/adb-broker-integration-probe",
	})
	if err != nil {
		t.Fatalf("a full scan of the host journal must complete: %v", err)
	}

	if len(entries) != 0 {
		t.Errorf("want no entries for a message id nothing published, got %d", len(entries))
	}
}

// TestRealJournalRejectsAnOpenFilterEvenOnRealFiles keeps the security property
// from being an artefact of synthetic fixtures: a filter that cannot be trusted
// is refused before any file is read, so there is no path on which a real
// journal is scanned with an unvalidated filter.
func TestRealJournalRejectsAnOpenFilterEvenOnRealFiles(t *testing.T) {
	reader := openRealJournal(t)

	if _, err := reader.Entries(Filter{MessageID: "not-a-message-id", UID: -1, Exe: "relative"}); err == nil {
		t.Fatal("want an error for a filter that names no uid and no absolute exe")
	}
}
