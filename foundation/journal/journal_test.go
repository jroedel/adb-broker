package journal

import (
	"encoding/hex"
	"errors"
	"fmt"
	"maps"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"testing"
)

// The fixtures in this file exist to break a circularity. The real journal files
// on this host cannot be read by the user running these tests, so everything is
// checked against files this test constructs — and if the constructor and the
// reader shared a wrong assumption about the format, every test here would pass
// while the reader misread reality.
//
// Two things break that circularity:
//
//  1. goldenRegular and goldenCompact below are hand-assembled byte literals,
//     laid out from the offsets documented in systemd's journal-def.h rather
//     than produced by any code in this package.
//  2. Both were fed to systemd 255's own journalctl, which read them and
//     printed exactly the fields and the cursor these tests assert. The byte
//     layout therefore has an authority outside this repository.
//
// TestBuilderReproducesGoldenBytes then pins the synthetic-file builder used by
// the rest of the tests to those same journalctl-validated bytes, so the
// builder cannot drift into an assumption the reader happens to share.

const (
	// testMessageID is the broker's anchor message id.
	testMessageID = "8f3c1d7a5e4b42c9b1d06a2f7c93e5a4"
	testExe       = "/usr/local/bin/adb-broker"

	testSeqnum    = 7
	testRealtime  = 1753000000000000
	testMonotonic = 987654321000
	testXorHash   = 0xdeadbeefcafef00d

	// testCursor is journalctl's own __CURSOR output for the golden files. It is
	// copied from the output of
	//
	//	journalctl --file golden.journal -o export
	//
	// so this constant checks cursor() against the reference implementation
	// rather than against itself.
	testCursor = "s=00112233445566778899aabbccddeeff;i=7;" +
		"b=ffeeddccbbaa99887766554433221100;m=e5f4c8f368;t=63a581e4a9000;x=deadbeefcafef00d"
)

var (
	testSeqnumID = [id128Size]byte{
		0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
		0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff,
	}
	testBootID = [id128Size]byte{
		0xff, 0xee, 0xdd, 0xcc, 0xbb, 0xaa, 0x99, 0x88,
		0x77, 0x66, 0x55, 0x44, 0x33, 0x22, 0x11, 0x00,
	}
	testFileID = [id128Size]byte{
		0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
		0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
	}
	testMachineID = [id128Size]byte{
		0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
		0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f,
	}
)

// goldenRegular is a complete journal file in the pre-COMPACT layout: a 272-byte
// header, the two hash table objects systemd's own header verification insists
// on, three DATA objects, one ENTRY object with three 16-byte items, and one
// ENTRY_ARRAY object with one 8-byte item.
//
// Object map, all offsets little-endian and 8-byte aligned:
//
//	  0 Header, header_size=272 arena_size=592 n_entries=1
//	    seqnum_id=0011..eeff entry_array_offset=832 (0x340)
//	272 DATA_HASH_TABLE  type=4 size=80, items at 288 (4 zeroed buckets)
//	352 FIELD_HASH_TABLE type=5 size=80, items at 368 (4 zeroed buckets)
//	432 DATA  type=1 size=107, payload at 496: "MESSAGE_ID=8f3c…e5a4"
//	544 DATA  type=1 size=73,  payload at 608: "_UID=1000"
//	624 DATA  type=1 size=94,  payload at 688: "_EXE=/usr/local/bin/adb-broker"
//	720 ENTRY type=3 size=112, seqnum=7 realtime@736 monotonic@752
//	    boot_id@760 xor_hash@776, items at 784: {432,0} {544,0} {624,0}
//	832 ENTRY_ARRAY type=6 size=32, next=0, items at 856: {720}
var goldenRegular = `
	4c504b53484852480200000000000000 //    0  signature "LPKSHHRH"; compatible=TAIL_ENTRY_BOOT_ID; incompatible=0
	02000000000000000001020304050607 //   16  state=ARCHIVED, reserved[7]; file_id
	08090a0b0c0d0e0f1011121314151617 //   32  file_id (cont); machine_id
	18191a1b1c1d1e1fffeeddccbbaa9988 //   48  machine_id (cont); tail_entry_boot_id
	77665544332211000011223344556677 //   64  tail_entry_boot_id (cont); seqnum_id
	8899aabbccddeeff1001000000000000 //   80  seqnum_id (cont); header_size=272
	50020000000000002001000000000000 //   96  arena_size=592; data_hash_table_offset=288
	40000000000000007001000000000000 //  112  data_hash_table_size=64; field_hash_table_offset=368
	40000000000000004003000000000000 //  128  field_hash_table_size=64; tail_object_offset=832
	07000000000000000100000000000000 //  144  n_objects=7; n_entries=1
	07000000000000000700000000000000 //  160  tail_entry_seqnum=7; head_entry_seqnum=7
	400300000000000000904a1e583a0600 //  176  entry_array_offset=832; head_entry_realtime
	00904a1e583a060068f3c8f4e5000000 //  192  tail_entry_realtime; tail_entry_monotonic
	03000000000000000000000000000000 //  208  n_data=3; n_fields=0
	00000000000000000100000000000000 //  224  n_tags=0; n_entry_arrays=1
	00000000000000000000000000000000 //  240  data_hash_chain_depth; field_hash_chain_depth
	4003000001000000d002000000000000 //  256  tail_entry_array_offset=832, n=1; tail_entry_offset=720
	04000000000000005000000000000000 //  272  DATA_HASH_TABLE type=4, size=80
	00000000000000000000000000000000 //  288  bucket 0
	00000000000000000000000000000000 //  304  bucket 1
	00000000000000000000000000000000 //  320  bucket 2
	00000000000000000000000000000000 //  336  bucket 3
	05000000000000005000000000000000 //  352  FIELD_HASH_TABLE type=5, size=80
	00000000000000000000000000000000 //  368  bucket 0
	00000000000000000000000000000000 //  384  bucket 1
	00000000000000000000000000000000 //  400  bucket 2
	00000000000000000000000000000000 //  416  bucket 3
	01000000000000006b00000000000000 //  432  DATA type=1 flags=0, size=107
	00000000000000000000000000000000 //  448  hash=0; next_hash_offset=0
	0000000000000000d002000000000000 //  464  next_field_offset=0; entry_offset=720
	00000000000000000100000000000000 //  480  entry_array_offset=0; n_entries=1
	4d4553534147455f49443d3866336331 //  496  payload "MESSAGE_ID=8f3c1"
	64376135653462343263396231643036 //  512  "d7a5e4b42c9b1d06"
	61326637633933653561340000000000 //  528  "a2f7c93e5a4" + 5 pad
	01000000000000004900000000000000 //  544  DATA type=1 flags=0, size=73
	00000000000000000000000000000000 //  560  hash=0; next_hash_offset=0
	0000000000000000d002000000000000 //  576  next_field_offset=0; entry_offset=720
	00000000000000000100000000000000 //  592  entry_array_offset=0; n_entries=1
	5f5549443d3130303000000000000000 //  608  payload "_UID=1000" + 7 pad
	01000000000000005e00000000000000 //  624  DATA type=1 flags=0, size=94
	00000000000000000000000000000000 //  640  hash=0; next_hash_offset=0
	0000000000000000d002000000000000 //  656  next_field_offset=0; entry_offset=720
	00000000000000000100000000000000 //  672  entry_array_offset=0; n_entries=1
	5f4558453d2f7573722f6c6f63616c2f //  688  payload "_EXE=/usr/local/"
	62696e2f6164622d62726f6b65720000 //  704  "bin/adb-broker" + 2 pad
	03000000000000007000000000000000 //  720  ENTRY type=3, size=112
	070000000000000000904a1e583a0600 //  736  seqnum=7; realtime=1753000000000000
	68f3c8f4e5000000ffeeddccbbaa9988 //  752  monotonic=987654321000; boot_id
	77665544332211000df0fecaefbeadde //  768  boot_id (cont); xor_hash=deadbeefcafef00d
	b0010000000000000000000000000000 //  784  item 0: object_offset=432, hash=0
	20020000000000000000000000000000 //  800  item 1: object_offset=544, hash=0
	70020000000000000000000000000000 //  816  item 2: object_offset=624, hash=0
	06000000000000002000000000000000 //  832  ENTRY_ARRAY type=6, size=32
	0000000000000000d002000000000000 //  848  next_entry_array_offset=0; item 0 = 720
`

// goldenCompact is the same content in the COMPACT layout, which narrows exactly
// two things: an entry array item from a u64 to a u32 offset, and an entry item
// from {object_offset u64, hash u64} to {object_offset u32}. DATA objects grow by
// the two u32 fields COMPACT inserts ahead of the payload, moving it from offset
// 64 to offset 72.
//
//	  0 Header, incompatible_flags=0x10 (COMPACT), entry_array_offset=824
//	432 DATA  size=115, payload at 504: "MESSAGE_ID=…"
//	552 DATA  size=81,  payload at 624: "_UID=1000"
//	640 DATA  size=102, payload at 712: "_EXE=…"
//	744 ENTRY size=76, items at 808: {432} {552} {640} — 4 bytes each
//	824 ENTRY_ARRAY size=28, items at 848: {744} — 4 bytes
var goldenCompact = `
	4c504b53484852480200000010000000 //    0  signature; compatible=TAIL_ENTRY_BOOT_ID; incompatible=COMPACT
	02000000000000000001020304050607 //   16  state=ARCHIVED, reserved[7]; file_id
	08090a0b0c0d0e0f1011121314151617 //   32  file_id (cont); machine_id
	18191a1b1c1d1e1fffeeddccbbaa9988 //   48  machine_id (cont); tail_entry_boot_id
	77665544332211000011223344556677 //   64  tail_entry_boot_id (cont); seqnum_id
	8899aabbccddeeff1001000000000000 //   80  seqnum_id (cont); header_size=272
	48020000000000002001000000000000 //   96  arena_size=584; data_hash_table_offset=288
	40000000000000007001000000000000 //  112  data_hash_table_size=64; field_hash_table_offset=368
	40000000000000003803000000000000 //  128  field_hash_table_size=64; tail_object_offset=824
	07000000000000000100000000000000 //  144  n_objects=7; n_entries=1
	07000000000000000700000000000000 //  160  tail_entry_seqnum=7; head_entry_seqnum=7
	380300000000000000904a1e583a0600 //  176  entry_array_offset=824; head_entry_realtime
	00904a1e583a060068f3c8f4e5000000 //  192  tail_entry_realtime; tail_entry_monotonic
	03000000000000000000000000000000 //  208  n_data=3; n_fields=0
	00000000000000000100000000000000 //  224  n_tags=0; n_entry_arrays=1
	00000000000000000000000000000000 //  240  data_hash_chain_depth; field_hash_chain_depth
	3803000001000000e802000000000000 //  256  tail_entry_array_offset=824, n=1; tail_entry_offset=744
	04000000000000005000000000000000 //  272  DATA_HASH_TABLE type=4, size=80
	00000000000000000000000000000000 //  288  bucket 0
	00000000000000000000000000000000 //  304  bucket 1
	00000000000000000000000000000000 //  320  bucket 2
	00000000000000000000000000000000 //  336  bucket 3
	05000000000000005000000000000000 //  352  FIELD_HASH_TABLE type=5, size=80
	00000000000000000000000000000000 //  368  bucket 0
	00000000000000000000000000000000 //  384  bucket 1
	00000000000000000000000000000000 //  400  bucket 2
	00000000000000000000000000000000 //  416  bucket 3
	01000000000000007300000000000000 //  432  DATA type=1 flags=0, size=115
	00000000000000000000000000000000 //  448  hash=0; next_hash_offset=0
	0000000000000000e802000000000000 //  464  next_field_offset=0; entry_offset=744
	00000000000000000100000000000000 //  480  entry_array_offset=0; n_entries=1
	00000000000000004d4553534147455f //  496  compact tail_entry_array_offset/n=0; payload "MESSAGE_"
	49443d38663363316437613565346234 //  512  "ID=8f3c1d7a5e4b4"
	32633962316430366132663763393365 //  528  "2c9b1d06a2f7c93e"
	35613400000000000100000000000000 //  544  "5a4" + 5 pad; DATA type=1 flags=0
	51000000000000000000000000000000 //  560  size=81; hash=0
	00000000000000000000000000000000 //  576  next_hash_offset=0; next_field_offset=0
	e8020000000000000000000000000000 //  592  entry_offset=744; entry_array_offset=0
	01000000000000000000000000000000 //  608  n_entries=1; compact tail_entry_array_offset/n=0
	5f5549443d3130303000000000000000 //  624  payload "_UID=1000" + 7 pad
	01000000000000006600000000000000 //  640  DATA type=1 flags=0, size=102
	00000000000000000000000000000000 //  656  hash=0; next_hash_offset=0
	0000000000000000e802000000000000 //  672  next_field_offset=0; entry_offset=744
	00000000000000000100000000000000 //  688  entry_array_offset=0; n_entries=1
	00000000000000005f4558453d2f7573 //  704  compact tail_entry_array_offset/n=0; payload "_EXE=/us"
	722f6c6f63616c2f62696e2f6164622d //  720  "r/local/bin/adb-"
	62726f6b657200000300000000000000 //  736  "broker" + 2 pad; ENTRY type=3
	4c000000000000000700000000000000 //  752  size=76; seqnum=7
	00904a1e583a060068f3c8f4e5000000 //  768  realtime; monotonic
	ffeeddccbbaa99887766554433221100 //  784  boot_id
	0df0fecaefbeaddeb001000028020000 //  800  xor_hash; items: 432, 552 (u32 each)
	80020000000000000600000000000000 //  816  item 640 (u32) + 4 pad; ENTRY_ARRAY type=6
	1c000000000000000000000000000000 //  832  size=28; next_entry_array_offset=0
	e802000000000000                 //  848  item 0 = 744 (u32) + 4 pad
`

// hexBytes decodes an annotated hex dump: everything from "//" to end of line is
// a comment and all whitespace is insignificant.
func hexBytes(t *testing.T, dump string) []byte {
	t.Helper()

	var sb strings.Builder
	for line := range strings.SplitSeq(dump, "\n") {
		if before, _, found := strings.Cut(line, "//"); found {
			line = before
		}

		sb.WriteString(strings.Join(strings.Fields(line), ""))
	}

	data, err := hex.DecodeString(sb.String())
	if err != nil {
		t.Fatalf("decoding the golden hex dump: %v", err)
	}

	return data
}

// goldenEntry is what both golden files must parse to. GID, PID and LoginUID are
// -1 and Comm is empty because the golden entry carries only three fields, which
// is also what makes those defaults observable.
func goldenEntry() Entry {
	return Entry{
		Fields: map[string]string{
			messageIDField: testMessageID,
			uidField:       "1000",
			exeField:       testExe,
		},
		UID:          1000,
		GID:          -1,
		PID:          -1,
		Comm:         "",
		Exe:          testExe,
		LoginUID:     -1,
		RealtimeUsec: testRealtime,
		Cursor:       testCursor,
	}
}

func TestGoldenBytesParseInRegularLayout(t *testing.T) {
	path := writeJournal(t, t.TempDir(), "regular.journal", hexBytes(t, goldenRegular))

	entries, err := openAndEntries(anchorFilter(), path)
	if err != nil {
		t.Fatalf("reading the hand-built regular golden file: %v", err)
	}

	assertEntries(t, entries, goldenEntry())
}

func TestGoldenBytesParseIdenticallyInCompactLayout(t *testing.T) {
	dir := t.TempDir()
	regular := writeJournal(t, dir, "regular.journal", hexBytes(t, goldenRegular))
	compact := writeJournal(t, dir, "compact.journal", hexBytes(t, goldenCompact))

	fromRegular, err := openAndEntries(anchorFilter(), regular)
	if err != nil {
		t.Fatalf("reading the regular golden file: %v", err)
	}

	fromCompact, err := openAndEntries(anchorFilter(), compact)
	if err != nil {
		t.Fatalf("reading the compact golden file: %v", err)
	}

	// The whole point of supporting both layouts is that they are the same
	// content, so the two must be indistinguishable once parsed.
	assertEntries(t, fromCompact, goldenEntry())

	if len(fromRegular) != 1 || len(fromCompact) != 1 {
		t.Fatalf("want one entry from each layout, got %d and %d", len(fromRegular), len(fromCompact))
	}

	if diff := entryDiff(fromRegular[0], fromCompact[0]); diff != "" {
		t.Errorf("the COMPACT layout parsed differently from the regular one:\n%s", diff)
	}
}

// TestBuilderReproducesGoldenBytes pins the synthetic-file builder that the rest
// of these tests rely on to the two byte literals systemd's own journalctl
// accepted. Without this, a wrong assumption shared by the builder and the
// reader would be invisible.
func TestBuilderReproducesGoldenBytes(t *testing.T) {
	tests := []struct {
		name   string
		golden string
		build  builder
	}{
		{"regular", goldenRegular, builder{entries: []testEntry{goldenTestEntry()}}},
		{"compact", goldenCompact, builder{compact: true, entries: []testEntry{goldenTestEntry()}}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			want := hexBytes(t, tt.golden)
			got := tt.build.build()

			if len(got) != len(want) {
				t.Fatalf("builder produced %d bytes, the golden literal is %d", len(got), len(want))
			}

			for i := range want {
				if got[i] != want[i] {
					t.Fatalf("builder diverges from the golden bytes at offset %d: got %#02x, want %#02x",
						i, got[i], want[i])
				}
			}
		})
	}
}

func TestOpenRejectsBadSignature(t *testing.T) {
	data := hexBytes(t, goldenRegular)
	copy(data, "NOTAJRNL")

	path := writeJournal(t, t.TempDir(), "bad-signature.journal", data)

	_, err := openAndEntries(anchorFilter(), path)
	if !errors.Is(err, ErrUnsupportedFormat) {
		t.Fatalf("want an error wrapping ErrUnsupportedFormat, got %v", err)
	}
}

// TestUnknownIncompatibleFlagIsAHardError is the failure-direction test. A
// future systemd that sets a flag this parser has never seen must break the
// call, because answering "no anchors found" for a file full of anchors is
// exactly the answer an attacker who deleted them would want.
func TestUnknownIncompatibleFlagIsAHardError(t *testing.T) {
	const unknownBit = 1 << 5

	path := writeJournal(t, t.TempDir(), "future.journal",
		builder{entries: []testEntry{goldenTestEntry()}, extraIncompatible: unknownBit}.build())

	entries, err := openAndEntries(anchorFilter(), path)

	if !errors.Is(err, ErrUnsupportedFormat) {
		t.Fatalf("want an error wrapping ErrUnsupportedFormat, got %v", err)
	}

	if len(entries) != 0 {
		t.Errorf("want no entries alongside the error, got %d", len(entries))
	}

	// The message has to say which bits were not understood, or an operator
	// cannot tell a format change from a corrupt file.
	if !strings.Contains(err.Error(), "0x00000020") {
		t.Errorf("error should name the unrecognized bit, got %q", err)
	}
}

// TestKeyedHashFilesAreReadable covers the flag every file on the target host
// sets. It is a known flag, so it must not be an error — it only means the hash
// tables are useless to this package, which never consults them.
func TestKeyedHashFilesAreReadable(t *testing.T) {
	path := writeJournal(t, t.TempDir(), "keyed.journal",
		builder{keyedHash: true, entries: []testEntry{goldenTestEntry()}}.build())

	entries, err := openAndEntries(anchorFilter(), path)
	if err != nil {
		t.Fatalf("a KEYED-HASH file must be readable: %v", err)
	}

	assertEntries(t, entries, goldenEntry())
}

// TestCompressedZSTDFlagAloneIsReadable covers the other flag the target host
// sets. It says some DATA object somewhere may be compressed, not that any
// object this call needs is.
func TestCompressedZSTDFlagAloneIsReadable(t *testing.T) {
	path := writeJournal(t, t.TempDir(), "zstd.journal",
		builder{extraIncompatible: incompatibleCompressedZSTD, entries: []testEntry{goldenTestEntry()}}.build())

	entries, err := openAndEntries(anchorFilter(), path)
	if err != nil {
		t.Fatalf("a COMPRESSED-ZSTD file with no compressed object in the way must be readable: %v", err)
	}

	assertEntries(t, entries, goldenEntry())
}

func TestEntriesFailsWhenANeededObjectIsCompressed(t *testing.T) {
	entry := goldenTestEntry()

	// _EXE is the one filter field with no small size bound, so it is the one
	// that can genuinely be compressed. With it unreadable, a matching _EXE
	// cannot be ruled out and the call must refuse rather than quietly drop a
	// candidate anchor.
	entry.fields = []testField{
		{name: messageIDField, value: testMessageID},
		{name: uidField, value: "1000"},
		{name: exeField, value: testExe, compressed: true},
	}

	path := writeJournal(t, t.TempDir(), "compressed-exe.journal",
		builder{extraIncompatible: incompatibleCompressedZSTD, entries: []testEntry{entry}}.build())

	entries, err := openAndEntries(anchorFilter(), path)

	if !errors.Is(err, ErrCompressed) {
		t.Fatalf("want an error wrapping ErrCompressed, got %v", err)
	}

	if len(entries) != 0 {
		t.Errorf("want no entries alongside the error, got %d", len(entries))
	}

	if !strings.Contains(err.Error(), "zstd") {
		t.Errorf("error should name the compression that would have been needed, got %q", err)
	}
}

func TestEntriesSkipsCompressedObjectsItDoesNotNeed(t *testing.T) {
	entry := goldenTestEntry()

	// A long MESSAGE is the ordinary reason for a compressed object, and it has
	// nothing to do with whether this entry is an anchor.
	entry.fields = append(entry.fields,
		testField{name: "MESSAGE", value: strings.Repeat("x", 600), compressed: true},
		testField{name: gidField, value: "1000"},
	)

	path := writeJournal(t, t.TempDir(), "compressed-message.journal",
		builder{extraIncompatible: incompatibleCompressedZSTD, entries: []testEntry{entry}}.build())

	entries, err := openAndEntries(anchorFilter(), path)
	if err != nil {
		t.Fatalf("a compressed field nobody asked for must not fail the call: %v", err)
	}

	if len(entries) != 1 {
		t.Fatalf("want one entry, got %d", len(entries))
	}

	if _, ok := entries[0].Fields["MESSAGE"]; ok {
		t.Error("a compressed field must be absent rather than reported as empty")
	}

	// The readable fields still have to come back.
	for name, want := range map[string]string{
		messageIDField: testMessageID,
		uidField:       "1000",
		exeField:       testExe,
		gidField:       "1000",
	} {
		if got := entries[0].Fields[name]; got != want {
			t.Errorf("Fields[%q] = %q, want %q", name, got, want)
		}
	}

	if entries[0].GID != 1000 {
		t.Errorf("GID = %d, want 1000", entries[0].GID)
	}
}

// TestEntriesRejectsForgedAnchorFromWrongUID is the test whose fixture is the
// threat. The journal socket is mode 0666, so any local process can publish a
// well-formed entry carrying the broker's MESSAGE_ID with a fabricated sequence
// number and hash — an anchor of exactly this shape was published from an
// ordinary uid during an experiment and is now permanently in this host's real
// journal, because journal entries cannot be removed.
//
// So a filter on MessageID alone would be a check that accepts everything,
// including the adversary's anchor, and would produce a confident pass on a
// truncated audit log. What the adversary cannot forge is _UID, which journald
// derives from the sending socket's credentials.
func TestEntriesRejectsForgedAnchorFromWrongUID(t *testing.T) {
	genuine := goldenTestEntry()
	genuine.seqnum = 10

	forgedUID := goldenTestEntry()
	forgedUID.seqnum = 11
	forgedUID.fields = []testField{
		{name: messageIDField, value: testMessageID},
		{name: uidField, value: "1001"}, // published by someone else
		{name: exeField, value: testExe},
	}

	forgedExe := goldenTestEntry()
	forgedExe.seqnum = 12
	forgedExe.fields = []testField{
		{name: messageIDField, value: testMessageID},
		{name: uidField, value: "1000"},
		{name: exeField, value: "/tmp/not-the-broker"},
	}

	path := writeJournal(t, t.TempDir(), "forged.journal",
		builder{entries: []testEntry{genuine, forgedUID, forgedExe}}.build())

	entries, err := openAndEntries(anchorFilter(), path)
	if err != nil {
		t.Fatalf("Entries: %v", err)
	}

	if len(entries) != 1 {
		var got []string
		for _, e := range entries {
			got = append(got, fmt.Sprintf("_UID=%d _EXE=%s", e.UID, e.Exe))
		}

		t.Fatalf("want only the genuine anchor, got %d entries: %v", len(entries), got)
	}

	if entries[0].UID != 1000 || entries[0].Exe != testExe {
		t.Errorf("returned the wrong entry: _UID=%d _EXE=%s", entries[0].UID, entries[0].Exe)
	}

	if entries[0].Fields[uidField] != "1000" {
		t.Errorf("Fields[%q] = %q, want \"1000\"", uidField, entries[0].Fields[uidField])
	}
}

func TestEntriesRejectsFiltersThatCannotBeTrusted(t *testing.T) {
	path := writeJournal(t, t.TempDir(), "anchor.journal",
		builder{entries: []testEntry{goldenTestEntry()}}.build())

	reader, err := Open([]string{path})
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	t.Cleanup(func() { reader.Close() })

	// Every one of these would match the entry in the file if the filter were
	// treated permissively, which is precisely why each has to be refused.
	tests := []struct {
		name   string
		filter Filter
		want   string
	}{
		{
			name:   "message id too short",
			filter: Filter{MessageID: "8f3c1d7a", UID: 1000, Exe: testExe},
			want:   "MessageID",
		},
		{
			name:   "message id with dashes",
			filter: Filter{MessageID: "8f3c1d7a-5e4b-42c9-b1d0-6a2f7c93e5a4", UID: 1000, Exe: testExe},
			want:   "MessageID",
		},
		{
			name:   "message id uppercase",
			filter: Filter{MessageID: strings.ToUpper(testMessageID), UID: 1000, Exe: testExe},
			want:   "MessageID",
		},
		{
			name:   "message id not hex",
			filter: Filter{MessageID: strings.Repeat("z", 32), UID: 1000, Exe: testExe},
			want:   "MessageID",
		},
		{
			name:   "negative uid is not a wildcard",
			filter: Filter{MessageID: testMessageID, UID: -1, Exe: testExe},
			want:   "UID",
		},
		{
			name:   "empty exe",
			filter: Filter{MessageID: testMessageID, UID: 1000, Exe: ""},
			want:   "Exe",
		},
		{
			name:   "relative exe",
			filter: Filter{MessageID: testMessageID, UID: 1000, Exe: "bin/adb-broker"},
			want:   "Exe",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			entries, err := reader.Entries(tt.filter)
			if err == nil {
				t.Fatalf("want an error, got %d entries", len(entries))
			}

			if len(entries) != 0 {
				t.Errorf("want no entries alongside the error, got %d", len(entries))
			}

			if !strings.Contains(err.Error(), tt.want) {
				t.Errorf("error should name the offending field %q, got %q", tt.want, err)
			}
		})
	}
}

// TestEntriesReportsEveryFilterProblemAtOnce keeps a caller with two bad fields
// from having to fix them one run at a time.
func TestEntriesReportsEveryFilterProblemAtOnce(t *testing.T) {
	path := writeJournal(t, t.TempDir(), "anchor.journal",
		builder{entries: []testEntry{goldenTestEntry()}}.build())

	_, err := openAndEntries(Filter{MessageID: "nope", UID: -5, Exe: "relative"}, path)
	if err == nil {
		t.Fatal("want an error")
	}

	for _, field := range []string{"MessageID", "UID", "Exe"} {
		if !strings.Contains(err.Error(), field) {
			t.Errorf("error should mention %s, got %q", field, err)
		}
	}
}

func TestEntriesAscendingBySequenceNumber(t *testing.T) {
	// Written to the file out of order, so a reader that just returned file
	// order would fail.
	var entries []testEntry
	for _, seqnum := range []uint64{40, 10, 30, 20} {
		e := goldenTestEntry()
		e.seqnum = seqnum
		e.realtime = testRealtime + seqnum
		entries = append(entries, e)
	}

	path := writeJournal(t, t.TempDir(), "unordered.journal", builder{entries: entries}.build())

	got, err := openAndEntries(anchorFilter(), path)
	if err != nil {
		t.Fatalf("Entries: %v", err)
	}

	assertRealtimes(t, got, []int64{testRealtime + 10, testRealtime + 20, testRealtime + 30, testRealtime + 40})
}

func TestEntriesAcrossFilesInterleavedBySequenceNumber(t *testing.T) {
	dir := t.TempDir()

	build := func(seqnums ...uint64) []byte {
		var entries []testEntry
		for _, seqnum := range seqnums {
			e := goldenTestEntry()
			e.seqnum = seqnum
			e.realtime = testRealtime + seqnum
			entries = append(entries, e)
		}

		return builder{entries: entries}.build()
	}

	// Odd sequence numbers in one file, even in the other, so a correct answer
	// can only come from merging them.
	first := writeJournal(t, dir, "system@odd.journal", build(1, 3, 5))
	second := writeJournal(t, dir, "system@even.journal", build(2, 4, 6))

	got, err := openAndEntries(anchorFilter(), second, first)
	if err != nil {
		t.Fatalf("Entries: %v", err)
	}

	want := []int64{
		testRealtime + 1, testRealtime + 2, testRealtime + 3,
		testRealtime + 4, testRealtime + 5, testRealtime + 6,
	}
	assertRealtimes(t, got, want)
}

// TestEntriesToleratesTruncatedTrailingObject covers a file journald is in the
// middle of writing. The committed entries have to come back; the half-written
// object at the tail must end the traversal rather than fail it.
func TestEntriesToleratesTruncatedTrailingObject(t *testing.T) {
	var entries []testEntry
	for _, seqnum := range []uint64{1, 2, 3} {
		e := goldenTestEntry()
		e.seqnum = seqnum
		e.realtime = testRealtime + seqnum
		entries = append(entries, e)
	}

	// One entry array per entry, so chopping the tail removes the last link of
	// the chain rather than the only one.
	data := builder{entries: entries, arrayChunk: 1}.build()

	// Cut into the final ENTRY_ARRAY object, which still declares its full size.
	truncated := data[:len(data)-8]

	path := writeJournal(t, t.TempDir(), "live.journal", truncated)

	got, err := openAndEntries(anchorFilter(), path)
	if err != nil {
		t.Fatalf("a truncated trailing object must be ignored, not fail the call: %v", err)
	}

	assertRealtimes(t, got, []int64{testRealtime + 1, testRealtime + 2})
}

// TestEntriesStopsAtUnfilledEntryArraySlot covers journald's over-allocation of
// entry arrays: the trailing slots of the last array are zero until they are
// used. The header's entry count normally stops the walk first, so this fixture
// overstates it to leave the zero slot as the only thing that can.
func TestEntriesStopsAtUnfilledEntryArraySlot(t *testing.T) {
	var entries []testEntry
	for _, seqnum := range []uint64{1, 2} {
		e := goldenTestEntry()
		e.seqnum = seqnum
		e.realtime = testRealtime + seqnum
		entries = append(entries, e)
	}

	data := builder{entries: entries, arraySlack: 3, nEntries: new(9)}.build()
	path := writeJournal(t, t.TempDir(), "slack.journal", data)

	got, err := openAndEntries(anchorFilter(), path)
	if err != nil {
		t.Fatalf("Entries: %v", err)
	}

	assertRealtimes(t, got, []int64{testRealtime + 1, testRealtime + 2})
}

// TestEntriesTrustsTheHeaderEntryCount is the other half of live-file tolerance:
// entries appended but not yet counted are not reported.
func TestEntriesTrustsTheHeaderEntryCount(t *testing.T) {
	var entries []testEntry
	for _, seqnum := range []uint64{1, 2, 3} {
		e := goldenTestEntry()
		e.seqnum = seqnum
		e.realtime = testRealtime + seqnum
		entries = append(entries, e)
	}

	data := builder{entries: entries, nEntries: new(2)}.build()
	path := writeJournal(t, t.TempDir(), "committed.journal", data)

	got, err := openAndEntries(anchorFilter(), path)
	if err != nil {
		t.Fatalf("Entries: %v", err)
	}

	assertRealtimes(t, got, []int64{testRealtime + 1, testRealtime + 2})
}

func TestEntriesExtractsTypedFields(t *testing.T) {
	entry := goldenTestEntry()
	entry.fields = []testField{
		{name: messageIDField, value: testMessageID},
		{name: uidField, value: "1000"},
		{name: gidField, value: "1001"},
		{name: pidField, value: "4242"},
		{name: commField, value: "adb-broker"},
		{name: exeField, value: testExe},
		{name: loginUIDField, value: "1002"},
		{name: "ANCHOR_SEQ", value: "17"},
	}

	path := writeJournal(t, t.TempDir(), "typed.journal", builder{entries: []testEntry{entry}}.build())

	got, err := openAndEntries(anchorFilter(), path)
	if err != nil {
		t.Fatalf("Entries: %v", err)
	}

	if len(got) != 1 {
		t.Fatalf("want one entry, got %d", len(got))
	}

	want := Entry{
		Fields: map[string]string{
			messageIDField: testMessageID,
			uidField:       "1000",
			gidField:       "1001",
			pidField:       "4242",
			commField:      "adb-broker",
			exeField:       testExe,
			loginUIDField:  "1002",
			"ANCHOR_SEQ":   "17",
		},
		UID:          1000,
		GID:          1001,
		PID:          4242,
		Comm:         "adb-broker",
		Exe:          testExe,
		LoginUID:     1002,
		RealtimeUsec: testRealtime,
		Cursor:       testCursor,
	}

	if diff := entryDiff(got[0], want); diff != "" {
		t.Errorf("unexpected entry:\n%s", diff)
	}
}

// TestEntriesRefusesAnEntryWithTwoValuesForAFilterField refuses to pick a winner
// where an attacker shadowing a trusted field would be the one choosing.
func TestEntriesRefusesAnEntryWithTwoValuesForAFilterField(t *testing.T) {
	entry := goldenTestEntry()
	entry.fields = []testField{
		{name: messageIDField, value: testMessageID},
		{name: uidField, value: "1000"},
		{name: uidField, value: "0"},
		{name: exeField, value: testExe},
	}

	path := writeJournal(t, t.TempDir(), "shadowed.journal", builder{entries: []testEntry{entry}}.build())

	entries, err := openAndEntries(anchorFilter(), path)
	if err == nil {
		t.Fatalf("want an error, got %d entries", len(entries))
	}

	if !strings.Contains(err.Error(), uidField) {
		t.Errorf("error should name the ambiguous field, got %q", err)
	}
}

func TestEntriesReturnsNothingForAnUnrelatedMessageID(t *testing.T) {
	path := writeJournal(t, t.TempDir(), "anchor.journal",
		builder{entries: []testEntry{goldenTestEntry()}}.build())

	other := anchorFilter()
	other.MessageID = strings.Repeat("ab", 16)

	got, err := openAndEntries(other, path)
	if err != nil {
		t.Fatalf("Entries: %v", err)
	}

	if len(got) != 0 {
		t.Errorf("want no entries, got %d", len(got))
	}
}

func TestOpenWithNoReadablePathsReportsPermission(t *testing.T) {
	requireNonRoot(t)

	dir := t.TempDir()
	path := writeJournal(t, dir, "unreadable.journal", hexBytes(t, goldenRegular))

	if err := os.Chmod(path, 0o000); err != nil {
		t.Fatalf("chmod: %v", err)
	}

	reader, err := Open([]string{path})
	if err == nil {
		reader.Close()
		t.Fatal("want an error opening a file with no read permission")
	}

	if !errors.Is(err, ErrPermission) {
		t.Fatalf("want an error wrapping ErrPermission, got %v", err)
	}

	// The message has to tell the operator what would fix it.
	if !strings.Contains(err.Error(), journalGroup) {
		t.Errorf("error should name the %q group, got %q", journalGroup, err)
	}
}

func TestOpenProceedsWithTheReadableSubset(t *testing.T) {
	requireNonRoot(t)

	dir := t.TempDir()
	readable := writeJournal(t, dir, "readable.journal", hexBytes(t, goldenRegular))
	unreadable := writeJournal(t, dir, "unreadable.journal", hexBytes(t, goldenRegular))

	if err := os.Chmod(unreadable, 0o000); err != nil {
		t.Fatalf("chmod: %v", err)
	}

	// A caller with access to part of the journal should get that part.
	entries, err := openAndEntries(anchorFilter(), unreadable, readable)
	if err != nil {
		t.Fatalf("a readable file alongside an unreadable one must still be read: %v", err)
	}

	assertEntries(t, entries, goldenEntry())
}

func TestOpenRejectsAnEmptyPathList(t *testing.T) {
	reader, err := Open(nil)
	if err == nil {
		reader.Close()
		t.Fatal("want an error for an empty path list")
	}
}

func TestOpenReportsAMissingLiteralPath(t *testing.T) {
	missing := filepath.Join(t.TempDir(), "absent.journal")

	reader, err := Open([]string{missing})
	if err == nil {
		reader.Close()
		t.Fatal("want an error for a path that does not exist")
	}

	// A literal path is not globbed, so its own error surfaces rather than
	// becoming a silent empty match.
	if !strings.Contains(err.Error(), "absent.journal") {
		t.Errorf("error should name the missing file, got %q", err)
	}
}

func TestOpenExpandsGlobPatterns(t *testing.T) {
	dir := t.TempDir()
	writeJournal(t, dir, "one.journal", hexBytes(t, goldenRegular))
	writeJournal(t, dir, "two.journal", hexBytes(t, goldenCompact))

	entries, err := openAndEntries(anchorFilter(), filepath.Join(dir, "*.journal"))
	if err != nil {
		t.Fatalf("Entries: %v", err)
	}

	if len(entries) != 2 {
		t.Fatalf("want two entries from two globbed files, got %d", len(entries))
	}
}

func TestDefaultPathsPrefersThePersistentDirectory(t *testing.T) {
	paths := DefaultPaths()

	want := []string{
		"/var/log/journal/*/*.journal",
		"/run/log/journal/*/*.journal",
	}

	if !slices.Equal(paths, want) {
		t.Errorf("DefaultPaths() = %v, want %v", paths, want)
	}
}

func TestCloseIsIdempotentAndEntriesFailsAfterIt(t *testing.T) {
	path := writeJournal(t, t.TempDir(), "anchor.journal",
		builder{entries: []testEntry{goldenTestEntry()}}.build())

	reader, err := Open([]string{path})
	if err != nil {
		t.Fatalf("Open: %v", err)
	}

	if err := reader.Close(); err != nil {
		t.Fatalf("first Close: %v", err)
	}

	if err := reader.Close(); err != nil {
		t.Fatalf("second Close should be a no-op, got %v", err)
	}

	// A closed reader must say so rather than answer "no anchors found".
	if _, err := reader.Entries(anchorFilter()); err == nil {
		t.Error("want an error from Entries after Close")
	}
}

// TestEntriesRejectsAnEntryArrayLoop keeps a corrupt chain from spinning
// forever.
func TestEntriesRejectsAnEntryArrayLoop(t *testing.T) {
	entries := []testEntry{goldenTestEntry(), goldenTestEntry()}
	entries[1].seqnum = 8

	// One array per entry, so there is a chain to close into a loop, and an
	// overstated n_entries so that the header's count cannot end the walk first.
	// With a truthful count the walk stops on reaching its last entry — which
	// happens inside the final array, before that array's next pointer is ever
	// followed — and the loop would never be traversed at all.
	data := builder{entries: entries, arrayChunk: 1, nEntries: new(9)}.build()

	// Point the last array's next pointer back at the first array.
	firstArray := int(readU64(data, hdrEntryArrayOffset))
	lastArray := int(readU64(data, 136)) // tail_object_offset
	writeU64(data, lastArray+entryArrayNextOffset, uint64(firstArray))

	path := writeJournal(t, t.TempDir(), "loop.journal", data)

	if _, err := openAndEntries(anchorFilter(), path); err == nil {
		t.Fatal("want an error for an entry array chain that loops")
	}
}

// --- helpers -------------------------------------------------------------

func anchorFilter() Filter {
	return Filter{MessageID: testMessageID, UID: 1000, Exe: testExe}
}

// goldenTestEntry is the builder input corresponding to the golden byte
// literals.
func goldenTestEntry() testEntry {
	return testEntry{
		seqnum:    testSeqnum,
		realtime:  testRealtime,
		monotonic: testMonotonic,
		xorHash:   testXorHash,
		bootID:    testBootID,
		fields: []testField{
			{name: messageIDField, value: testMessageID},
			{name: uidField, value: "1000"},
			{name: exeField, value: testExe},
		},
	}
}

func writeJournal(t *testing.T, dir, name string, data []byte) string {
	t.Helper()

	path := filepath.Join(dir, name)
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatalf("writing %s: %v", path, err)
	}

	return path
}

// openAndEntries runs a whole read, returning whichever call reported an error.
// Tests of malformed files use it so they do not have to encode whether Open or
// Entries is the one that notices.
func openAndEntries(filter Filter, paths ...string) ([]Entry, error) {
	reader, err := Open(paths)
	if err != nil {
		return nil, err
	}
	defer reader.Close()

	return reader.Entries(filter)
}

func assertEntries(t *testing.T, got []Entry, want ...Entry) {
	t.Helper()

	if len(got) != len(want) {
		t.Fatalf("got %d entries, want %d", len(got), len(want))
	}

	for i := range want {
		if diff := entryDiff(got[i], want[i]); diff != "" {
			t.Errorf("entry %d:\n%s", i, diff)
		}
	}
}

func assertRealtimes(t *testing.T, got []Entry, want []int64) {
	t.Helper()

	stamps := make([]int64, len(got))
	for i, e := range got {
		stamps[i] = e.RealtimeUsec
	}

	if !slices.Equal(stamps, want) {
		t.Errorf("realtime timestamps in order = %v, want %v", stamps, want)
	}
}

func entryDiff(got, want Entry) string {
	var problems []string

	if !maps.Equal(got.Fields, want.Fields) {
		problems = append(problems, fmt.Sprintf("  Fields: got %v, want %v", got.Fields, want.Fields))
	}

	for _, f := range []struct {
		name      string
		got, want any
	}{
		{"UID", got.UID, want.UID},
		{"GID", got.GID, want.GID},
		{"PID", got.PID, want.PID},
		{"Comm", got.Comm, want.Comm},
		{"Exe", got.Exe, want.Exe},
		{"LoginUID", got.LoginUID, want.LoginUID},
		{"RealtimeUsec", got.RealtimeUsec, want.RealtimeUsec},
		{"Cursor", got.Cursor, want.Cursor},
	} {
		if f.got != f.want {
			problems = append(problems, fmt.Sprintf("  %s: got %v, want %v", f.name, f.got, f.want))
		}
	}

	return strings.Join(problems, "\n")
}

func requireNonRoot(t *testing.T) {
	t.Helper()

	if os.Geteuid() == 0 {
		t.Skip("running as root, which ignores the file mode this test depends on")
	}

	if runtime.GOOS == "windows" {
		t.Skip("POSIX file modes are needed to make a file unreadable")
	}
}
