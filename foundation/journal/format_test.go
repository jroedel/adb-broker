package journal

import (
	"errors"
	"slices"
	"strings"
	"testing"
)

// The fixtures in this file are a second, independent set of hand-assembled
// bytes, laid out from the struct definitions systemd documents at
// https://systemd.io/JOURNAL_FILE_FORMAT/ (matching
// src/libsystemd/sd-journal/journal-def.h in v255).
//
// They exist because the golden files in journal_test.go and the builder in
// builder_test.go could in principle share a misreading of the format with each
// other and with the parser. These differ from the golden files in every way
// that could hide such a misreading:
//
//   - No hash table objects at all, and data_hash_table_offset zero. The parser
//     must not need them, since KEYED-HASH makes them unusable anyway.
//   - Two entries in one ENTRY_ARRAY, so an array item is read at a non-zero
//     index in both widths. The golden files have a single item each, where a
//     wrong item width would still land on the right bytes.
//   - Two entries sharing all three DATA objects, which is what journald
//     actually does and which exercises the reader's DATA memo.
//   - Different values everywhere: a different seqnum_id, boot id, message id,
//     uid and exe, and payload lengths that pad differently.
//
// Object map of minimalRegular (792 bytes, header_size=272, arena_size=520,
// n_entries=2, entry_array_offset=752, tail_object_offset=752, n_objects=6):
//
//	272 DATA        size=107 payload "MESSAGE_ID=aabbccddeeff00112233445566778899"
//	384 DATA        size=70  payload "_UID=0"
//	456 DATA        size=71  payload "_EXE=/x"
//	528 ENTRY       size=112 seqnum=1 items {272,0} {384,0} {456,0}
//	640 ENTRY       size=112 seqnum=2 items {272,0} {384,0} {456,0}
//	752 ENTRY_ARRAY size=40  next=0 items {528} {640}
//
// Object map of minimalCompact (744 bytes, arena_size=472,
// entry_array_offset=712, tail_object_offset=712):
//
//	272 DATA        size=115 payload at 344
//	392 DATA        size=78  payload at 464
//	472 DATA        size=79  payload at 544
//	552 ENTRY       size=76  seqnum=1 items {272} {392} {472} — 4 bytes each
//	632 ENTRY       size=76  seqnum=2
//	712 ENTRY_ARRAY size=32  next=0 items {552} {632} — 4 bytes each
//
// The trailing comment on each line is the offset of that line's first byte.
var minimalRegular = `
	4c504b53484852480200000000000000 //    0  "LPKSHHRH"; compatible=TAIL_ENTRY_BOOT_ID; incompatible=0
	0200000000000000a0a1a2a3a4a5a6a7 //   16  state=ARCHIVED, reserved[7]; file_id
	a8a9aaabacadaeafb0b1b2b3b4b5b6b7 //   32
	b8b9babbbcbdbebf0102030405060708 //   48  machine_id (cont); tail_entry_boot_id
	090a0b0c0d0e0f100f0e0d0c0b0a0908 //   64  tail_entry_boot_id (cont); seqnum_id
	07060504030201001001000000000000 //   80  seqnum_id (cont); header_size=272
	08020000000000000000000000000000 //   96  arena_size=520; data_hash_table_offset=0
	00000000000000000000000000000000 //  112  no hash tables at all
	0000000000000000f002000000000000 //  128  field_hash_table_size=0; tail_object_offset=752
	06000000000000000200000000000000 //  144  n_objects=6; n_entries=2
	02000000000000000100000000000000 //  160  tail_entry_seqnum=2; head_entry_seqnum=1
	f00200000000000040420f0000000000 //  176  entry_array_offset=752; head_entry_realtime=1000000
	80841e00000000000600000000000000 //  192  tail_entry_realtime=2000000; tail_entry_monotonic=6
	03000000000000000000000000000000 //  208  n_data=3; n_fields=0
	00000000000000000100000000000000 //  224  n_tags=0; n_entry_arrays=1
	00000000000000000000000000000000 //  240  data_hash_chain_depth; field_hash_chain_depth
	f0020000020000008002000000000000 //  256  tail_entry_array_offset=752, n=2; tail_entry_offset=640
	01000000000000006b00000000000000 //  272  DATA type=1 size=107
	00000000000000000000000000000000 //  288  hash=0; next_hash_offset=0
	00000000000000001002000000000000 //  304  next_field_offset=0; entry_offset=528
	00000000000000000200000000000000 //  320  entry_array_offset=0; n_entries=2
	4d4553534147455f49443d6161626263 //  336  payload "MESSAGE_ID=aabbc"
	63646465656666303031313232333334 //  352  "cddeeff001122333"
	34353536363737383839390000000000 //  368  "44556677889" + 5 pad
	01000000000000004600000000000000 //  384  DATA type=1 size=70
	00000000000000000000000000000000 //  400  hash=0; next_hash_offset=0
	00000000000000001002000000000000 //  416  next_field_offset=0; entry_offset=528
	00000000000000000200000000000000 //  432  entry_array_offset=0; n_entries=2
	5f5549443d3000000100000000000000 //  448  payload "_UID=0" + 2 pad; DATA type=1
	47000000000000000000000000000000 //  464  size=71; hash=0
	00000000000000000000000000000000 //  480  next_hash_offset=0; next_field_offset=0
	10020000000000000000000000000000 //  496  entry_offset=528; entry_array_offset=0
	02000000000000005f4558453d2f7800 //  512  n_entries=2; payload "_EXE=/x" + 1 pad
	03000000000000007000000000000000 //  528  ENTRY type=3 size=112
	010000000000000040420f0000000000 //  544  seqnum=1; realtime=1000000
	05000000000000000102030405060708 //  560  monotonic=5; boot_id
	090a0b0c0d0e0f108877665544332211 //  576  boot_id (cont); xor_hash=1122334455667788
	10010000000000000000000000000000 //  592  item 0: object_offset=272, hash=0
	80010000000000000000000000000000 //  608  item 1: object_offset=384, hash=0
	c8010000000000000000000000000000 //  624  item 2: object_offset=456, hash=0
	03000000000000007000000000000000 //  640  ENTRY type=3 size=112
	020000000000000080841e0000000000 //  656  seqnum=2; realtime=2000000
	06000000000000000102030405060708 //  672  monotonic=6; boot_id
	090a0b0c0d0e0f1000ffeeddccbbaa99 //  688  boot_id (cont); xor_hash=99aabbccddeeff00
	10010000000000000000000000000000 //  704  item 0: object_offset=272, hash=0
	80010000000000000000000000000000 //  720  item 1: object_offset=384, hash=0
	c8010000000000000000000000000000 //  736  item 2: object_offset=456, hash=0
	06000000000000002800000000000000 //  752  ENTRY_ARRAY type=6 size=40
	00000000000000001002000000000000 //  768  next_entry_array_offset=0; item 0 = 528
	8002000000000000                 //  784  item 1 = 640
`

var minimalCompact = `
	4c504b53484852480200000010000000 //    0  "LPKSHHRH"; compatible=TAIL_ENTRY_BOOT_ID; incompatible=COMPACT
	0200000000000000a0a1a2a3a4a5a6a7 //   16  state=ARCHIVED, reserved[7]; file_id
	a8a9aaabacadaeafb0b1b2b3b4b5b6b7 //   32
	b8b9babbbcbdbebf0102030405060708 //   48  machine_id (cont); tail_entry_boot_id
	090a0b0c0d0e0f100f0e0d0c0b0a0908 //   64  tail_entry_boot_id (cont); seqnum_id
	07060504030201001001000000000000 //   80  seqnum_id (cont); header_size=272
	d8010000000000000000000000000000 //   96  arena_size=472; data_hash_table_offset=0
	00000000000000000000000000000000 //  112  no hash tables at all
	0000000000000000c802000000000000 //  128  field_hash_table_size=0; tail_object_offset=712
	06000000000000000200000000000000 //  144  n_objects=6; n_entries=2
	02000000000000000100000000000000 //  160  tail_entry_seqnum=2; head_entry_seqnum=1
	c80200000000000040420f0000000000 //  176  entry_array_offset=712; head_entry_realtime=1000000
	80841e00000000000600000000000000 //  192  tail_entry_realtime=2000000; tail_entry_monotonic=6
	03000000000000000000000000000000 //  208  n_data=3; n_fields=0
	00000000000000000100000000000000 //  224  n_tags=0; n_entry_arrays=1
	00000000000000000000000000000000 //  240  data_hash_chain_depth; field_hash_chain_depth
	c8020000020000007802000000000000 //  256  tail_entry_array_offset=712, n=2; tail_entry_offset=632
	01000000000000007300000000000000 //  272  DATA type=1 size=115
	00000000000000000000000000000000 //  288  hash=0; next_hash_offset=0
	00000000000000002802000000000000 //  304  next_field_offset=0; entry_offset=552
	00000000000000000200000000000000 //  320  entry_array_offset=0; n_entries=2
	00000000000000004d4553534147455f //  336  compact tail_entry_array_offset/n=0; payload "MESSAGE_"
	49443d61616262636364646565666630 //  352  "ID=aabbccddeeff0"
	30313132323333343435353636373738 //  368  "0112233445566778"
	38393900000000000100000000000000 //  384  "899" + 5 pad; DATA type=1
	4e000000000000000000000000000000 //  400  size=78; hash=0
	00000000000000000000000000000000 //  416  next_hash_offset=0; next_field_offset=0
	28020000000000000000000000000000 //  432  entry_offset=552; entry_array_offset=0
	02000000000000000000000000000000 //  448  n_entries=2; compact tail_entry_array_offset/n=0
	5f5549443d3000000100000000000000 //  464  payload "_UID=0" + 2 pad; DATA type=1
	4f000000000000000000000000000000 //  480  size=79; hash=0
	00000000000000000000000000000000 //  496  next_hash_offset=0; next_field_offset=0
	28020000000000000000000000000000 //  512  entry_offset=552; entry_array_offset=0
	02000000000000000000000000000000 //  528  n_entries=2; compact tail_entry_array_offset/n=0
	5f4558453d2f78000300000000000000 //  544  payload "_EXE=/x" + 1 pad; ENTRY type=3
	4c000000000000000100000000000000 //  560  size=76; seqnum=1
	40420f00000000000500000000000000 //  576  realtime=1000000; monotonic=5
	0102030405060708090a0b0c0d0e0f10 //  592  boot_id
	88776655443322111001000088010000 //  608  xor_hash; items 272, 384 (u32 each)
	d8010000000000000300000000000000 //  624  item 456 (u32) + 4 pad; ENTRY type=3
	4c000000000000000200000000000000 //  640  size=76; seqnum=2
	80841e00000000000600000000000000 //  656  realtime=2000000; monotonic=6
	0102030405060708090a0b0c0d0e0f10 //  672  boot_id
	00ffeeddccbbaa991001000088010000 //  688  xor_hash; items 272, 384 (u32 each)
	d8010000000000000600000000000000 //  704  item 456 (u32) + 4 pad; ENTRY_ARRAY type=6
	20000000000000000000000000000000 //  720  size=32; next_entry_array_offset=0
	2802000078020000                 //  736  items 552, 632 (u32 each)
`

// minimalEntries is what both minimal fixtures must parse to. The cursors are
// spelled out rather than computed so that cursor() is checked against the
// documented sd_journal_get_cursor format and not against itself.
func minimalEntries() []Entry {
	fields := func() map[string]string {
		return map[string]string{
			messageIDField: minimalMessageID,
			uidField:       "0",
			exeField:       "/x",
		}
	}

	return []Entry{
		{
			Fields: fields(), UID: 0, GID: -1, PID: -1, LoginUID: -1,
			Exe:          "/x",
			RealtimeUsec: 1_000_000,
			Cursor: "s=0f0e0d0c0b0a09080706050403020100;i=1;" +
				"b=0102030405060708090a0b0c0d0e0f10;m=5;t=f4240;x=1122334455667788",
		},
		{
			Fields: fields(), UID: 0, GID: -1, PID: -1, LoginUID: -1,
			Exe:          "/x",
			RealtimeUsec: 2_000_000,
			Cursor: "s=0f0e0d0c0b0a09080706050403020100;i=2;" +
				"b=0102030405060708090a0b0c0d0e0f10;m=6;t=1e8480;x=99aabbccddeeff00",
		},
	}
}

// minimalMessageID is the message id in the minimal fixtures, deliberately not
// the one the golden files use.
const minimalMessageID = "aabbccddeeff00112233445566778899"

func minimalFilter() Filter {
	return Filter{MessageID: minimalMessageID, UID: 0, Exe: "/x"}
}

// TestMinimalFixturesParseWithoutHashTables reads a file that has no hash table
// objects and whose header points at none. The parser must not need them: on
// every file this targets they are SipHash-2-4 keyed and therefore unusable, so
// a dependency on them would be a dependency that cannot be satisfied.
func TestMinimalFixturesParseWithoutHashTables(t *testing.T) {
	for name, dump := range map[string]string{"regular": minimalRegular, "compact": minimalCompact} {
		t.Run(name, func(t *testing.T) {
			path := writeJournal(t, t.TempDir(), name+".journal", hexBytes(t, dump))

			entries, err := openAndEntries(minimalFilter(), path)
			if err != nil {
				t.Fatalf("reading the hand-built minimal %s file: %v", name, err)
			}

			assertEntries(t, entries, minimalEntries()...)
		})
	}
}

// TestMinimalFixturesAgreeAcrossLayouts is the same cross-layout check the
// golden files get, on a fixture whose entry arrays hold more than one item —
// where a wrong item width shows up as a wrong offset rather than landing on the
// right bytes by luck.
func TestMinimalFixturesAgreeAcrossLayouts(t *testing.T) {
	dir := t.TempDir()
	regular := writeJournal(t, dir, "regular.journal", hexBytes(t, minimalRegular))
	compact := writeJournal(t, dir, "compact.journal", hexBytes(t, minimalCompact))

	fromRegular, err := openAndEntries(minimalFilter(), regular)
	if err != nil {
		t.Fatalf("regular: %v", err)
	}

	fromCompact, err := openAndEntries(minimalFilter(), compact)
	if err != nil {
		t.Fatalf("compact: %v", err)
	}

	if len(fromRegular) != 2 || len(fromCompact) != 2 {
		t.Fatalf("want two entries from each layout, got %d and %d", len(fromRegular), len(fromCompact))
	}

	for i := range fromRegular {
		if diff := entryDiff(fromRegular[i], fromCompact[i]); diff != "" {
			t.Errorf("entry %d differs between layouts:\n%s", i, diff)
		}
	}
}

// TestObjectsTileTheArenaWithoutGaps walks each golden file object by object
// using nothing but the declared sizes and the 8-byte alignment rule, and checks
// that the walk lands exactly on the object map the byte literal documents. A
// wrong alignment or a size read from the wrong offset desynchronises the walk
// immediately, which is why this is worth asserting separately from any parse.
func TestObjectsTileTheArenaWithoutGaps(t *testing.T) {
	type object struct {
		offset uint64
		typ    uint8
		size   uint64
	}

	tests := []struct {
		name string
		dump string
		want []object
	}{
		{
			name: "goldenRegular",
			dump: goldenRegular,
			want: []object{
				{272, objectDataHashTable, 80},
				{352, objectFieldHashTable, 80},
				{432, objectData, 107},
				{544, objectData, 73},
				{624, objectData, 94},
				{720, objectEntry, 112},
				{832, objectEntryArray, 32},
			},
		},
		{
			name: "goldenCompact",
			dump: goldenCompact,
			want: []object{
				{272, objectDataHashTable, 80},
				{352, objectFieldHashTable, 80},
				{432, objectData, 115},
				{552, objectData, 81},
				{640, objectData, 102},
				{744, objectEntry, 76},
				{824, objectEntryArray, 28},
			},
		},
		{
			name: "minimalRegular",
			dump: minimalRegular,
			want: []object{
				{272, objectData, 107},
				{384, objectData, 70},
				{456, objectData, 71},
				{528, objectEntry, 112},
				{640, objectEntry, 112},
				{752, objectEntryArray, 40},
			},
		},
		{
			name: "minimalCompact",
			dump: minimalCompact,
			want: []object{
				{272, objectData, 115},
				{392, objectData, 78},
				{472, objectData, 79},
				{552, objectEntry, 76},
				{632, objectEntry, 76},
				{712, objectEntryArray, 32},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			file := hexBytes(t, tt.dump)

			hdr, err := parseFileHeader(file)
			if err != nil {
				t.Fatalf("parseFileHeader: %v", err)
			}

			if got := hdr.headerSize + hdr.arenaSize; got != uint64(len(file)) {
				t.Errorf("header_size+arena_size = %d, but the file is %d bytes", got, len(file))
			}

			var got []object
			for at := hdr.headerSize; at < uint64(len(file)); {
				var raw [objectHeaderSize]byte
				copy(raw[:], file[at:])

				obj := parseObjectHeader(raw)
				got = append(got, object{at, obj.typ, obj.size})

				at = advance(at, obj.size)
			}

			if len(got) != len(tt.want) {
				t.Fatalf("walked %d objects, want %d: %v", len(got), len(tt.want), got)
			}

			for i := range tt.want {
				if got[i] != tt.want[i] {
					t.Errorf("object %d = %+v, want %+v", i, got[i], tt.want[i])
				}
			}
		})
	}
}

func TestParseFileHeaderDecodesTheGoldenHeader(t *testing.T) {
	tests := []struct {
		name             string
		dump             string
		wantArena        uint64
		wantEntryArray   uint64
		wantCompact      bool
		wantIncompatible uint32
	}{
		{"regular", goldenRegular, 592, 832, false, 0},
		{"compact", goldenCompact, 584, 824, true, incompatibleCompact},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			hdr, err := parseFileHeader(hexBytes(t, tt.dump))
			if err != nil {
				t.Fatalf("parseFileHeader: %v", err)
			}

			switch {
			case hdr.headerSize != testHeaderSize:
				t.Errorf("headerSize = %d, want %d", hdr.headerSize, testHeaderSize)

			case hdr.arenaSize != tt.wantArena:
				t.Errorf("arenaSize = %d, want %d", hdr.arenaSize, tt.wantArena)

			case hdr.nEntries != 1:
				t.Errorf("nEntries = %d, want 1", hdr.nEntries)

			case hdr.entryArrayOffset != tt.wantEntryArray:
				t.Errorf("entryArrayOffset = %d, want %d", hdr.entryArrayOffset, tt.wantEntryArray)

			case hdr.incompatibleFlags != tt.wantIncompatible:
				t.Errorf("incompatibleFlags = %#x, want %#x", hdr.incompatibleFlags, tt.wantIncompatible)

			case hdr.compact() != tt.wantCompact:
				t.Errorf("compact() = %t, want %t", hdr.compact(), tt.wantCompact)

			case formatID128(hdr.seqnumID) != "00112233445566778899aabbccddeeff":
				t.Errorf("seqnumID = %s, want 00112233445566778899aabbccddeeff", formatID128(hdr.seqnumID))
			}
		})
	}
}

// TestParseFileHeaderRefusesWhatItCannotInterpret checks that every way a header
// can be wrong is an ErrUnsupportedFormat and never a quiet partial read.
func TestParseFileHeaderRefusesWhatItCannotInterpret(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(hdr []byte) []byte
		want   string
	}{
		{
			name:   "empty",
			mutate: func([]byte) []byte { return nil },
			want:   "signature",
		},
		{
			name:   "wrong signature",
			mutate: func(hdr []byte) []byte { copy(hdr, "NOTAJRNL"); return hdr },
			want:   "signature",
		},
		{
			name:   "truncated below the minimum header",
			mutate: func(hdr []byte) []byte { return hdr[:minHeaderSize-1] },
			want:   "below the 208-byte minimum",
		},
		{
			name: "declares a header shorter than the minimum",
			mutate: func(hdr []byte) []byte {
				writeU64(hdr, hdrHeaderSize, minHeaderSize-8)

				return hdr
			},
			want: "below the 208-byte minimum",
		},
		{
			name: "declares a header larger than this reader accepts",
			mutate: func(hdr []byte) []byte {
				writeU64(hdr, hdrHeaderSize, maxHeaderSize+8)

				return hdr
			},
			want: "above the 4096 bytes",
		},
		{
			name: "declares an implausible arena",
			mutate: func(hdr []byte) []byte {
				writeU64(hdr, hdrArenaSize, maxArenaSize+1)

				return hdr
			},
			want: "arena size",
		},
		{
			name: "unrecognized incompatible bit",
			mutate: func(hdr []byte) []byte {
				putU32(hdr, hdrIncompatibleFlags, 1<<31)

				return hdr
			},
			want: "0x80000000",
		},
		{
			name: "a known bit alongside an unrecognized one",
			mutate: func(hdr []byte) []byte {
				putU32(hdr, hdrIncompatibleFlags, incompatibleCompact|1<<9)

				return hdr
			},
			want: "0x00000200",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			hdr := hexBytes(t, goldenRegular)[:testHeaderSize]

			_, err := parseFileHeader(tt.mutate(hdr))
			if !errors.Is(err, ErrUnsupportedFormat) {
				t.Fatalf("want an error wrapping ErrUnsupportedFormat, got %v", err)
			}

			if !strings.Contains(err.Error(), tt.want) {
				t.Errorf("error should mention %q, got %q", tt.want, err)
			}
		})
	}
}

// TestParseFileHeaderIgnoresCompatibleFlags is the other half of the flag
// policy. A compatible flag means exactly that a reader may ignore it without
// misreading anything, so even a bit from a future systemd must not be refused.
func TestParseFileHeaderIgnoresCompatibleFlags(t *testing.T) {
	hdr := hexBytes(t, goldenRegular)[:testHeaderSize]
	putU32(hdr, hdrCompatibleFlags, 0xffffffff)

	if _, err := parseFileHeader(hdr); err != nil {
		t.Fatalf("an unknown compatible flag must not be an error: %v", err)
	}
}

// TestParseFileHeaderAcceptsTheShortestSupportedHeader covers a file written by
// an old systemd: HEADER_SIZE_MIN is the shortest header that still contains
// every field this package reads.
func TestParseFileHeaderAcceptsTheShortestSupportedHeader(t *testing.T) {
	hdr := hexBytes(t, goldenRegular)[:minHeaderSize]
	writeU64(hdr, hdrHeaderSize, minHeaderSize)

	got, err := parseFileHeader(hdr)
	if err != nil {
		t.Fatalf("a %d-byte header must be accepted: %v", minHeaderSize, err)
	}

	if got.nEntries != 1 || got.entryArrayOffset != 832 {
		t.Errorf("nEntries = %d and entryArrayOffset = %d, want 1 and 832", got.nEntries, got.entryArrayOffset)
	}
}

func TestParseObjectHeaderIgnoresTheReservedBytes(t *testing.T) {
	// type=3 flags=0x04, six reserved bytes deliberately non-zero, size=0x1234.
	raw := [objectHeaderSize]byte{
		0x03, 0x04, 0xde, 0xad, 0xbe, 0xef, 0xca, 0xfe,
		0x34, 0x12, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	}

	got := parseObjectHeader(raw)

	switch {
	case got.typ != objectEntry:
		t.Errorf("typ = %d, want %d", got.typ, objectEntry)

	case got.flags != objectCompressedZSTD:
		t.Errorf("flags = %#x, want %#x", got.flags, objectCompressedZSTD)

	case got.size != 0x1234:
		t.Errorf("size = %#x, want 0x1234", got.size)
	}
}

// TestParseEntryObjectReadsBothItemWidths is the check that COMPACT is
// understood as narrowing the item and nothing else. The two fixtures carry the
// same three offsets, so a width mix-up produces visibly wrong offsets rather
// than a plausible-looking result.
func TestParseEntryObjectReadsBothItemWidths(t *testing.T) {
	regular := `
		03000000000000006000000000000000 //  0  ENTRY type=3, size=96
		11000000000000002200000000000000 // 16  seqnum=0x11; realtime=0x22
		33000000000000000102030405060708 // 32  monotonic=0x33; boot_id
		090a0b0c0d0e0f104400000000000000 // 48  boot_id (cont); xor_hash=0x44
		0001000000000000aaaa000000000000 // 64  item 0: offset=0x100, hash=0xaaaa
		0002000000000000bbbb000000000000 // 80  item 1: offset=0x200, hash=0xbbbb
	`

	compact := `
		03000000000000004800000000000000 //  0  ENTRY type=3, size=72
		11000000000000002200000000000000 // 16  seqnum=0x11; realtime=0x22
		33000000000000000102030405060708 // 32  monotonic=0x33; boot_id
		090a0b0c0d0e0f104400000000000000 // 48  boot_id (cont); xor_hash=0x44
		0001000000020000                 // 64  items: 0x100, 0x200 (u32 each)
	`

	tests := []struct {
		name    string
		dump    string
		compact bool
	}{
		{"regular", regular, false},
		{"compact", compact, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := parseEntryObject(hexBytes(t, tt.dump), tt.compact)
			if err != nil {
				t.Fatalf("parseEntryObject: %v", err)
			}

			switch {
			case got.seqnum != 0x11:
				t.Errorf("seqnum = %#x, want 0x11", got.seqnum)

			case got.realtime != 0x22:
				t.Errorf("realtime = %#x, want 0x22", got.realtime)

			case got.monotonic != 0x33:
				t.Errorf("monotonic = %#x, want 0x33", got.monotonic)

			case got.xorHash != 0x44:
				t.Errorf("xorHash = %#x, want 0x44", got.xorHash)

			case formatID128(got.bootID) != "0102030405060708090a0b0c0d0e0f10":
				t.Errorf("bootID = %s, want 0102030405060708090a0b0c0d0e0f10", formatID128(got.bootID))
			}

			want := []uint64{0x100, 0x200}
			if len(got.dataOffsets) != len(want) {
				t.Fatalf("dataOffsets = %v, want %v", got.dataOffsets, want)
			}

			for i := range want {
				if got.dataOffsets[i] != want[i] {
					t.Errorf("dataOffsets[%d] = %#x, want %#x", i, got.dataOffsets[i], want[i])
				}
			}
		})
	}
}

func TestParseEntryObjectRejectsATruncatedFixedPart(t *testing.T) {
	if _, err := parseEntryObject(make([]byte, entryItemsOffset-1), false); err == nil {
		t.Fatal("want an error for an entry object shorter than its fixed part")
	}
}

// TestParseEntryObjectSkipsAZeroItem covers the belt-and-braces check: offset 0
// is where the file signature lives, so it can never name an object.
func TestParseEntryObjectSkipsAZeroItem(t *testing.T) {
	dump := `
		03000000000000006000000000000000 //  0  ENTRY type=3, size=96
		00000000000000000000000000000000 // 16  seqnum=0; realtime=0
		00000000000000000000000000000000 // 32  monotonic=0; boot_id
		00000000000000000000000000000000 // 48  boot_id (cont); xor_hash=0
		0001000000000000aaaa000000000000 // 64  item 0: offset=0x100, hash=0xaaaa
		00000000000000000000000000000000 // 80  item 1: offset=0, which names no object
	`

	got, err := parseEntryObject(hexBytes(t, dump), false)
	if err != nil {
		t.Fatalf("parseEntryObject: %v", err)
	}

	if len(got.dataOffsets) != 1 || got.dataOffsets[0] != 0x100 {
		t.Errorf("dataOffsets = %v, want [256]", got.dataOffsets)
	}
}

// TestParseEntryArrayReadsBothItemWidths also pins the decision not to trim
// trailing zeros: what a zero slot means belongs to the traversal, which reads
// it as the end of the written data.
func TestParseEntryArrayReadsBothItemWidths(t *testing.T) {
	regular := `
		06000000000000003000000000000000 //  0  ENTRY_ARRAY type=6, size=48
		00030000000000000001000000000000 // 16  next=0x300; item 0 = 0x100
		00020000000000000000000000000000 // 32  item 1 = 0x200; item 2 = 0 (unfilled)
	`

	compact := `
		06000000000000002400000000000000 //  0  ENTRY_ARRAY type=6, size=36
		00030000000000000001000000020000 // 16  next=0x300; items 0x100, 0x200 (u32)
		00000000                         // 32  item 2 = 0 (unfilled)
	`

	tests := []struct {
		name    string
		dump    string
		compact bool
	}{
		{"regular", regular, false},
		{"compact", compact, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := parseEntryArray(hexBytes(t, tt.dump), tt.compact)
			if err != nil {
				t.Fatalf("parseEntryArray: %v", err)
			}

			if got.next != 0x300 {
				t.Errorf("next = %#x, want 0x300", got.next)
			}

			want := []uint64{0x100, 0x200, 0}
			if len(got.items) != len(want) {
				t.Fatalf("items = %v, want %v", got.items, want)
			}

			for i := range want {
				if got.items[i] != want[i] {
					t.Errorf("items[%d] = %#x, want %#x", i, got.items[i], want[i])
				}
			}
		})
	}
}

func TestParseEntryArrayRejectsATruncatedFixedPart(t *testing.T) {
	if _, err := parseEntryArray(make([]byte, entryArrayItemsOffset-1), false); err == nil {
		t.Fatal("want an error for an entry array shorter than its fixed part")
	}
}

// TestParseDataObjectPayloadOffsets is where COMPACT's third effect is pinned:
// the two u32 fields it inserts push the payload from offset 64 to offset 72.
// Reading the compact payload at 64 would return "\x00\x00\x00\x00\x00\x00\x00\x00NAME=value",
// which is exactly the kind of plausible-looking wrong answer that has to be
// impossible.
func TestParseDataObjectPayloadOffsets(t *testing.T) {
	tests := []struct {
		name      string
		compact   bool
		dump      string
		wantName  string
		wantValue string
	}{
		{
			name:    "regular",
			compact: false,
			dump: `
				01000000000000004300000000000000 //  0  DATA type=1, size=67
				00000000000000000000000000000000 // 16  hash; next_hash_offset
				00000000000000000000000000000000 // 32  next_field_offset; entry_offset
				00000000000000000000000000000000 // 48  entry_array_offset; n_entries
				413d62                           // 64  payload "A=b"
			`,
			wantName:  "A",
			wantValue: "b",
		},
		{
			name:    "compact",
			compact: true,
			dump: `
				01000000000000004b00000000000000 //  0  DATA type=1, size=75
				00000000000000000000000000000000 // 16  hash; next_hash_offset
				00000000000000000000000000000000 // 32  next_field_offset; entry_offset
				00000000000000000000000000000000 // 48  entry_array_offset; n_entries
				0000000000000000                 // 64  tail_entry_array_offset; n
				413d62                           // 72  payload "A=b"
			`,
			wantName:  "A",
			wantValue: "b",
		},
		{
			name:    "value containing an equals sign",
			compact: false,
			dump: `
				01000000000000004600000000000000 //  0  DATA type=1, size=70
				00000000000000000000000000000000 // 16
				00000000000000000000000000000000 // 32
				00000000000000000000000000000000 // 48
				413d623d63                       // 64  payload "A=b=c"
			`,
			wantName:  "A",
			wantValue: "b=c",
		},
		{
			name:    "empty value",
			compact: false,
			dump: `
				01000000000000004200000000000000 //  0  DATA type=1, size=66
				00000000000000000000000000000000 // 16
				00000000000000000000000000000000 // 32
				00000000000000000000000000000000 // 48
				413d                             // 64  payload "A="
			`,
			wantName:  "A",
			wantValue: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := parseDataObject(hexBytes(t, tt.dump), tt.compact)
			if err != nil {
				t.Fatalf("parseDataObject: %v", err)
			}

			switch {
			case got.compression != "":
				t.Errorf("compression = %q, want none", got.compression)

			case got.malformed:
				t.Error("malformed = true, want false")

			case got.name != tt.wantName:
				t.Errorf("name = %q, want %q", got.name, tt.wantName)

			case got.value != tt.wantValue:
				t.Errorf("value = %q, want %q", got.value, tt.wantValue)
			}
		})
	}
}

// TestParseDataObjectReportsCompressionWithoutGuessing checks that a compressed
// object comes back with no name and no value. That is what lets a caller tell
// "this field says nothing" from "this field says the empty string" — the object
// cannot even be identified, because the field name is inside the compressed
// payload.
func TestParseDataObjectReportsCompressionWithoutGuessing(t *testing.T) {
	tests := []struct {
		name  string
		flags uint8
		want  string
	}{
		{"zstd", objectCompressedZSTD, "zstd"},
		{"lz4", objectCompressedLZ4, "lz4"},
		{"xz", objectCompressedXZ, "xz"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			obj := make([]byte, dataPayloadOffsetRegular+3)
			putObjectHeader(obj, 0, objectData, tt.flags, uint64(len(obj)))
			copy(obj[dataPayloadOffsetRegular:], "A=b")

			got, err := parseDataObject(obj, false)
			if err != nil {
				t.Fatalf("parseDataObject: %v", err)
			}

			switch {
			case got.compression != tt.want:
				t.Errorf("compression = %q, want %q", got.compression, tt.want)

			case got.name != "", got.value != "":
				t.Errorf("a compressed object must not be given a name or value, got %q=%q", got.name, got.value)
			}
		})
	}
}

// TestParseDataObjectFlagsAreCheckedBeforeTheSize matters because a compressed
// payload can be shorter than the uncompressed fixed part is long: the flags
// have to be read from the object header before anything decides the object is
// too small.
func TestParseDataObjectFlagsAreCheckedBeforeTheSize(t *testing.T) {
	obj := make([]byte, objectHeaderSize)
	putObjectHeader(obj, 0, objectData, objectCompressedZSTD, uint64(len(obj)))

	got, err := parseDataObject(obj, false)
	if err != nil {
		t.Fatalf("parseDataObject: %v", err)
	}

	if got.compression != "zstd" {
		t.Errorf("compression = %q, want zstd", got.compression)
	}
}

func TestParseDataObjectMarksAPayloadWithNoSeparator(t *testing.T) {
	obj := make([]byte, dataPayloadOffsetRegular+2)
	putObjectHeader(obj, 0, objectData, 0, uint64(len(obj)))
	copy(obj[dataPayloadOffsetRegular:], "AB")

	got, err := parseDataObject(obj, false)
	if err != nil {
		t.Fatalf("parseDataObject: %v", err)
	}

	switch {
	case !got.malformed:
		t.Error("malformed = false, want true for a payload with no '='")

	case got.name != "", got.value != "":
		t.Errorf("a malformed object must not be given a name or value, got %q=%q", got.name, got.value)
	}
}

func TestParseDataObjectRejectsATruncatedFixedPart(t *testing.T) {
	tests := []struct {
		name    string
		size    int
		compact bool
	}{
		{"below the object header", objectHeaderSize - 1, false},
		{"below the regular fixed part", dataPayloadOffsetRegular - 1, false},
		{"below the compact fixed part", dataPayloadOffsetCompact - 1, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if _, err := parseDataObject(make([]byte, tt.size), tt.compact); err == nil {
				t.Fatal("want an error for a data object shorter than its fixed part")
			}
		})
	}
}

// TestCompactRegularConfusionIsDetectable is the negative control for the whole
// layout question: reading a compact file as regular, or the reverse, must not
// quietly produce the right answer. If it did, none of the layout tests above
// would be proving anything.
func TestCompactRegularConfusionIsDetectable(t *testing.T) {
	tests := []struct {
		name string
		dump string
		want []uint64
	}{
		{"regular", minimalRegular, []uint64{528, 640}},
		{"compact", minimalCompact, []uint64{552, 632}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			file := hexBytes(t, tt.dump)

			hdr, err := parseFileHeader(file)
			if err != nil {
				t.Fatalf("parseFileHeader: %v", err)
			}

			var raw [objectHeaderSize]byte
			copy(raw[:], file[hdr.entryArrayOffset:])
			obj := file[hdr.entryArrayOffset : hdr.entryArrayOffset+parseObjectHeader(raw).size]

			right, err := parseEntryArray(obj, hdr.compact())
			if err != nil {
				t.Fatalf("parseEntryArray at the declared width: %v", err)
			}

			if !slices.Equal(right.items, tt.want) {
				t.Fatalf("items at the declared width = %v, want %v", right.items, tt.want)
			}

			wrong, err := parseEntryArray(obj, !hdr.compact())
			if err != nil {
				t.Fatalf("parseEntryArray at the wrong width: %v", err)
			}

			if slices.Equal(wrong.items, right.items) {
				t.Errorf("the wrong item width produced the same offsets %v, so the layout tests prove nothing",
					wrong.items)
			}
		})
	}
}

func TestObjectTypeNameCoversEveryType(t *testing.T) {
	want := map[uint8]string{
		objectUnused:         "UNUSED",
		objectData:           "DATA",
		objectField:          "FIELD",
		objectEntry:          "ENTRY",
		objectDataHashTable:  "DATA_HASH_TABLE",
		objectFieldHashTable: "FIELD_HASH_TABLE",
		objectEntryArray:     "ENTRY_ARRAY",
		objectTag:            "TAG",
	}

	for typ, name := range want {
		if got := objectTypeName(typ); got != name {
			t.Errorf("objectTypeName(%d) = %q, want %q", typ, got, name)
		}
	}

	// An unknown type has to report its number, or a mismatch error says nothing
	// an operator can act on.
	if got := objectTypeName(200); !strings.Contains(got, "200") {
		t.Errorf("objectTypeName(200) = %q, want it to name the type", got)
	}
}

// TestPrintableHeadDoesNotSprayControlCharacters covers the signature in an
// error message: the file whose head is being reported is by definition not one
// this package understands, so its bytes are arbitrary.
func TestPrintableHeadDoesNotSprayControlCharacters(t *testing.T) {
	tests := []struct {
		name string
		in   []byte
		n    int
		want string
	}{
		{"printable", []byte("LPKSHHRH"), 8, "LPKSHHRH"},
		{"control bytes", []byte{0x00, 0x1f, 0x7f, 0xff, 'a'}, 5, "....a"},
		{"shorter than n", []byte("ab"), 8, "ab"},
		{"empty", nil, 8, ""},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := printableHead(tt.in, tt.n); got != tt.want {
				t.Errorf("printableHead(%q, %d) = %q, want %q", tt.in, tt.n, got, tt.want)
			}
		})
	}
}
