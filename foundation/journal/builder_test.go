package journal

import (
	"encoding/binary"
	"slices"
)

// This file is a *writer* for the journal format, used only by tests. It is a
// second, independent implementation of the layout format.go decodes, which is
// the point: a reader checked only against files its own parser produced would
// pass every test while misreading reality.
//
// The builder is therefore not the authority on the format. The hand-assembled
// byte literals are — goldenRegular and goldenCompact in journal_test.go, and
// minimalRegular and minimalCompact in format_test.go. Those were laid out from
// the struct definitions systemd documents (https://systemd.io/JOURNAL_FILE_FORMAT/,
// matching src/libsystemd/sd-journal/journal-def.h in v255) and
// TestBuilderReproducesGoldenBytes pins this builder to them byte for byte. If
// the builder drifts, that test fails; if the reader drifts,
// TestGoldenBytesParseInRegularLayout fails. Neither can drift quietly.
//
// What the fixtures deliberately do not reproduce:
//
//   - Hash values. Every hash field is zero. The hash tables are present but
//     empty, and DATA/ENTRY item hashes are zero. This package never consults a
//     hash, because KEYED-HASH means they are SipHash-2-4 keyed and that is not
//     in the standard library; writing real hashes would be inventing agreement
//     with code that does not exist.
//   - FIELD objects. journald writes one per distinct field name; nothing here
//     reads them, so n_fields is zero and none are written.
//   - Actual compression. A field marked compressed gets its DATA object's
//     OBJECT_COMPRESSED_ZSTD flag set and its payload written verbatim, because
//     no reader in this module may look past that flag and producing real zstd
//     would need a dependency this module does not have.

// Header field offsets the builder writes. The ones format.go decodes are
// reused from there; these are the rest of the table documented at the top of
// format.go, so a fixture can be a plausible whole file rather than only the
// parts this package happens to read.
const (
	hdrCompatibleFlags        = 8
	hdrState                  = 16
	hdrFileID                 = 24
	hdrMachineID              = 40
	hdrTailEntryBootID        = 56
	hdrDataHashTableOffset    = 104
	hdrDataHashTableSize      = 112
	hdrFieldHashTableOffset   = 120
	hdrFieldHashTableSize     = 128
	hdrTailObjectOffset       = 136
	hdrNObjects               = 144
	hdrTailEntrySeqnum        = 160
	hdrHeadEntrySeqnum        = 168
	hdrHeadEntryRealtime      = 184
	hdrTailEntryRealtime      = 192
	hdrTailEntryMonotonic     = 200
	hdrNData                  = 208
	hdrNEntryArrays           = 232
	hdrTailEntryArrayOffset   = 256
	hdrTailEntryArrayNEntries = 260
	hdrTailEntryOffset        = 264
)

// The DATA object fields the builder fills in. The others — hash,
// next_hash_offset, next_field_offset, entry_array_offset and the two u32
// fields COMPACT inserts — are left zero, and nothing in this package reads
// them.
const (
	dataEntryOffset    = 40
	dataNEntriesOffset = 56
)

const (
	// testHeaderSize is the v255 header length. Every fixture writes a full
	// modern header rather than the shortest one the reader accepts, since that
	// is what a file on the target host looks like.
	testHeaderSize = 272

	// compatibleTailEntryBootID is HEADER_COMPATIBLE_TAIL_ENTRY_BOOT_ID, which
	// every file on the target host sets. Fixtures set it so that the reader's
	// deliberate refusal to look at compatible flags is exercised rather than
	// merely asserted.
	compatibleTailEntryBootID uint32 = 1 << 1

	// stateArchived is STATE_ARCHIVED, the state of a rotated file.
	stateArchived byte = 2

	// hashItemSize is sizeof(HashItem): {head_hash_offset, tail_hash_offset}.
	hashItemSize = 16

	// testHashBuckets is how many buckets each of the two hash table objects
	// gets. Four is the smallest count that keeps the objects a plausible shape;
	// they are never read.
	testHashBuckets = 4
)

// testField is one NAME=value pair of a synthetic entry.
type testField struct {
	name  string
	value string

	// compressed sets the DATA object's OBJECT_COMPRESSED_ZSTD flag. See the
	// note at the top of this file on why the payload is still written as-is.
	compressed bool
}

// payload is the on-disk form of a field: "NAME=value", with no length prefix
// and no terminator.
func (f testField) payload() []byte {
	return []byte(f.name + "=" + f.value)
}

// key identifies the DATA object a field lives in. journald stores one object
// per distinct pair and points every entry carrying that pair at it, so the
// builder does the same. The compression flag is part of the identity because a
// compressed and an uncompressed object with the same payload are not
// interchangeable to a reader that cannot decompress.
func (f testField) key() string {
	if f.compressed {
		return "zstd\x00" + f.name + "=" + f.value
	}

	return "plain\x00" + f.name + "=" + f.value
}

// testEntry is one synthetic ENTRY object together with the fields it points at.
type testEntry struct {
	seqnum    uint64
	realtime  uint64
	monotonic uint64
	xorHash   uint64
	bootID    [id128Size]byte

	// fields become this entry's items, in this order. A name may repeat, which
	// is how a fixture expresses an entry that shadows a trusted field.
	fields []testField
}

// builder assembles one whole synthetic journal file.
//
// The zero value builds an empty but well-formed file. Every field exists
// because some test needs to vary that one thing and hold the rest still.
type builder struct {
	// entries are written in this order, which is deliberately not required to
	// be sorted by sequence number: ordering the result is the reader's job.
	entries []testEntry

	// compact selects the COMPACT item widths and sets the flag that declares
	// them.
	compact bool

	// keyedHash sets HEADER_INCOMPATIBLE_KEYED_HASH. It changes no layout — it
	// only says the (unread) hash tables are SipHash keyed.
	keyedHash bool

	// extraIncompatible is OR'd into incompatible_flags, so a fixture can
	// declare COMPRESSED-ZSTD, or a bit no released systemd has ever set.
	extraIncompatible uint32

	// arrayChunk is how many entries each ENTRY_ARRAY object lists. Zero puts
	// every entry in a single array. More than one array is what makes a chain
	// to walk, and a tail to truncate.
	arrayChunk int

	// arraySlack appends unused item slots to the last ENTRY_ARRAY, left zero.
	// journald over-allocates these arrays, so its live tail array looks like
	// this.
	arraySlack int

	// nEntries overrides the header's n_entries. nil writes the truthful count;
	// a value understates it (entries appended but not yet committed) or
	// overstates it (a count that cannot stop the walk).
	nEntries *int
}

// testData is one DATA object in the plan.
type testData struct {
	field  testField
	offset uint64
	size   uint64

	// firstEntry indexes the first entry carrying this pair, which is what
	// journald records in the object's entry_offset.
	firstEntry int

	// nEntries counts the entries carrying it.
	nEntries uint64
}

// build serialises the whole file.
//
// Objects are laid out back to back in one pass — hash tables, DATA, ENTRY,
// ENTRY_ARRAY — each padded up to the next 8-byte boundary while its declared
// size stays the exact unpadded length. The offsets have to be known before
// anything can be written, since a DATA object records the offset of an entry
// that comes after it, so planning and writing are separate.
func (b builder) build() []byte {
	// COMPACT narrows exactly three widths and changes nothing else.
	var (
		dataPayload   = uint64(dataPayloadOffsetRegular)
		entryItemSize = uint64(entryItemSizeRegular)
		arrayItemSize = uint64(entryArrayItemSizeRegular)
	)
	if b.compact {
		dataPayload = dataPayloadOffsetCompact
		entryItemSize = entryItemSizeCompact
		arrayItemSize = entryArrayItemSizeCompact
	}

	data, byPair := b.planData()

	at := uint64(testHeaderSize)

	hashTableSize := uint64(objectHeaderSize + testHashBuckets*hashItemSize)
	dataHashTable := at
	at = advance(at, hashTableSize)
	fieldHashTable := at
	at = advance(at, hashTableSize)

	for _, d := range data {
		d.offset = at
		d.size = dataPayload + uint64(len(d.field.payload()))
		at = advance(at, d.size)
	}

	entryOffsets := make([]uint64, len(b.entries))
	entrySizes := make([]uint64, len(b.entries))
	for i, e := range b.entries {
		entryOffsets[i] = at
		entrySizes[i] = entryItemsOffset + entryItemSize*uint64(len(e.fields))
		at = advance(at, entrySizes[i])
	}

	arrays := b.planArrays(entryOffsets)
	arrayOffsets := make([]uint64, len(arrays))
	arraySizes := make([]uint64, len(arrays))
	for i, items := range arrays {
		slots := uint64(len(items))
		if i == len(arrays)-1 {
			slots += uint64(b.arraySlack)
		}

		arrayOffsets[i] = at
		arraySizes[i] = entryArrayItemsOffset + arrayItemSize*slots
		at = advance(at, arraySizes[i])
	}

	buf := make([]byte, at)

	// The two hash table objects, present and empty. systemd's own header
	// verification insists a file has them; this package never looks inside one.
	putObjectHeader(buf, dataHashTable, objectDataHashTable, 0, hashTableSize)
	putObjectHeader(buf, fieldHashTable, objectFieldHashTable, 0, hashTableSize)

	for _, d := range data {
		flags := uint8(0)
		if d.field.compressed {
			flags = objectCompressedZSTD
		}

		putObjectHeader(buf, d.offset, objectData, flags, d.size)
		putU64(buf, d.offset+dataEntryOffset, entryOffsets[d.firstEntry])
		putU64(buf, d.offset+dataNEntriesOffset, d.nEntries)
		copy(buf[d.offset+dataPayload:], d.field.payload())
	}

	for i, e := range b.entries {
		off := entryOffsets[i]

		putObjectHeader(buf, off, objectEntry, 0, entrySizes[i])
		putU64(buf, off+entrySeqnumOffset, e.seqnum)
		putU64(buf, off+entryRealtimeOffset, e.realtime)
		putU64(buf, off+entryMonotonicOffset, e.monotonic)
		copy(buf[off+entryBootIDOffset:], e.bootID[:])
		putU64(buf, off+entryXorHashOffset, e.xorHash)

		// In the regular layout each item is {object_offset, hash} and the hash
		// half stays zero; in COMPACT the item is the offset alone.
		for j, f := range e.fields {
			putItem(buf, off+entryItemsOffset+entryItemSize*uint64(j), byPair[f.key()].offset, b.compact)
		}
	}

	for i, items := range arrays {
		off := arrayOffsets[i]

		var next uint64
		if i+1 < len(arrays) {
			next = arrayOffsets[i+1]
		}

		putObjectHeader(buf, off, objectEntryArray, 0, arraySizes[i])
		putU64(buf, off+entryArrayNextOffset, next)

		// Slack slots are left zero, which is how journald leaves the unused
		// tail of an array it allocated with room to grow.
		for j, entryOff := range items {
			putItem(buf, off+entryArrayItemsOffset+arrayItemSize*uint64(j), entryOff, b.compact)
		}
	}

	copy(buf, signature)
	putU32(buf, hdrCompatibleFlags, compatibleTailEntryBootID)
	putU32(buf, hdrIncompatibleFlags, b.incompatibleFlags())
	buf[hdrState] = stateArchived
	copy(buf[hdrFileID:], testFileID[:])
	copy(buf[hdrMachineID:], testMachineID[:])
	copy(buf[hdrSeqnumID:], testSeqnumID[:])
	putU64(buf, hdrHeaderSize, testHeaderSize)
	putU64(buf, hdrArenaSize, uint64(len(buf))-testHeaderSize)
	putU64(buf, hdrDataHashTableOffset, dataHashTable+objectHeaderSize)
	putU64(buf, hdrDataHashTableSize, testHashBuckets*hashItemSize)
	putU64(buf, hdrFieldHashTableOffset, fieldHashTable+objectHeaderSize)
	putU64(buf, hdrFieldHashTableSize, testHashBuckets*hashItemSize)
	putU64(buf, hdrNObjects, uint64(2+len(data)+len(b.entries)+len(arrays)))
	putU64(buf, hdrNData, uint64(len(data)))
	putU64(buf, hdrNEntryArrays, uint64(len(arrays)))

	// n_fields and n_tags stay zero: no FIELD and no TAG objects are written.

	nEntries := uint64(len(b.entries))
	if b.nEntries != nil {
		nEntries = uint64(*b.nEntries)
	}
	putU64(buf, hdrNEntries, nEntries)

	if len(b.entries) > 0 {
		first, last := b.entries[0], b.entries[len(b.entries)-1]
		lastArray := arrayOffsets[len(arrayOffsets)-1]

		// "head" and "tail" are file order, which is the order journald wrote
		// them in and not necessarily sequence-number order.
		copy(buf[hdrTailEntryBootID:], last.bootID[:])
		putU64(buf, hdrHeadEntrySeqnum, first.seqnum)
		putU64(buf, hdrTailEntrySeqnum, last.seqnum)
		putU64(buf, hdrHeadEntryRealtime, first.realtime)
		putU64(buf, hdrTailEntryRealtime, last.realtime)
		putU64(buf, hdrTailEntryMonotonic, last.monotonic)
		putU64(buf, hdrTailEntryOffset, entryOffsets[len(entryOffsets)-1])
		putU64(buf, hdrTailObjectOffset, lastArray)
		putU64(buf, hdrEntryArrayOffset, arrayOffsets[0])
		putU32(buf, hdrTailEntryArrayOffset, uint32(lastArray))
		putU32(buf, hdrTailEntryArrayNEntries, uint32(len(arrays[len(arrays)-1])+b.arraySlack))
	}

	return buf
}

// planData collects one DATA object per distinct field, in order of first
// appearance, and returns them alongside an index from field to object.
func (b builder) planData() ([]*testData, map[string]*testData) {
	var (
		data   []*testData
		byPair = make(map[string]*testData)
	)

	for i, e := range b.entries {
		for _, f := range e.fields {
			if d, seen := byPair[f.key()]; seen {
				d.nEntries++

				continue
			}

			d := &testData{field: f, firstEntry: i, nEntries: 1}
			byPair[f.key()] = d
			data = append(data, d)
		}
	}

	return data, byPair
}

// planArrays splits the entry offsets into one group per ENTRY_ARRAY object.
func (b builder) planArrays(entryOffsets []uint64) [][]uint64 {
	if len(entryOffsets) == 0 {
		return nil
	}

	chunk := len(entryOffsets)
	if b.arrayChunk > 0 {
		chunk = b.arrayChunk
	}

	return slices.Collect(slices.Chunk(entryOffsets, chunk))
}

// incompatibleFlags is the header's incompatible_flags word.
func (b builder) incompatibleFlags() uint32 {
	flags := b.extraIncompatible

	if b.compact {
		flags |= incompatibleCompact
	}

	if b.keyedHash {
		flags |= incompatibleKeyedHash
	}

	return flags
}

// advance returns the offset the object after one of size size at off begins
// at: objects abut, each padded up to the 8-byte alignment the format requires.
func advance(off, size uint64) uint64 {
	return (off + size + objectAlignment - 1) / objectAlignment * objectAlignment
}

// putObjectHeader writes the 16-byte preamble every object carries. The six
// reserved bytes stay zero.
func putObjectHeader(buf []byte, off uint64, typ, flags uint8, size uint64) {
	buf[off] = typ
	buf[off+objectFlagsOffset] = flags
	putU64(buf, off+objectSizeOffset, size)
}

// putItem writes one entry-array item, or the object_offset half of one entry
// item, at whichever width the layout uses.
func putItem(buf []byte, off, value uint64, compact bool) {
	if compact {
		putU32(buf, off, uint32(value))

		return
	}

	putU64(buf, off, value)
}

func putU64(buf []byte, off, value uint64) {
	binary.LittleEndian.PutUint64(buf[off:], value)
}

func putU32(buf []byte, off uint64, value uint32) {
	binary.LittleEndian.PutUint32(buf[off:], value)
}

// readU64 and writeU64 let a test reach into a built file and corrupt one
// field, so a fixture can be a valid file with exactly one thing wrong.
func readU64(buf []byte, off int) uint64 {
	return binary.LittleEndian.Uint64(buf[off:])
}

func writeU64(buf []byte, off int, value uint64) {
	putU64(buf, uint64(off), value)
}
