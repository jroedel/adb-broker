package journal

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"fmt"
)

// The on-disk layout below is transcribed from systemd's journal file format:
// the packed C structs in src/libsystemd/sd-journal/journal-def.h (v255) and the
// accessor helpers in journal-file.h, cross-checked against the prose in
// https://systemd.io/JOURNAL_FILE_FORMAT/.
//
// Every offset here is a byte offset from the start of the containing structure.
// All multi-byte integers are little-endian. Objects are padded to a multiple of
// 8 bytes, but an object's `size` field records its exact unpadded length.
//
// Header (272 bytes as of v255; older files are shorter, see minHeaderSize):
//
//	  0 signature[8]                 136 tail_object_offset
//	  8 compatible_flags   (u32)     144 n_objects
//	 12 incompatible_flags (u32)     152 n_entries
//	 16 state              (u8)      160 tail_entry_seqnum
//	 17 reserved[7]                  168 head_entry_seqnum
//	 24 file_id[16]                  176 entry_array_offset
//	 40 machine_id[16]               184 head_entry_realtime
//	 56 tail_entry_boot_id[16]       192 tail_entry_realtime
//	 72 seqnum_id[16]                200 tail_entry_monotonic
//	 88 header_size                  208 n_data
//	 96 arena_size                   216 n_fields
//	104 data_hash_table_offset       224 n_tags
//	112 data_hash_table_size         232 n_entry_arrays
//	120 field_hash_table_offset      240 data_hash_chain_depth
//	128 field_hash_table_size        248 field_hash_chain_depth
//	                                 256 tail_entry_array_offset    (u32)
//	                                 260 tail_entry_array_n_entries (u32)
//	                                 264 tail_entry_offset
//
// ObjectHeader (16 bytes): type(u8)@0 flags(u8)@1 reserved[6]@2 size@8, payload@16.
//
// DataObject:  objhdr@0 hash@16 next_hash_offset@24 next_field_offset@32
//              entry_offset@40 entry_array_offset@48 n_entries@56
//              then, when COMPACT is set, tail_entry_array_offset(u32)@64 and
//              tail_entry_array_n_entries(u32)@68 — which is why the payload
//              starts at 72 in a compact file and at 64 otherwise.
//
// EntryObject: objhdr@0 seqnum@16 realtime@24 monotonic@32 boot_id[16]@40
//              xor_hash@56 items@64.
//
// EntryArrayObject: objhdr@0 next_entry_array_offset@16 items@24.
//
// COMPACT (systemd >= 252) narrows two item widths and nothing else: an entry
// array item drops from a u64 offset to a u32 offset, and an entry item drops
// from {object_offset u64, hash u64} to {object_offset u32}.

// signature is the magic at offset 0 of every journal file.
const signature = "LPKSHHRH"

// Object types, from the ObjectType enum.
const (
	objectUnused         uint8 = 0
	objectData           uint8 = 1
	objectField          uint8 = 2
	objectEntry          uint8 = 3
	objectDataHashTable  uint8 = 4
	objectFieldHashTable uint8 = 5
	objectEntryArray     uint8 = 6
	objectTag            uint8 = 7
)

// Per-object compression flags, carried in ObjectHeader.flags.
const (
	objectCompressedXZ   uint8 = 1 << 0
	objectCompressedLZ4  uint8 = 1 << 1
	objectCompressedZSTD uint8 = 1 << 2

	objectCompressedMask = objectCompressedXZ | objectCompressedLZ4 | objectCompressedZSTD
)

// Header.incompatible_flags. A reader that does not understand one of these
// cannot interpret the file at all, which is what makes an unrecognized bit a
// hard error rather than something to skip past.
const (
	incompatibleCompressedXZ   uint32 = 1 << 0
	incompatibleCompressedLZ4  uint32 = 1 << 1
	incompatibleKeyedHash      uint32 = 1 << 2
	incompatibleCompressedZSTD uint32 = 1 << 3
	incompatibleCompact        uint32 = 1 << 4

	// incompatibleKnown is every bit this package has been written against.
	// Anything outside it means the format moved on and this parser's
	// assumptions are no longer known to hold.
	incompatibleKnown = incompatibleCompressedXZ | incompatibleCompressedLZ4 |
		incompatibleKeyedHash | incompatibleCompressedZSTD | incompatibleCompact
)

// Byte offsets of the header fields this package reads. The fields it does not
// read are documented in the table above but deliberately not decoded.
const (
	hdrIncompatibleFlags = 12
	hdrSeqnumID          = 72
	hdrHeaderSize        = 88
	hdrArenaSize         = 96
	hdrNEntries          = 152
	hdrEntryArrayOffset  = 176

	// minHeaderSize is systemd's own HEADER_SIZE_MIN, ALIGN64(offsetof(Header,
	// n_data)) — the shortest header any supported systemd wrote. Every field
	// this package reads sits below it, so a header at least this long can
	// always be decoded.
	minHeaderSize = 208

	// maxHeaderSize bounds how much of a file is read before its header is
	// trusted. The real header is 272 bytes; a file claiming vastly more is
	// not one this package should try to interpret.
	maxHeaderSize = 4096

	// maxArenaSize keeps headerSize+arenaSize from overflowing and rejects a
	// header claiming an implausible arena. 256 TiB is far above any journal.
	maxArenaSize = 1 << 48
)

// Object header layout.
const (
	objectHeaderSize  = 16
	objectFlagsOffset = 1
	objectSizeOffset  = 8

	// objectAlignment is the padding boundary every object starts on.
	objectAlignment = 8
)

// Entry object layout.
const (
	entrySeqnumOffset    = 16
	entryRealtimeOffset  = 24
	entryMonotonicOffset = 32
	entryBootIDOffset    = 40
	entryXorHashOffset   = 56
	entryItemsOffset     = 64

	entryItemSizeRegular = 16 // {object_offset u64, hash u64}
	entryItemSizeCompact = 4  // {object_offset u32}
)

// Entry array object layout.
const (
	entryArrayNextOffset  = 16
	entryArrayItemsOffset = 24

	entryArrayItemSizeRegular = 8 // u64 offset
	entryArrayItemSizeCompact = 4 // u32 offset
)

// Data object payload offsets, which differ between the two layouts because
// COMPACT inserts two u32 fields ahead of the payload.
const (
	dataPayloadOffsetRegular = 64
	dataPayloadOffsetCompact = 72
)

// id128Size is the width of an sd_id128_t.
const id128Size = 16

// fileHeader holds the header fields this package needs. The rest of the header
// is intentionally not decoded: reading a field implies depending on it, and
// this parser depends on as little of the format as it can.
type fileHeader struct {
	incompatibleFlags uint32
	seqnumID          [id128Size]byte
	headerSize        uint64
	arenaSize         uint64
	nEntries          uint64
	entryArrayOffset  uint64
}

// compact reports whether this file uses the narrowed COMPACT item widths.
func (h fileHeader) compact() bool {
	return h.incompatibleFlags&incompatibleCompact != 0
}

// parseFileHeader decodes and validates a journal file header.
//
// Validation happens before anything in the file is trusted, and every failure
// is an ErrUnsupportedFormat: a file that is not a journal, or is a journal in a
// dialect this package was not written against, must be refused outright. The
// alternative — parsing what we recognize and ignoring what we do not — would
// report "no anchors found" for a file full of anchors, and that is
// indistinguishable from an adversary having removed them.
func parseFileHeader(buf []byte) (fileHeader, error) {
	if len(buf) < len(signature) || string(buf[:len(signature)]) != signature {
		return fileHeader{}, fmt.Errorf("%w: not a journal file, signature is %q and not %q",
			ErrUnsupportedFormat, printableHead(buf, len(signature)), signature)
	}

	if len(buf) < minHeaderSize {
		return fileHeader{}, fmt.Errorf("%w: header is %d bytes, below the %d-byte minimum",
			ErrUnsupportedFormat, len(buf), minHeaderSize)
	}

	flags := binary.LittleEndian.Uint32(buf[hdrIncompatibleFlags:])
	if unknown := flags &^ incompatibleKnown; unknown != 0 {
		return fileHeader{}, fmt.Errorf("%w: incompatible flags %#08x include unrecognized bits %#08x; "+
			"this reader was written against %#08x and cannot know what the unknown bits changed",
			ErrUnsupportedFormat, flags, unknown, incompatibleKnown)
	}

	// The compatible flags are deliberately not checked. That is what
	// "compatible" means in this format: a reader may ignore a bit it does not
	// know without misreading anything. TAIL_ENTRY_BOOT_ID, set on every file
	// on the target host, is one of these.

	h := fileHeader{
		incompatibleFlags: flags,
		headerSize:        binary.LittleEndian.Uint64(buf[hdrHeaderSize:]),
		arenaSize:         binary.LittleEndian.Uint64(buf[hdrArenaSize:]),
		nEntries:          binary.LittleEndian.Uint64(buf[hdrNEntries:]),
		entryArrayOffset:  binary.LittleEndian.Uint64(buf[hdrEntryArrayOffset:]),
	}
	copy(h.seqnumID[:], buf[hdrSeqnumID:hdrSeqnumID+id128Size])

	switch {
	case h.headerSize < minHeaderSize:
		return fileHeader{}, fmt.Errorf("%w: header declares size %d, below the %d-byte minimum",
			ErrUnsupportedFormat, h.headerSize, minHeaderSize)

	case h.headerSize > maxHeaderSize:
		return fileHeader{}, fmt.Errorf("%w: header declares size %d, above the %d bytes this reader accepts",
			ErrUnsupportedFormat, h.headerSize, maxHeaderSize)

	case h.arenaSize > maxArenaSize:
		return fileHeader{}, fmt.Errorf("%w: header declares arena size %d, above the %d bytes this reader accepts",
			ErrUnsupportedFormat, h.arenaSize, maxArenaSize)
	}

	return h, nil
}

// objectHeader is the 16-byte preamble every object carries.
type objectHeader struct {
	typ   uint8
	flags uint8

	// size is the object's exact length in bytes, its own header included, and
	// before the padding that aligns the next object.
	size uint64
}

// parseObjectHeader decodes an object header. The fixed-size argument makes the
// only precondition — that there are 16 bytes to read — a compile-time one.
func parseObjectHeader(raw [objectHeaderSize]byte) objectHeader {
	return objectHeader{
		typ:   raw[0],
		flags: raw[objectFlagsOffset],
		size:  binary.LittleEndian.Uint64(raw[objectSizeOffset:]),
	}
}

// entryObject is one journal entry: its identity and timestamps, plus the
// offsets of the DATA objects holding its fields.
type entryObject struct {
	seqnum      uint64
	realtime    uint64
	monotonic   uint64
	xorHash     uint64
	bootID      [id128Size]byte
	dataOffsets []uint64
}

// parseEntryObject decodes an ENTRY object. obj must be the object's bytes
// starting at its own header and running to its declared size.
func parseEntryObject(obj []byte, compact bool) (entryObject, error) {
	if len(obj) < entryItemsOffset {
		return entryObject{}, fmt.Errorf("entry object is %d bytes, below the %d-byte fixed part",
			len(obj), entryItemsOffset)
	}

	e := entryObject{
		seqnum:    binary.LittleEndian.Uint64(obj[entrySeqnumOffset:]),
		realtime:  binary.LittleEndian.Uint64(obj[entryRealtimeOffset:]),
		monotonic: binary.LittleEndian.Uint64(obj[entryMonotonicOffset:]),
		xorHash:   binary.LittleEndian.Uint64(obj[entryXorHashOffset:]),
	}
	copy(e.bootID[:], obj[entryBootIDOffset:entryBootIDOffset+id128Size])

	itemSize := entryItemSizeRegular
	if compact {
		itemSize = entryItemSizeCompact
	}

	items := obj[entryItemsOffset:]
	e.dataOffsets = make([]uint64, 0, len(items)/itemSize)

	for at := 0; at+itemSize <= len(items); at += itemSize {
		// Only the object offset is read. The regular layout also carries a
		// per-item copy of the DATA object's hash, which is keyed with
		// SipHash-2-4 on every file this package targets and so is of no use
		// here; see the comment on Reader.Entries.
		off := uint64(binary.LittleEndian.Uint32(items[at:]))
		if !compact {
			off = binary.LittleEndian.Uint64(items[at:])
		}

		// Offset 0 is where the file signature lives, so it can never name an
		// object. Entry items are written exactly, without slack, so this is a
		// belt-and-braces check rather than an expected case.
		if off == 0 {
			continue
		}

		e.dataOffsets = append(e.dataOffsets, off)
	}

	return e, nil
}

// entryArray is one link in a chain of entry offsets.
type entryArray struct {
	next  uint64
	items []uint64
}

// parseEntryArray decodes an ENTRY_ARRAY object. obj must be the object's bytes
// starting at its own header and running to its declared size.
//
// Trailing zero items are returned as-is rather than trimmed, because deciding
// what a zero means belongs to the traversal: journald allocates these arrays
// with room to grow, so a zero is the end of the written data.
func parseEntryArray(obj []byte, compact bool) (entryArray, error) {
	if len(obj) < entryArrayItemsOffset {
		return entryArray{}, fmt.Errorf("entry array object is %d bytes, below the %d-byte fixed part",
			len(obj), entryArrayItemsOffset)
	}

	itemSize := entryArrayItemSizeRegular
	if compact {
		itemSize = entryArrayItemSizeCompact
	}

	items := obj[entryArrayItemsOffset:]
	a := entryArray{
		next:  binary.LittleEndian.Uint64(obj[entryArrayNextOffset:]),
		items: make([]uint64, 0, len(items)/itemSize),
	}

	for at := 0; at+itemSize <= len(items); at += itemSize {
		off := uint64(binary.LittleEndian.Uint32(items[at:]))
		if !compact {
			off = binary.LittleEndian.Uint64(items[at:])
		}

		a.items = append(a.items, off)
	}

	return a, nil
}

// dataObject is one decoded field of an entry.
type dataObject struct {
	name  string
	value string

	// compression names the algorithm the payload is compressed with, and is
	// empty when the payload was decoded. A compressed object never carries a
	// name or value, because the field name lives inside the compressed
	// payload — which is exactly why a compressed object cannot be identified.
	compression string

	// malformed records a payload with no '=' separator. Such an object cannot
	// be any field looked up by name, so the traversal can pass over it.
	malformed bool
}

// parseDataObject decodes a DATA object. obj must be the object's bytes starting
// at its own header and running to its declared size.
//
// A compressed payload is reported, never decoded: journald compresses with
// zstd (or historically xz or lz4) and none of those are in the Go standard
// library, which this module is restricted to. Returning a name of "" for a
// compressed object is what lets the caller distinguish "this field says
// nothing" from "this field says the empty string".
func parseDataObject(obj []byte, compact bool) (dataObject, error) {
	if len(obj) < objectHeaderSize {
		return dataObject{}, fmt.Errorf("data object is %d bytes, below the %d-byte object header",
			len(obj), objectHeaderSize)
	}

	if flags := obj[objectFlagsOffset]; flags&objectCompressedMask != 0 {
		return dataObject{compression: compressionName(flags)}, nil
	}

	payloadOffset := dataPayloadOffsetRegular
	if compact {
		payloadOffset = dataPayloadOffsetCompact
	}

	if len(obj) < payloadOffset {
		return dataObject{}, fmt.Errorf("data object is %d bytes, below the %d-byte fixed part",
			len(obj), payloadOffset)
	}

	// The payload is "NAME=value" with no length prefix and no terminator.
	name, value, ok := bytes.Cut(obj[payloadOffset:], []byte("="))
	if !ok {
		return dataObject{malformed: true}, nil
	}

	return dataObject{name: string(name), value: string(value)}, nil
}

// formatID128 renders a 128-bit systemd id the way SD_ID128_TO_STRING does: 32
// lowercase hex characters, no dashes.
func formatID128(id [id128Size]byte) string {
	return hex.EncodeToString(id[:])
}

// objectTypeName names an object type for error messages, so a mismatch reports
// what was found rather than a bare integer.
func objectTypeName(typ uint8) string {
	switch typ {
	case objectUnused:
		return "UNUSED"
	case objectData:
		return "DATA"
	case objectField:
		return "FIELD"
	case objectEntry:
		return "ENTRY"
	case objectDataHashTable:
		return "DATA_HASH_TABLE"
	case objectFieldHashTable:
		return "FIELD_HASH_TABLE"
	case objectEntryArray:
		return "ENTRY_ARRAY"
	case objectTag:
		return "TAG"
	default:
		return fmt.Sprintf("unknown type %d", typ)
	}
}

// compressionName names the compression a DATA object's flags declare, so an
// ErrCompressed message can say which algorithm would have been needed.
func compressionName(flags uint8) string {
	switch {
	case flags&objectCompressedZSTD != 0:
		return "zstd"
	case flags&objectCompressedLZ4 != 0:
		return "lz4"
	case flags&objectCompressedXZ != 0:
		return "xz"
	default:
		return "none"
	}
}

// printableHead renders the first n bytes of buf for an error message, keeping
// an arbitrary file's contents from spraying control characters into a log.
func printableHead(buf []byte, n int) string {
	head := buf[:min(n, len(buf))]

	out := make([]rune, 0, len(head))
	for _, b := range head {
		if b < 0x20 || b > 0x7e {
			out = append(out, '.')
			continue
		}

		out = append(out, rune(b))
	}

	return string(out)
}
