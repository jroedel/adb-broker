package audit

import (
	"crypto/sha256"
	"fmt"
	"slices"
	"strconv"
	"time"
	"unicode/utf8"
)

// tsLayout is the only accepted timestamp form: RFC 3339 in UTC with exactly
// three fractional digits and a literal Z. The "Z" here is literal text, not
// Go's "Z07:00" zone verb, so parsing with this layout accepts nothing else —
// no numeric offsets, no other fractional widths.
const tsLayout = "2006-01-02T15:04:05.000Z"

// tsLen is the exact byte length a canonical timestamp must have. A time whose
// year falls outside 0000-9999 formats to a different width, which would break
// the fixed-width guarantee; Canonical rejects such a record rather than
// emitting a form a verifier could not reproduce.
const tsLen = len("2026-07-30T16:52:03.114Z")

// VolumeRef identifies the filesystem object a record refers to by device and
// inode number rather than by name, because a name can be re-pointed between
// the moment a path is authorised and the moment it is used.
type VolumeRef struct{ Dev, Ino int64 }

// Record is one audit entry.
//
// The field order below IS the canonical serialization order (see Canonical).
// Reordering these fields does not change the bytes on the wire — the encoder
// spells the order out explicitly — but it would make the declaration lie about
// the format, so keep the two in step.
type Record struct {
	Seq            uint64
	TS             time.Time
	Op             string
	CallerUID      int
	ClientAsserted string
	Serial         string
	PathB64        string
	Decision       string // "allow" | "deny"
	Result         string // "ok", or an error code
	Bytes          int64
	SHA256         string
	Volume         VolumeRef
	Prev           string // hex of the previous record's hash
	Hash           string // hex; EXCLUDED from its own input
}

// Canonical returns the byte-exact serialization of r that the hash chain is
// computed over. Two independent implementations of this function must agree to
// the byte, so the format is specified here rather than delegated to
// encoding/json's defaults:
//
//   - Fields appear in exactly the order they are declared in Record. The
//     encoder writes each key as a literal, so no struct-tag or reflection
//     ordering behaviour can silently change a hash.
//   - Hash is omitted entirely: a record cannot cover its own digest.
//   - The form is compact — no insignificant whitespace, no trailing newline.
//   - Every field is always present. There is no omitempty/omitzero anywhere:
//     a field that vanishes when zero makes the byte stream depend on the value
//     in a way every verifier would then have to replicate exactly.
//   - Strings are escaped with the minimum JSON escape set: '"' and '\' as
//     '\"' and '\\'; U+0008, U+0009, U+000A, U+000C and U+000D as \b, \t, \n,
//     \f and \r; any other code point below U+0020 as \u00xx with lower-case
//     hex. Nothing else is escaped. In particular '<', '>' and '&' are written
//     literally — encoding/json escapes those by default, and a rule that only
//     happens to hold (because paths are base64) is not a rule: ClientAsserted
//     and Result carry arbitrary text. U+2028 and U+2029 are likewise literal.
//     Invalid UTF-8 bytes are replaced one-for-one by U+FFFD.
//   - TS is normalised to UTC and truncated — never rounded — to milliseconds,
//     then written as RFC 3339 with exactly three fractional digits and a Z
//     suffix ("2026-07-30T16:52:03.114Z"). A caller passing a local-zone time
//     therefore produces the same bytes as one passing the equivalent UTC time.
//   - Volume is a nested object: {"dev":190,"ino":3252}.
//   - Integers are plain base-10. No field in Record is floating point, so
//     there is no float formatting to disagree about.
//
// It returns an error only when TS cannot be represented in the fixed-width
// timestamp form.
func Canonical(r Record) ([]byte, error) {
	ts, err := canonicalTime(r.TS)
	if err != nil {
		return nil, err
	}

	b := make([]byte, 0, 512)
	b = append(b, `{"seq":`...)
	b = strconv.AppendUint(b, r.Seq, 10)
	b = append(b, `,"ts":`...)
	b = appendJSONString(b, ts)
	b = append(b, `,"op":`...)
	b = appendJSONString(b, r.Op)
	b = append(b, `,"caller_uid":`...)
	b = strconv.AppendInt(b, int64(r.CallerUID), 10)
	b = append(b, `,"client_asserted":`...)
	b = appendJSONString(b, r.ClientAsserted)
	b = append(b, `,"serial":`...)
	b = appendJSONString(b, r.Serial)
	b = append(b, `,"path_b64":`...)
	b = appendJSONString(b, r.PathB64)
	b = append(b, `,"decision":`...)
	b = appendJSONString(b, r.Decision)
	b = append(b, `,"result":`...)
	b = appendJSONString(b, r.Result)
	b = append(b, `,"bytes":`...)
	b = strconv.AppendInt(b, r.Bytes, 10)
	b = append(b, `,"sha256":`...)
	b = appendJSONString(b, r.SHA256)
	b = append(b, `,"volume":{"dev":`...)
	b = strconv.AppendInt(b, r.Volume.Dev, 10)
	b = append(b, `,"ino":`...)
	b = strconv.AppendInt(b, r.Volume.Ino, 10)
	b = append(b, `},"prev":`...)
	b = appendJSONString(b, r.Prev)
	b = append(b, '}')

	return b, nil
}

// HashRecord returns SHA-256(prev ‖ Canonical(r)).
//
// prev is the raw 32-byte hash of the preceding record; for the first record it
// is 32 zero bytes. The chain is hash_n = SHA-256(hash_{n-1} ‖ canonical(record_n
// without its own hash)).
//
// HashRecord does not check that r.Prev is the hex of prev — it is a mechanical
// function of its two inputs. Append sets r.Prev from the live chain head
// before calling this, and VerifyChain checks the linkage separately, so the
// two representations of the predecessor cannot drift apart unnoticed.
func HashRecord(prev [32]byte, r Record) ([32]byte, error) {
	c, err := Canonical(r)
	if err != nil {
		return [32]byte{}, err
	}

	return sha256.Sum256(slices.Concat(prev[:], c)), nil
}

// canonicalTime renders t in the single accepted timestamp form.
func canonicalTime(t time.Time) (string, error) {
	s := t.UTC().Truncate(time.Millisecond).Format(tsLayout)
	if len(s) != tsLen || s[len(s)-1] != 'Z' {
		return "", fmt.Errorf("audit: timestamp %s is not representable in the fixed-width canonical form", s)
	}

	return s, nil
}

const hexDigits = "0123456789abcdef"

// appendJSONString appends s to dst as a JSON string literal using the minimum
// escape set documented on Canonical. It is deliberately hand-written: the
// chain's correctness depends on these bytes never changing, and delegating to
// encoding/json would tie the on-disk format to that package's escaping
// choices (HTML escaping, U+2028/U+2029) rather than to a written-down rule.
func appendJSONString(dst []byte, s string) []byte {
	dst = append(dst, '"')

	for i := 0; i < len(s); {
		c := s[i]
		if c >= utf8.RuneSelf {
			r, size := utf8.DecodeRuneInString(s[i:])
			switch {
			case r == utf8.RuneError && size == 1:
				dst = utf8.AppendRune(dst, utf8.RuneError)
			default:
				dst = append(dst, s[i:i+size]...)
			}
			i += size

			continue
		}

		switch {
		case c == '"':
			dst = append(dst, '\\', '"')
		case c == '\\':
			dst = append(dst, '\\', '\\')
		case c == '\b':
			dst = append(dst, '\\', 'b')
		case c == '\f':
			dst = append(dst, '\\', 'f')
		case c == '\n':
			dst = append(dst, '\\', 'n')
		case c == '\r':
			dst = append(dst, '\\', 'r')
		case c == '\t':
			dst = append(dst, '\\', 't')
		case c < 0x20:
			dst = append(dst, `\u00`...)
			dst = append(dst, hexDigits[c>>4], hexDigits[c&0x0f])
		default:
			dst = append(dst, c)
		}
		i++
	}

	return append(dst, '"')
}
