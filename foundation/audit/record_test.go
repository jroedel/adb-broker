package audit

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"slices"
	"strings"
	"testing"
	"time"
)

// goldenRecord is a fully populated Record with no zero-valued field, used by
// the golden-bytes test. Nothing about it may change casually: its canonical
// form and digest are asserted against hardcoded values derived independently
// of this package's code, which is what makes an accidental format change
// visible instead of silently re-baselining every hash the broker ever wrote.
func goldenRecord() Record {
	return Record{
		Seq:            42,
		TS:             time.Date(2026, 7, 30, 16, 52, 3, 114_000_000, time.UTC),
		Op:             "pull",
		CallerUID:      1000,
		ClientAsserted: "/sdcard/DCIM/a<b>&c.jpg",
		Serial:         "R58MA0ABCDE",
		PathB64:        "L3NkY2FyZC9EQ0lNL2E8Yj4mYy5qcGc=",
		Decision:       "allow",
		Result:         "ok",
		Bytes:          1048576,
		SHA256:         "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08",
		Volume:         VolumeRef{Dev: 190, Ino: 3252},
		Prev:           "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f",
		Hash:           strings.Repeat("f", 64), // must be ignored by both
	}
}

const goldenCanonical = `{"seq":42,"ts":"2026-07-30T16:52:03.114Z","op":"pull","caller_uid":1000,` +
	`"client_asserted":"/sdcard/DCIM/a<b>&c.jpg","serial":"R58MA0ABCDE",` +
	`"path_b64":"L3NkY2FyZC9EQ0lNL2E8Yj4mYy5qcGc=","decision":"allow","result":"ok",` +
	`"bytes":1048576,"sha256":"9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08",` +
	`"volume":{"dev":190,"ino":3252},` +
	`"prev":"000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"}`

// goldenHash is SHA-256(prev ‖ goldenCanonical) where prev is the raw bytes
// 0x00..0x1f, computed outside this package.
const goldenHash = "87da0acf8292aa5b0be20c5ba0a307df395e14157cab6b83bb37d10e8d905210"

func TestCanonicalGoldenBytes(t *testing.T) {
	got, err := Canonical(goldenRecord())
	if err != nil {
		t.Fatalf("Canonical: %v", err)
	}

	if string(got) != goldenCanonical {
		t.Errorf("canonical form changed.\n got: %s\nwant: %s", got, goldenCanonical)
	}

	if bytes.Contains(got, []byte(`"hash"`)) {
		t.Error("canonical form must not contain the hash member")
	}

	if bytes.ContainsAny(got, "\n\t ") {
		t.Errorf("canonical form must be compact, got %q", got)
	}
}

func TestHashRecordGoldenDigest(t *testing.T) {
	var prev [32]byte
	for i := range prev {
		prev[i] = byte(i)
	}

	sum, err := HashRecord(prev, goldenRecord())
	if err != nil {
		t.Fatalf("HashRecord: %v", err)
	}

	if got := hex.EncodeToString(sum[:]); got != goldenHash {
		t.Errorf("digest changed.\n got: %s\nwant: %s", got, goldenHash)
	}
}

// TestHashRecordIgnoresOwnHash pins the rule that a record cannot cover its own
// digest: two records differing only in Hash must hash identically.
func TestHashRecordIgnoresOwnHash(t *testing.T) {
	var prev [32]byte

	a := goldenRecord()
	a.Hash = strings.Repeat("a", 64)

	b := goldenRecord()
	b.Hash = ""

	sumA, err := HashRecord(prev, a)
	if err != nil {
		t.Fatalf("HashRecord(a): %v", err)
	}

	sumB, err := HashRecord(prev, b)
	if err != nil {
		t.Fatalf("HashRecord(b): %v", err)
	}

	if sumA != sumB {
		t.Errorf("Hash field leaked into its own digest: %x vs %x", sumA, sumB)
	}
}

// TestHashRecordZeroPrevIsChainStart documents that hash_0 is 32 zero bytes, so
// a caller starting a chain passes the zero array and nothing else.
func TestHashRecordZeroPrevIsChainStart(t *testing.T) {
	var zero [32]byte
	if hex.EncodeToString(zero[:]) != strings.Repeat("0", 64) {
		t.Fatal("the zero chain head must be 64 hex zeros")
	}

	if _, err := HashRecord(zero, Record{TS: time.Unix(0, 0)}); err != nil {
		t.Fatalf("HashRecord with the zero head: %v", err)
	}
}

// TestCanonicalDoesNotEscapeHTML guards the rule that '<', '>' and '&' are
// written literally. encoding/json escapes them by default, so a verifier built
// on that default would disagree with this package on every record whose
// client-asserted path or result code contained one.
func TestCanonicalDoesNotEscapeHTML(t *testing.T) {
	r := Record{TS: time.Unix(0, 0).UTC(), ClientAsserted: "a<b>&c", Result: "x<y>&z"}

	got, err := Canonical(r)
	if err != nil {
		t.Fatalf("Canonical: %v", err)
	}

	for _, want := range []string{`"client_asserted":"a<b>&c"`, `"result":"x<y>&z"`} {
		if !bytes.Contains(got, []byte(want)) {
			t.Errorf("want %s literally in %s", want, got)
		}
	}

	// The escaped forms encoding/json would emit by default must be absent.
	for _, bad := range []string{`\u003c`, `\u003e`, `\u0026`} {
		if bytes.Contains(got, []byte(bad)) {
			t.Errorf("found HTML escape %s in %s", bad, got)
		}
	}
}

// TestCanonicalEscapeSet pins the exact escape set, including the code points
// that are deliberately NOT escaped.
func TestCanonicalEscapeSet(t *testing.T) {
	tests := map[string]struct {
		in   string
		want string
	}{
		"quote":             {in: `a"b`, want: `a\"b`},
		"backslash":         {in: `a\b`, want: `a\\b`},
		"tab":               {in: "a\tb", want: `a\tb`},
		"newline":           {in: "a\nb", want: `a\nb`},
		"carriage return":   {in: "a\rb", want: `a\rb`},
		"backspace":         {in: "a\bb", want: `a\bb`},
		"form feed":         {in: "a\fb", want: `a\fb`},
		"other control":     {in: "a\x01\x1fb", want: `a\u0001\u001fb`},
		"del stays literal": {in: "a\x7fb", want: "a\x7fb"},
		"line separator":    {in: "a\u2028b", want: "a\u2028b"},
		"para separator":    {in: "a\u2029b", want: "a\u2029b"},
		"multibyte utf8":    {in: "a\u00e9\U0001F600b", want: "a\u00e9\U0001F600b"},
		"invalid utf8 byte": {in: "a\xffb", want: "a\ufffdb"},
	}

	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			got, err := Canonical(Record{TS: time.Unix(0, 0).UTC(), Op: tc.in})
			if err != nil {
				t.Fatalf("Canonical: %v", err)
			}

			want := `"op":"` + tc.want + `"`
			if !bytes.Contains(got, []byte(want)) {
				t.Errorf("want %q in %q", want, got)
			}
		})
	}
}

// TestCanonicalTimestampNormalization covers the two rules that let a caller
// pass whatever time.Time it happens to hold: the zone is normalised to UTC,
// and sub-millisecond precision is truncated rather than rounded.
func TestCanonicalTimestampNormalization(t *testing.T) {
	t.Run("zone independent", func(t *testing.T) {
		utc := time.Date(2026, 7, 30, 16, 52, 3, 114_000_000, time.UTC)
		local := utc.In(time.FixedZone("UTC+5:30", 5*3600+1800))

		if !utc.Equal(local) {
			t.Fatal("test setup: the two times must be the same instant")
		}

		gotUTC, err := Canonical(Record{TS: utc})
		if err != nil {
			t.Fatalf("Canonical(utc): %v", err)
		}

		gotLocal, err := Canonical(Record{TS: local})
		if err != nil {
			t.Fatalf("Canonical(local): %v", err)
		}

		if !bytes.Equal(gotUTC, gotLocal) {
			t.Errorf("zone leaked into the canonical form:\n utc: %s\nlocal: %s", gotUTC, gotLocal)
		}

		if !bytes.Contains(gotUTC, []byte(`"ts":"2026-07-30T16:52:03.114Z"`)) {
			t.Errorf("unexpected timestamp in %s", gotUTC)
		}
	})

	t.Run("truncates not rounds", func(t *testing.T) {
		tests := map[string]struct {
			ns   int
			want string
		}{
			"just under a ms": {ns: 114_999_999, want: "16:52:03.114Z"},
			"just over a ms":  {ns: 115_000_001, want: "16:52:03.115Z"},
			"sub-ms only":     {ns: 999_999, want: "16:52:03.000Z"},
			"exactly on a ms": {ns: 500_000_000, want: "16:52:03.500Z"},
		}

		for name, tc := range tests {
			t.Run(name, func(t *testing.T) {
				got, err := Canonical(Record{TS: time.Date(2026, 7, 30, 16, 52, 3, tc.ns, time.UTC)})
				if err != nil {
					t.Fatalf("Canonical: %v", err)
				}

				if !bytes.Contains(got, []byte(tc.want)) {
					t.Errorf("want %s in %s", tc.want, got)
				}
			})
		}
	})
}

// TestCanonicalFieldOrder asserts the key order over a record with every field
// non-zero. A struct-field reorder must not be able to change it, because the
// encoder spells the order out; this test is what proves the two agree.
func TestCanonicalFieldOrder(t *testing.T) {
	got, err := Canonical(goldenRecord())
	if err != nil {
		t.Fatalf("Canonical: %v", err)
	}

	want := []string{
		"seq", "ts", "op", "caller_uid", "client_asserted", "serial", "path_b64",
		"decision", "result", "bytes", "sha256", "volume", "dev", "ino", "prev",
	}

	if keys := jsonKeysInOrder(t, got); !slices.Equal(keys, want) {
		t.Errorf("key order changed.\n got: %v\nwant: %v", keys, want)
	}
}

// TestCanonicalEveryFieldPresentWhenZero pins the no-omitempty rule: a
// completely zero Record still serialises all fifteen members.
func TestCanonicalEveryFieldPresentWhenZero(t *testing.T) {
	got, err := Canonical(Record{})
	if err != nil {
		t.Fatalf("Canonical: %v", err)
	}

	want := `{"seq":0,"ts":"0001-01-01T00:00:00.000Z","op":"","caller_uid":0,` +
		`"client_asserted":"","serial":"","path_b64":"","decision":"","result":"",` +
		`"bytes":0,"sha256":"","volume":{"dev":0,"ino":0},"prev":""}`

	if string(got) != want {
		t.Errorf("zero record changed.\n got: %s\nwant: %s", got, want)
	}
}

// TestCanonicalRejectsUnrepresentableTimestamp checks that a year outside the
// fixed-width range is refused rather than serialised at a different width,
// which would produce bytes no verifier could reproduce from the parsed form.
func TestCanonicalRejectsUnrepresentableTimestamp(t *testing.T) {
	for _, year := range []int{-1, 10000} {
		r := Record{TS: time.Date(year, 1, 1, 0, 0, 0, 0, time.UTC)}
		if _, err := Canonical(r); err == nil {
			t.Errorf("year %d: want an error, got none", year)
		}
	}
}

// jsonKeysInOrder returns every object key in b in document order, descending
// into nested objects. The input has no arrays, so a two-state walk suffices.
func jsonKeysInOrder(t *testing.T, b []byte) []string {
	t.Helper()

	dec := json.NewDecoder(bytes.NewReader(b))

	var keys []string
	expectKey := false

	for {
		tok, err := dec.Token()
		if errors.Is(err, io.EOF) {
			return keys
		}

		if err != nil {
			t.Fatalf("token: %v", err)
		}

		switch v := tok.(type) {
		case json.Delim:
			expectKey = true
		case string:
			switch expectKey {
			case true:
				keys = append(keys, v)
				expectKey = false
			default:
				expectKey = true
			}
		default:
			expectKey = true
		}
	}
}
