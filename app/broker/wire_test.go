package broker

import (
	"bytes"
	"encoding/json"
	"reflect"
	"strings"
	"testing"
)

// These tests assert the bytes of each wire type directly, without going through a
// subcommand, because the contract is a byte format and not a struct: a renamed member, a
// reordered one or an added one is a change a consumer sees, and it must not be possible to
// make one by accident.

// marshal renders v exactly as the package writes it: compact, one line, no HTML escaping.
func marshal(t *testing.T, v any) string {
	t.Helper()

	var buf bytes.Buffer
	if err := writeJSON(&buf, v); err != nil {
		t.Fatalf("encode %T: %v", v, err)
	}

	return buf.String()
}

func TestProbeResponseBytes(t *testing.T) {
	got := marshal(t, ProbeResponse{
		Proto:           proto,
		Status:          statusOK,
		Serial:          "EXAMPLESERIAL1",
		State:           "device",
		Broker:          "0.1.0",
		ADB:             "1.0.41",
		AttachedDevices: 1,
		Allowlist:       []string{"/sdcard/DCIM", "/sdcard/Download"},
	})

	want := `{"proto":1,"status":"ok","serial":"EXAMPLESERIAL1","state":"device","broker":"0.1.0","adb":"1.0.41","attached_devices":1,"allowlist":["/sdcard/DCIM","/sdcard/Download"]}` + "\n"

	if got != want {
		t.Errorf("\n got: %q\nwant: %q", got, want)
	}
}

func TestProbeResponseMembersAreAlwaysPresent(t *testing.T) {
	// No omitempty and no omitzero on a probe response, for the same reason a record has
	// none: a consumer must never have to distinguish an absent member from a zero one. The
	// two that make this worth asserting are the new ones — an absent allowlist reads as "no
	// roots are reachable" and an absent attached_devices reads as "no phone is attached",
	// and both of those are the opposite of what a zero value would mean here.
	decoded := map[string]any{}
	if err := json.Unmarshal([]byte(marshal(t, ProbeResponse{})), &decoded); err != nil {
		t.Fatalf("decode: %v", err)
	}

	for _, member := range []string{"proto", "status", "serial", "state", "broker", "adb", "attached_devices", "allowlist"} {
		if _, ok := decoded[member]; !ok {
			t.Errorf("the zero probe response omits %q", member)
		}
	}
}

func TestFileRecordResponseBytes(t *testing.T) {
	got := marshal(t, FileRecordResponse{
		Path:    "/sdcard/DCIM/Camera/IMG_0182.JPG",
		PathB64: "L3NkY2FyZC9EQ0lNL0NhbWVyYS9JTUdfMDE4Mi5KUEc=",
		Size:    103159,
		Mtime:   1709828653,
	})

	want := `{"path":"/sdcard/DCIM/Camera/IMG_0182.JPG","path_b64":"L3NkY2FyZC9EQ0lNL0NhbWVyYS9JTUdfMDE4Mi5KUEc=","size":103159,"mtime":1709828653}` + "\n"

	if got != want {
		t.Errorf("\n got: %q\nwant: %q", got, want)
	}
}

func TestFileRecordResponseHasNoNanosecondMember(t *testing.T) {
	// The transport carries whole seconds only. A member that can never be populated must not
	// exist in the contract, so this asserts on the marshalled TYPE rather than on one output:
	// adding the field to the struct fails here even if no code ever sets it.
	got := marshal(t, FileRecordResponse{})

	if strings.Contains(got, "nsec") {
		t.Errorf("a record carries a sub-second member: %s", got)
	}
}

func TestEveryRecordMemberIsAlwaysPresent(t *testing.T) {
	// No omitempty and no omitzero anywhere on a record: a zero-byte file with an mtime of 0 —
	// both of which exist on the target device — must still carry size and mtime, or a
	// consumer would have to distinguish "absent" from "zero".
	decoded := map[string]any{}
	if err := json.Unmarshal([]byte(marshal(t, FileRecordResponse{})), &decoded); err != nil {
		t.Fatalf("decode: %v", err)
	}

	for _, member := range []string{"path", "path_b64", "size", "mtime"} {
		if _, ok := decoded[member]; !ok {
			t.Errorf("the zero record omits %q", member)
		}
	}
}

func TestListSummaryResponseBytes(t *testing.T) {
	for _, tc := range []struct {
		name string
		res  ListSummaryResponse
		want string
	}{
		{
			name: "nothing failed",
			res:  ListSummaryResponse{Proto: proto, Status: statusOK, Files: 20397, Errors: []PathErrorResponse{}},
			want: `{"proto":1,"status":"ok","files":20397,"errors":[]}`,
		},
		{
			name: "some paths failed",
			res: ListSummaryResponse{Proto: proto, Status: statusPartial, Files: 20397, Errors: []PathErrorResponse{
				{Code: "permission_denied", Path: "/sdcard/DCIM/Camera/locked", PathB64: "L3NkY2FyZC9EQ0lNL0NhbWVyYS9sb2NrZWQ="},
			}},
			want: `{"proto":1,"status":"partial","files":20397,"errors":[{"code":"permission_denied","path":"/sdcard/DCIM/Camera/locked","path_b64":"L3NkY2FyZC9EQ0lNL0NhbWVyYS9sb2NrZWQ="}]}`,
		},
	} {
		if got := marshal(t, tc.res); got != tc.want+"\n" {
			t.Errorf("%s\n got: %q\nwant: %q", tc.name, got, tc.want+"\n")
		}
	}
}

func TestASummaryNeverCarriesAPathMember(t *testing.T) {
	// ListSummaryResponse itself never declares a path member — that remains true and is
	// worth guarding — but it is NOT the discriminator a consumer may use to identify a
	// terminator. See TestAbsenceOfPathDoesNotSafelyDiscriminateATerminator immediately
	// below for why: a list stream's OTHER terminator, ErrorResponse, can carry a path.
	decoded := map[string]any{}
	if err := json.Unmarshal([]byte(marshal(t, ListSummaryResponse{})), &decoded); err != nil {
		t.Fatalf("decode: %v", err)
	}

	if _, ok := decoded["path"]; ok {
		t.Error("a summary carries a path member")
	}
}

func TestAbsenceOfPathDoesNotSafelyDiscriminateATerminator(t *testing.T) {
	// This is Defect A, made concrete. The spec used to say a list stream's terminating
	// summary is "distinguished by having no path member" — but a list can also terminate
	// with an ErrorResponse, e.g. a denied root reported after the fact, and that error
	// object DOES carry a path when the failure names one.
	errTerminator := marshal(t, ErrorResponse{
		Proto: proto, Status: statusError, Code: "path_denied", Path: "/sdcard/NOPE", PathB64: "L3NkY2FyZC9OT1BF", Message: "denied",
	})

	decoded := map[string]any{}
	if err := json.Unmarshal([]byte(errTerminator), &decoded); err != nil {
		t.Fatalf("decode: %v", err)
	}

	if _, ok := decoded["path"]; !ok {
		t.Fatal("the fixture error terminator does not carry path; the test proves nothing")
	}

	// A consumer following the old "no path member" rule would read this object as a file
	// record: PathB64 "" (since a FileRecordResponse decode would look for path_b64 anyway,
	// but the point stands for any decoder keyed on path's absence), Size 0, Mtime 0 — and it
	// would silently lose Code. The safe rule is the one below: status's presence, not
	// path's absence, marks this object as a terminator rather than a record.
	if _, ok := decoded["status"]; !ok {
		t.Fatal("the fixture error terminator does not carry status; the new rule has nothing to check")
	}

	record := marshal(t, FileRecordResponse{Path: "/sdcard/DCIM/a.JPG"})

	decodedRecord := map[string]any{}
	if err := json.Unmarshal([]byte(record), &decodedRecord); err != nil {
		t.Fatalf("decode record: %v", err)
	}

	if _, ok := decodedRecord["status"]; ok {
		t.Error("a file record carries a status member; the discriminator no longer distinguishes anything")
	}
}

func TestFetchFramingBytes(t *testing.T) {
	header := marshal(t, FetchHeader{Proto: proto, Op: "fetch", Size: 103159})
	if want := `{"proto":1,"op":"fetch","size":103159}` + "\n"; header != want {
		t.Errorf("header\n got: %q\nwant: %q", header, want)
	}

	trailer := marshal(t, FetchTrailer{Status: statusOK, Bytes: 103159, SHA256: "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"})
	want := `{"status":"ok","bytes":103159,"sha256":"e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"}` + "\n"

	if trailer != want {
		t.Errorf("trailer\n got: %q\nwant: %q", trailer, want)
	}
}

func TestErrorResponseBytes(t *testing.T) {
	got := marshal(t, ErrorResponse{
		Proto:   proto,
		Status:  statusError,
		Code:    "root_not_found",
		Path:    "/sdcard/NOPE",
		PathB64: "L3NkY2FyZC9OT1BF",
		Message: "no such file or directory",
	})

	want := `{"proto":1,"status":"error","code":"root_not_found","path":"/sdcard/NOPE","path_b64":"L3NkY2FyZC9OT1BF","message":"no such file or directory"}` + "\n"

	if got != want {
		t.Errorf("\n got: %q\nwant: %q", got, want)
	}
}

func TestErrorResponseOmitsThePathWhenTheFailureNamesNone(t *testing.T) {
	// Defect C, part 2: PathB64 must disappear under exactly the condition Path does, via
	// the same omitzero tag, or a consumer would have to work out whether a missing PathB64
	// alongside a missing Path means "no path" or "the broker forgot to encode it".
	got := marshal(t, ErrorResponse{Proto: proto, Status: statusError, Code: "no_device", Message: "no device is attached"})

	want := `{"proto":1,"status":"error","code":"no_device","message":"no device is attached"}` + "\n"

	if got != want {
		t.Errorf("\n got: %q\nwant: %q", got, want)
	}
}

func TestHTMLIsNotEscapedInAPath(t *testing.T) {
	// A device filename may legitimately contain these three bytes, and encoding/json escapes
	// all of them by default. A consumer comparing the path it asked for against the path it
	// received would see them differ.
	got := marshal(t, FileRecordResponse{Path: "/sdcard/DCIM/Camera/a<b>&c.JPG"})

	if !strings.Contains(got, `"/sdcard/DCIM/Camera/a<b>&c.JPG"`) {
		t.Errorf("the path was escaped: %s", got)
	}
}

func TestEveryObjectIsOneLine(t *testing.T) {
	// The framing is line-based: one object, one newline, nothing else. An encoder that
	// indented would break every consumer at once.
	for _, v := range []any{
		ProbeResponse{},
		FileRecordResponse{Path: "/sdcard/DCIM/a.JPG"},
		ListSummaryResponse{Errors: []PathErrorResponse{{Code: "permission_denied", Path: "/sdcard/DCIM/b"}}},
		FetchHeader{},
		FetchTrailer{},
		VerifyResponse{},
		ErrorResponse{},
	} {
		got := marshal(t, v)

		if strings.Count(got, "\n") != 1 || !strings.HasSuffix(got, "\n") {
			t.Errorf("%T is not exactly one line: %q", v, got)
		}
	}
}

func TestRequestStructsHoldPrimitivesOnly(t *testing.T) {
	// The App layer's edge is primitives. This is asserted mechanically because the failure
	// mode is invisible: a strong type in a request struct compiles, works, and moves parsing
	// out of the one place it is supposed to live.
	for _, req := range []any{ProbeRequest{}, ListRequest{}, FetchRequest{}, VerifyRequest{}} {
		assertPrimitiveFields(t, req)
	}
}

func TestResponseStructsHoldPrimitivesOnly(t *testing.T) {
	for _, res := range []any{
		ProbeResponse{},
		FileRecordResponse{},
		PathErrorResponse{},
		ListSummaryResponse{},
		FetchHeader{},
		FetchTrailer{},
		VerifyResponse{},
		ErrorResponse{},
	} {
		assertPrimitiveFields(t, res)
	}
}

// assertPrimitiveFields fails if any field of v, or of a struct nested inside it, is anything
// other than a primitive or a slice of primitives.
//
// It is deliberately a whitelist. The types it rejects are the interesting ones: a
// devicepath.AuthorizedPath, a serial.Serial, an mtime.Mtime or a devicepath.Volume in one of
// these structs would compile and marshal, and the wire format would then be whatever that
// type's MarshalJSON happens to do — decided somewhere other than wire.go.
func assertPrimitiveFields(t *testing.T, v any) {
	t.Helper()

	typ := reflect.TypeOf(v)
	if typ.Kind() != reflect.Struct {
		t.Fatalf("%T is not a struct", v)
	}

	for i := range typ.NumField() {
		field := typ.Field(i)

		ft := field.Type
		if ft.Kind() == reflect.Slice {
			ft = ft.Elem()
		}

		switch ft.Kind() {
		case reflect.String, reflect.Bool, reflect.Int, reflect.Int64, reflect.Uint64:
			continue

		case reflect.Struct:
			// A nested struct is allowed only when it is itself made of primitives, which is
			// what lets a summary carry its errors array.
			if ft.PkgPath() != typ.PkgPath() {
				t.Errorf("%s.%s is %s, which is defined outside this package", typ.Name(), field.Name, ft)

				continue
			}

			assertPrimitiveFields(t, reflect.New(ft).Elem().Interface())

		default:
			t.Errorf("%s.%s is %s, which is not a primitive", typ.Name(), field.Name, ft)
		}
	}
}
