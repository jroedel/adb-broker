package broker

import (
	"encoding/base64"
	"errors"
	"os/user"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/jroedel/adb-broker/business/domain/device/devicebus"
	"github.com/jroedel/adb-broker/business/types/devicepath"
	"github.com/jroedel/adb-broker/business/types/errcode"
	"github.com/jroedel/adb-broker/business/types/filekind"
	"github.com/jroedel/adb-broker/business/types/mtime"
	"github.com/jroedel/adb-broker/business/types/serial"
	"github.com/jroedel/adb-broker/foundation/errs"
)

func TestToBusListRequestParsesEveryFlag(t *testing.T) {
	in, err := toBusListRequest(ListRequest{
		Root:     "/sdcard/DCIM/Camera",
		Serial:   "EXAMPLESERIAL1",
		Client:   "photos",
		MaxDepth: 1,
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	switch {
	case in.list.Root.String() != "/sdcard/DCIM/Camera":
		t.Errorf("root = %q", in.list.Root.String())
	case in.list.Serial.String() != "EXAMPLESERIAL1":
		t.Errorf("serial = %q", in.list.Serial.String())
	case in.list.MaxDepth != 1:
		t.Errorf("max-depth = %d", in.list.MaxDepth)
	case in.client != "photos":
		t.Errorf("client = %q", in.client)
	}
}

func TestToBusListRequestAccumulatesEveryFailure(t *testing.T) {
	_, err := toBusListRequest(ListRequest{
		Root:     "/etc/passwd",
		Serial:   "not a serial",
		Client:   "not a client",
		MaxDepth: -3,
	})

	fes, ok := errs.IsFieldErrors(err)
	if !ok {
		t.Fatalf("error is %T, want errs.FieldErrors", err)
	}

	want := []string{"root", "serial", "client", "max-depth"}
	if got := fes.Fields(); !slices.Equal(got, want) {
		t.Errorf("fields = %v, want %v in the order the converter checked them", got, want)
	}
}

func TestToBusListRequestKeepsTheClassificationDevicepathDecided(t *testing.T) {
	// The App layer does not decide that a denied path is path_denied. devicepath's own
	// rejection carries the code, and errcode.From reads it back through the Coder contract —
	// even from inside an errs.FieldErrors, which unwraps to every failure it accumulated.
	_, err := toBusListRequest(ListRequest{Root: "/data/data"})

	if !errors.Is(err, devicepath.ErrPathDenied) {
		t.Errorf("error %v does not match devicepath.ErrPathDenied", err)
	}

	if got := requestCode(err); got != errcode.CodePathDenied {
		t.Errorf("requestCode = %s, want path_denied", got)
	}
}

func TestRequestCodeClassifiesAValidationFailureThatCarriesNoCode(t *testing.T) {
	// An unknown flag or an unacceptable value is unsupported. internal — which errcode.From
	// returns for an unclassified error — would be wrong: internal means the broker itself
	// failed, and a caller reading it would look in the wrong place.
	_, err := toBusProbeRequest(ProbeRequest{Serial: "not a serial"})

	if got := requestCode(err); got != errcode.CodeUnsupported {
		t.Errorf("requestCode = %s, want unsupported", got)
	}
}

func TestRequestCodeLeavesANonValidationFailureAsInternal(t *testing.T) {
	if got := requestCode(errors.New("something nobody classified")); got != errcode.CodeInternal {
		t.Errorf("requestCode = %s, want internal", got)
	}
}

func TestToBusRootDistinguishesMissingFromDenied(t *testing.T) {
	_, missing := toBusListRequest(ListRequest{Root: ""})
	_, denied := toBusListRequest(ListRequest{Root: "/etc"})

	if got := requestCode(missing); got != errcode.CodeUnsupported {
		t.Errorf("an absent --root is %s, want unsupported: it is a usage mistake, not a confinement decision", got)
	}

	if got := requestCode(denied); got != errcode.CodePathDenied {
		t.Errorf("a denied --root is %s, want path_denied", got)
	}
}

func TestToBusSerialTreatsAnAbsentFlagAsTheOneAttachedDevice(t *testing.T) {
	ser, err := toBusSerial("")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if !ser.IsZero() {
		t.Error("an absent --serial did not produce the zero Serial")
	}
}

func TestToClientLabel(t *testing.T) {
	for _, tc := range []struct {
		name    string
		label   string
		accepts bool
	}{
		{"absent", "", true},
		{"a plain name", "photos", true},
		{"every accepted byte class", "abcXYZ019._-", true},
		{"exactly the limit", strings.Repeat("p", maxClientBytes), true},
		{"one over the limit", strings.Repeat("p", maxClientBytes+1), false},
		{"a space", "a b", false},
		{"a slash", "a/b", false},
		{"a colon", "a:b", false},
		{"a NUL", "a\x00b", false},
		{"a newline", "a\nb", false},
		{"a multi-byte rune", "phötos", false},
		{"a percent", "photos%s", false},
	} {
		got, err := toClientLabel(tc.label)

		switch {
		case tc.accepts && err != nil:
			t.Errorf("%s: unexpected error: %v", tc.name, err)

		case tc.accepts && got != tc.label:
			t.Errorf("%s: label = %q, want it returned unchanged", tc.name, got)

		case !tc.accepts && err == nil:
			t.Errorf("%s: accepted %q; the rule is reject, never sanitize", tc.name, tc.label)

		case !tc.accepts && got != "":
			t.Errorf("%s: returned %q alongside an error; a rejected label must not be usable", tc.name, got)
		}
	}
}

func TestFromBusDeviceResponse(t *testing.T) {
	res := fromBusDeviceResponse(devicebus.Device{
		Serial:        serial.MustParseSerial("EXAMPLESERIAL1"),
		State:         "unauthorized",
		BrokerVersion: "0.1.0",
		ServerVersion: "1.0.41",
		Features:      []string{"stat_v2", "ls_v2", "sendrecv_v2"},
	})

	switch {
	case res.Proto != proto:
		t.Errorf("proto = %d", res.Proto)
	case res.Status != statusOK:
		t.Errorf("status = %q", res.Status)
	case res.State != "unauthorized":
		t.Errorf("state = %q, want the token verbatim", res.State)
	case res.Serial != "EXAMPLESERIAL1":
		t.Errorf("serial = %q", res.Serial)
	case res.Broker != "0.1.0" || res.ADB != "1.0.41":
		t.Errorf("broker = %q, adb = %q", res.Broker, res.ADB)
	}
}

func TestFromBusFileRecordResponse(t *testing.T) {
	rec := devicebus.FileRecord{
		Path:  devicepath.MustParseAuthorizedPath("/sdcard/DCIM/Camera/IMG_0182.JPG"),
		Size:  103159,
		Mtime: mtime.ParseMtime(1709828653),
		Kind:  filekind.KindRegular,
	}

	res := fromBusFileRecordResponse(rec)

	switch {
	case res.Path != "/sdcard/DCIM/Camera/IMG_0182.JPG":
		t.Errorf("path = %q", res.Path)
	case res.PathB64 != "L3NkY2FyZC9EQ0lNL0NhbWVyYS9JTUdfMDE4Mi5KUEc=":
		t.Errorf("path_b64 = %q", res.PathB64)
	case res.Size != 103159:
		t.Errorf("size = %d", res.Size)
	case res.Mtime != 1709828653:
		t.Errorf("mtime = %d, want the device's own whole seconds", res.Mtime)
	}
}

func TestFromBusFileRecordResponseReportsMtimeExactlyAsTheDeviceDid(t *testing.T) {
	// No normalization, no timezone adjustment, no reconciliation with anything. A negative
	// value is a pre-1970 mtime, which is unusual and not invalid, and zero is a real value the
	// device reports. The consumer's incremental fast path depends only on the same file
	// reporting the same number twice.
	for _, sec := range []int64{-86400, -1, 0, 1, 1709828653, 1 << 40} {
		rec := devicebus.FileRecord{
			Path:  devicepath.MustParseAuthorizedPath("/sdcard/DCIM/Camera/x.JPG"),
			Mtime: mtime.ParseMtime(sec),
		}

		if got := fromBusFileRecordResponse(rec).Mtime; got != sec {
			t.Errorf("mtime = %d, want %d", got, sec)
		}
	}
}

func TestFromBusFileRecordResponseCoercesOnlyTheHumanReadablePath(t *testing.T) {
	raw := "/sdcard/DCIM/Camera/IMG_\xff\xfe.JPG"

	res := fromBusFileRecordResponse(devicebus.FileRecord{
		Path: devicepath.MustParseAuthorizedPath(raw),
	})

	decoded, err := base64.StdEncoding.DecodeString(res.PathB64)
	if err != nil {
		t.Fatalf("decode path_b64: %v", err)
	}

	if string(decoded) != raw {
		t.Errorf("path_b64 decodes to %q, want the raw bytes %q", decoded, raw)
	}

	if res.Path == raw {
		t.Error("path carries the raw bytes; a JSON string cannot, so it must be coerced here")
	}

	if !strings.Contains(res.Path, "�") {
		t.Errorf("path = %q, want the invalid bytes replaced", res.Path)
	}
}

func TestFromBusListSummaryResponse(t *testing.T) {
	for _, tc := range []struct {
		name   string
		sum    devicebus.ListSummary
		status string
		errors int
	}{
		{
			name:   "nothing failed",
			sum:    devicebus.ListSummary{Files: 3},
			status: statusOK,
		},
		{
			name:   "refused entries only",
			sum:    devicebus.ListSummary{Files: 3, RefusedEntries: 9},
			status: statusOK,
		},
		{
			name: "one path failed",
			sum: devicebus.ListSummary{Files: 3, Errors: []devicebus.PathError{
				{Path: devicepath.MustParseAuthorizedPath("/sdcard/DCIM/locked"), Code: errcode.CodePermissionDenied},
			}},
			status: statusPartial,
			errors: 1,
		},
		{
			name: "nothing listed and one path failed",
			sum: devicebus.ListSummary{Errors: []devicebus.PathError{
				{Path: devicepath.MustParseAuthorizedPath("/sdcard/DCIM/locked"), Code: errcode.CodePermissionDenied},
			}},
			status: statusPartial,
			errors: 1,
		},
	} {
		res := fromBusListSummaryResponse(tc.sum)

		switch {
		case res.Status != tc.status:
			t.Errorf("%s: status = %q, want %q", tc.name, res.Status, tc.status)

		case len(res.Errors) != tc.errors:
			t.Errorf("%s: %d errors, want %d", tc.name, len(res.Errors), tc.errors)

		case res.Errors == nil:
			t.Errorf("%s: errors is nil, and would marshal as null rather than []", tc.name)

		case res.Files != tc.sum.Files:
			t.Errorf("%s: files = %d, want %d", tc.name, res.Files, tc.sum.Files)
		}
	}
}

func TestFromBusListSummaryResponseRoundTripsANonUTF8Path(t *testing.T) {
	// Defect C, part 1. Before the fix PathErrorResponse had no path_b64, so a per-path
	// error naming a filename that is not valid UTF-8 could not be acted on: Path is
	// necessarily lossy for such a name, and there was no authoritative companion. This
	// mirrors TestFromBusFileRecordResponseCoercesOnlyTheHumanReadablePath, which already
	// establishes that /sdcard/DCIM/Camera accepts a non-UTF-8 leaf name.
	raw := "/sdcard/DCIM/Camera/locked_\xff\xfe"

	sum := devicebus.ListSummary{Errors: []devicebus.PathError{
		{Path: devicepath.MustParseAuthorizedPath(raw), Code: errcode.CodePermissionDenied},
	}}

	res := fromBusListSummaryResponse(sum)
	if len(res.Errors) != 1 {
		t.Fatalf("got %d errors, want 1", len(res.Errors))
	}

	pe := res.Errors[0]

	if pe.Path == raw {
		t.Error("path carries the raw bytes; a JSON string cannot, so it must be coerced")
	}

	if !strings.Contains(pe.Path, "�") {
		t.Errorf("path = %q, want the invalid bytes replaced", pe.Path)
	}

	decoded, err := base64.StdEncoding.DecodeString(pe.PathB64)
	if err != nil {
		t.Fatalf("decode path_b64: %v", err)
	}

	if string(decoded) != raw {
		t.Errorf("path_b64 decodes to %q, want the raw bytes %q", decoded, raw)
	}
}

func TestFromBusListSummaryResponseCarriesTheCodeEachPathFailureDecided(t *testing.T) {
	sum := devicebus.ListSummary{Errors: []devicebus.PathError{
		{Path: devicepath.MustParseAuthorizedPath("/sdcard/DCIM/a"), Code: errcode.CodePermissionDenied},
		{Path: devicepath.MustParseAuthorizedPath("/sdcard/DCIM/b"), Code: errcode.CodePathNotFound},
	}}

	res := fromBusListSummaryResponse(sum)

	if res.Errors[0].Code != "permission_denied" || res.Errors[1].Code != "path_not_found" {
		t.Errorf("codes = %q and %q", res.Errors[0].Code, res.Errors[1].Code)
	}
}

func TestFromBusFetchResultResponse(t *testing.T) {
	res := fromBusFetchResultResponse(devicebus.FetchResult{
		Bytes:  103159,
		SHA256: "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
		Serial: serial.MustParseSerial("EXAMPLESERIAL1"),
	})

	switch {
	case res.Status != statusOK:
		t.Errorf("status = %q", res.Status)
	case res.Bytes != 103159:
		t.Errorf("bytes = %d", res.Bytes)
	case res.SHA256 != "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855":
		t.Errorf("sha256 = %q", res.SHA256)
	}
}

func TestDisplayBytesReplacesOnlyWhatItMust(t *testing.T) {
	for _, tc := range []struct{ in, want string }{
		{"/sdcard/DCIM/Camera/IMG_0182.JPG", "/sdcard/DCIM/Camera/IMG_0182.JPG"},
		{"/sdcard/DCIM/Camera/naïve.JPG", "/sdcard/DCIM/Camera/naïve.JPG"},
		{"/sdcard/DCIM/Camera/a<b>&c.JPG", "/sdcard/DCIM/Camera/a<b>&c.JPG"},
		{"", ""},
		{"\xff", "�"},
	} {
		if got := displayBytes(tc.in); got != tc.want {
			t.Errorf("displayBytes(%q) = %q, want %q", tc.in, got, tc.want)
		}
	}
}

func TestToVerifyInput(t *testing.T) {
	in, err := toVerifyInput(VerifyRequest{LogPath: "/var/log/adb-broker/audit.log", AnchorsPath: "-"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if !in.fromStdin {
		t.Error(`--anchors - was not read as the stdin form`)
	}

	if _, err := toVerifyInput(VerifyRequest{LogPath: "/x"}); err == nil {
		t.Error("an absent --anchors was accepted; the anchor comparison is the only truncation check there is")
	}

	if _, err := toVerifyInput(VerifyRequest{AnchorsPath: "-"}); err == nil {
		t.Error("an empty --log was accepted")
	}
}

func TestFromBusErrorResponse(t *testing.T) {
	res := fromBusErrorResponse(errcode.CodeRootNotFound, "/sdcard/NOPE", errors.New("no such file or directory"))

	switch {
	case res.Proto != proto:
		t.Errorf("proto = %d", res.Proto)
	case res.Status != statusError:
		t.Errorf("status = %q", res.Status)
	case res.Code != "root_not_found":
		t.Errorf("code = %q", res.Code)
	case res.Path != "/sdcard/NOPE":
		t.Errorf("path = %q", res.Path)
	case res.PathB64 != "L3NkY2FyZC9OT1BF":
		t.Errorf("path_b64 = %q", res.PathB64)
	case res.Message != "no such file or directory":
		t.Errorf("message = %q", res.Message)
	}
}

func TestFromBusErrorResponseOmitsBothPathMembersForAnEmptyRawPath(t *testing.T) {
	// rawPath == "" means the failure names no path at all, not an empty one: Path and
	// PathB64 must both come out zero, or the omitzero tags on ErrorResponse would disagree
	// with each other about whether a path was named.
	res := fromBusErrorResponse(errcode.CodeNoDevice, "", errors.New("no device is attached"))

	if res.Path != "" {
		t.Errorf("path = %q, want empty", res.Path)
	}

	if res.PathB64 != "" {
		t.Errorf("path_b64 = %q, want empty", res.PathB64)
	}
}

func TestFromBusErrorResponseThreadsTheRawBytesRatherThanReDerivingThem(t *testing.T) {
	// Defect C, part 2, and the whole difficulty of that fix: rawPath must reach this
	// converter BEFORE displayBytes has coerced it, so Path and PathB64 are built from the
	// same string. If a caller instead coerced first and handed this converter the coerced
	// string, PathB64 would decode to bytes containing U+FFFD rather than the raw path the
	// operation actually named — which looks authoritative and is not.
	raw := "/sdcard/DCIM/Camera/locked_\xff\xfe"

	res := fromBusErrorResponse(errcode.CodePermissionDenied, raw, errors.New("denied"))

	if res.Path == raw {
		t.Error("path carries the raw bytes; a JSON string cannot, so it must be coerced")
	}

	if !strings.Contains(res.Path, "�") {
		t.Errorf("path = %q, want the invalid bytes replaced", res.Path)
	}

	decoded, err := base64.StdEncoding.DecodeString(res.PathB64)
	if err != nil {
		t.Fatalf("decode path_b64: %v", err)
	}

	if string(decoded) != raw {
		t.Errorf("path_b64 decodes to %q, want the raw bytes %q", decoded, raw)
	}
}

func TestTheAuditLogPathIsThisUsersOwnAndIsNotTakenFromTheEnvironment(t *testing.T) {
	// The path is derived from the passwd entry for the running uid, so this asserts the
	// shape rather than a constant: one fixed location per account, under that account's
	// home directory, which is what makes a chain and the anchors published beside it
	// describe the same file.
	got, err := auditLogPath()
	if err != nil {
		t.Fatalf("auditLogPath: %v", err)
	}

	u, err := user.Current()
	if err != nil {
		t.Fatalf("user.Current: %v", err)
	}

	if want := filepath.Join(u.HomeDir, ".local", "state", "adb-broker", "audit.log"); got != want {
		t.Errorf("auditLogPath() = %q, want %q", got, want)
	}

	// $HOME is the input this must not take. os.UserHomeDir would read it, user.Current
	// does not, and the difference is the whole reason the derivation is written the way it
	// is: a caller that can move the audit log has removed the guarantee without removing
	// the appearance of one. TestPackageSourceReadsNoEnvironment enforces the same rule
	// statically; this one proves it about the value actually produced.
	t.Setenv("HOME", filepath.Join(t.TempDir(), "not-the-real-home"))

	after, err := auditLogPath()
	if err != nil {
		t.Fatalf("auditLogPath after moving HOME: %v", err)
	}

	if after != got {
		t.Errorf("auditLogPath() followed $HOME: got %q, want %q unchanged", after, got)
	}
}
