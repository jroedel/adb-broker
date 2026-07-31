package adbsyncdb

import (
	"errors"
	"io"
	"testing"

	"github.com/jroedel/adb-broker/business/types/devicepath"
	"github.com/jroedel/adb-broker/business/types/errcode"
)

// This file covers the one path adbsyncdb_test.go's reconnect coverage stops
// short of: a RECV failure whose automatic rebuild ALSO fails. See reconnect.go
// for why the rebuild happens at all, and adbsyncdb.go's Fetch for the
// errors.Join branch this exercises.
//
// The two single-failure halves are already covered elsewhere:
// TestFetchRecvFailureReconnectsOnce (adbsyncdb_test.go) is the RECV-fails,
// rebuild-succeeds case, and TestProbeMapsWireSentinels covers a bare dial
// failure with no RECV involved. Neither puts both failures on the same call.

// errRecvGone and errDialGone are local sentinels standing in for whatever the
// device and the adb server would actually say. Using our own, rather than
// adbwire's prose, is what lets the assertions below tell the two failures
// apart unambiguously: a real RECV FAIL message and a real dial error do not
// share any substring, but a test should not rely on that.
var (
	errRecvGone = errors.New("simulated: the device pulled away mid-transfer")
	errDialGone = errors.New("simulated: the adb server stopped answering")
)

// TestFetchDoubleFailureJoinsBothCauses is the double failure: RECV fails, and
// the automatic rebuild that follows it ALSO fails, because the dial itself is
// now the thing that is broken (measured shape of a phone unplugged mid-run:
// the adb server stays up, but the transport underneath it is gone). The
// caller must not lose either half — a per-file transfer_failed reads as "skip
// this one file," while the rebuild's own failure is what says the device
// itself is gone, and a consumer needs both to react correctly.
func TestFetchDoubleFailureJoinsBothCauses(t *testing.T) {
	st, tr := newTestStore()

	// Establish one real session first, exactly as a normal run would: dial
	// succeeds, the volume is pinned. Only after that does the dial start
	// failing — otherwise the very first connect would fail and there would be
	// no live session for the RECV below to kill in the first place.
	vol := pinVolume(t, st)

	const path = testRoot + "/Camera/IMG_0001.jpg"

	tr.fs.lstat[path] = regularStat(10, devMedia)
	tr.fs.recvErr[path] = errRecvGone

	dialsBefore := tr.dials

	// Now the transport itself is gone: the reconnect that RECV triggers must
	// fail too.
	tr.dialErr = errDialGone

	_, err := st.Fetch(t.Context(), devicepath.MustParseAuthorizedPath(path), vol, io.Discard, nil)
	if err == nil {
		t.Fatal("Fetch: want an error when both the transfer and the rebuild fail, got nil")
	}

	// Both failures must survive the join. A consumer diagnosing this later
	// needs to find the RECV cause (which file, which reason) AND the rebuild's
	// own cause (why the device could not be reached again) — losing either
	// one to the errors.Join plumbing would leave a half-explained abort.
	if !errors.Is(err, errRecvGone) {
		t.Errorf("err = %v, want it to wrap the RECV failure %v", err, errRecvGone)
	}

	if !errors.Is(err, errDialGone) {
		t.Errorf("err = %v, want it to wrap the reconnect's own dial failure %v", err, errDialGone)
	}

	// The rebuild really was attempted, exactly once, and it really dialled.
	if st.reconnects != 1 {
		t.Errorf("reconnects = %d, want exactly 1", st.reconnects)
	}

	if tr.dials != dialsBefore+1 {
		t.Errorf("dials = %d, want %d: the rebuild must still be attempted even though it is doomed", tr.dials, dialsBefore+1)
	}

	// The double failure must classify as fatal, not as transfer_failed. Fetch now
	// derives `code` from the reconnect's own outcome once reconnectLocked has run: rerr
	// here is a dial failure with no adbwire sentinel attached, so connectLocked's
	// codeForWire(err, errcode.CodeInternal) falls through to its fallback, and that is
	// what errcode.From reads back. Any of the rebuild's other failure modes
	// (CodeNoADBServer, CodeUnauthorized, CodeOffline, CodeNoDevice, CodeMultipleDevices,
	// CodeUnsupported) would equally satisfy "fatal" — this test pins the one this fixture
	// actually produces.
	if got := errcode.From(err); got != errcode.CodeInternal {
		t.Errorf("errcode.From(err) = %s, want %s", got, errcode.CodeInternal)
	}

	if !errcode.From(err).Fatal() {
		t.Error("a double failure (RECV failed AND the rebuild failed) must classify as fatal: the reconnect's own failure is evidence about the device or the server, not about the one file being fetched")
	}
}

// TestFetchSingleFailureStillReportsTransferFailed is the contrasting half of the double
// failure above: RECV fails but the automatic rebuild that follows it SUCCEEDS. This must
// keep reporting errcode.CodeTransferFailed exactly as before — "skip this one file, keep
// going" is the correct and only classification once the transport has proven it still
// works. (TestFetchRecvFailureReconnectsOnce in adbsyncdb_test.go already covers this same
// behaviour end to end; this copy lives here too because it is the fix's control case: it
// is what would break if Fetch's new code-selection logic reached into the successful
// reconnect branch instead of leaving it alone.)
func TestFetchSingleFailureStillReportsTransferFailed(t *testing.T) {
	st, tr := newTestStore()
	vol := pinVolume(t, st)

	const path = testRoot + "/Camera/IMG_0001.jpg"

	tr.fs.lstat[path] = regularStat(10, devMedia)
	tr.fs.recvErr[path] = errRecvGone

	dialsBefore := tr.dials

	_, err := st.Fetch(t.Context(), devicepath.MustParseAuthorizedPath(path), vol, io.Discard, nil)
	if err == nil {
		t.Fatal("Fetch: want an error when RECV fails, got nil")
	}

	if got := errcode.From(err); got != errcode.CodeTransferFailed {
		t.Errorf("errcode.From(err) = %s, want %s: the rebuild succeeded, so this is still one file's failure, not the device's", got, errcode.CodeTransferFailed)
	}

	if st.reconnects != 1 {
		t.Errorf("reconnects = %d, want exactly 1", st.reconnects)
	}

	if tr.dials != dialsBefore+1 {
		t.Errorf("dials = %d, want %d", tr.dials, dialsBefore+1)
	}
}
