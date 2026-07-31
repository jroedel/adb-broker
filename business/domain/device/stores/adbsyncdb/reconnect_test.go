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

	// What this test deliberately does NOT assert: a specific want for
	// errcode.From(err).
	//
	// Reading adbsyncdb.go's Fetch (the errors.Join branch, and the `code`
	// computed above it): `code` is computed from the RECV failure alone,
	// BEFORE reconnectLocked is even attempted, and is never revisited once
	// the rebuild's own outcome is known. So today this call reports
	// errcode.CodeTransferFailed — "skip this file, keep going" — even though
	// the rebuild it just ran has already discovered the device cannot be
	// reached at all. Compare walk.go's listing failures, which fall back to
	// errcode.CodeDeviceDisconnected (fatal) for the equivalent single-failure
	// case, on the documented reasoning that a dead sync channel is different
	// news for a listing than for one file. That reasoning does not extend to
	// THIS call: here the store has not merely lost the channel, it has tried
	// to rebuild it and failed, which is stronger evidence than either single
	// failure alone and should not classify as the weaker of the two.
	//
	// Asserting CodeTransferFailed here would pin exactly that misclassification
	// into a green test. See the task report for the recommendation (surface
	// the reconnect failure's own classification, e.g. via codeForWire(rerr,
	// errcode.CodeDeviceDisconnected), when rerr != nil).
	t.Logf("errcode.From(err) = %s (see comment above: this is believed to be a misclassification, not asserted as correct)", errcode.From(err))
}
