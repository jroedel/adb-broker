package adbwire

import (
	"bytes"
	"context"
	"errors"
	"io"
	"testing"
	"time"
)

// The tests in adbwire_test.go and sync_test.go cover protocol-SHAPE failures:
// a malformed header, a bad length, a FAIL reply. Every one of those is a
// complete, well-formed (if unwelcome) exchange.
//
// This file covers a different failure: the socket dying for real, mid
// exchange, so the bytes read so far were genuine and the NEXT read simply
// never arrives. The desync this class of bug produces has bitten the project
// twice already — see the "MEASURED LANDMINE" comment on List's DONE handling
// — so the assertion that matters here is not "the call returned an error" (a
// stray partial read could satisfy that too) but "the session is unusable
// afterwards": every later call must fail fast with ErrSyncSessionDead rather
// than reading stray bytes off a socket that no longer has any.

// TestSyncDiesMidHeaderMarksSessionDead covers the socket closing after only
// part of a sync reply's 8-byte header arrived. This is the desync case in its
// purest form: the reply had begun, so there is no FAIL and no malformed
// length to key off, only a read that will never complete.
func TestSyncDiesMidHeaderMarksSessionDead(t *testing.T) {
	const path = "/sdcard/DCIM"

	// Three of the eight header bytes, then the fake closes the connection:
	// serve() has nothing left to do once this step finishes. A non-zero,
	// short write is what turns the client's read into io.ErrUnexpectedEOF
	// rather than a plain io.EOF — the two are already told apart at the host
	// layer (TestServerClosesWithZeroBytes), so this is the sync layer's half
	// of the same distinction.
	sc := newSyncFake(t, []step{{
		want: syncPathReq(syncLstat, path),
		send: []byte(syncLstat)[:3],
	}})

	ctx := t.Context()

	_, err := sc.Lstat(ctx, path)
	if err == nil {
		t.Fatal("Lstat: want an error when the header arrives half-written, got nil")
	}

	if !errors.Is(err, ErrProtocol) {
		t.Errorf("err = %v, want it to wrap ErrProtocol", err)
	}

	if !errors.Is(err, ErrSyncSessionDead) {
		t.Fatalf("err = %v, want it to wrap ErrSyncSessionDead: a header cut short leaves no way to know what would have followed it", err)
	}

	assertSessionUnusable(t, sc, path)
}

// TestSyncDiesMidLIS2StreamMarksSessionDead covers a directory listing that
// stops after one genuine entry. The entry the fake sent IS real — this is not
// a malformed record — so a reader that failed to notice the death here would
// not error at all: it would report a one-entry directory and call it a
// complete listing, which is exactly the "confident, silent, wrong answer" the
// DONE-body comment in sync.go warns about.
func TestSyncDiesMidLIS2StreamMarksSessionDead(t *testing.T) {
	const dir = "/sdcard/DCIM"

	camera := measuredDirStat
	camera.Ino = 4813

	sc := newSyncFake(t, []step{{
		want: syncPathReq(syncList, dir),
		// One complete, valid DNT2 record. No DONE, no second record: the
		// fake closes here, mid-stream rather than mid-record.
		send: dentRecord(camera, []byte("Camera")),
	}})

	ctx := t.Context()

	var names []string

	err := sc.List(ctx, dir, func(d Dirent) error {
		names = append(names, string(d.Name))

		return nil
	})
	if err == nil {
		t.Fatal("List: want an error when the stream ends before DONE, got nil")
	}

	if !errors.Is(err, ErrSyncSessionDead) {
		t.Fatalf("err = %v, want it to wrap ErrSyncSessionDead", err)
	}

	// The one entry that really did arrive must still be reported: the
	// caller's callback ran for real data, and swallowing that on the way to
	// the error would lose a file the walk actually saw.
	if len(names) != 1 || names[0] != "Camera" {
		t.Errorf("names = %q, want [Camera]: the entry before the death is real and must reach the caller", names)
	}

	assertSessionUnusable(t, sc, dir)
}

// TestSyncDiesMidRecvPayloadMarksSessionDead covers a DATA chunk that is
// announced (a real header naming a real length) and then cut off partway
// through its bytes. Recv's signature returns (int64, error), and the byte
// count is exactly what a caller uses to know how much of the destination is
// trustworthy — so the assertion that matters is that the count reflects only
// the FULLY delivered chunk, not the cut one.
func TestSyncDiesMidRecvPayloadMarksSessionDead(t *testing.T) {
	const path = "/sdcard/DCIM/Camera/example.jpg"

	first := []byte("complete-chunk")         // delivered whole, and must be counted
	second := bytes.Repeat([]byte{0x7f}, 100) // announced at 100 bytes, cut at 40

	announced := recvData(second)

	sc := newSyncFake(t, []step{{
		want: syncPathReq(syncRecv, path),
		send: concat(recvData(first), announced[:len(announced)-len(second)+40]),
	}})

	ctx := t.Context()

	var buf bytes.Buffer

	n, err := sc.Recv(ctx, path, &buf)
	if err == nil {
		t.Fatal("Recv: want an error when a DATA chunk is cut short, got nil")
	}

	if !errors.Is(err, ErrSyncSessionDead) {
		t.Fatalf("err = %v, want it to wrap ErrSyncSessionDead", err)
	}

	if n != int64(len(first)) {
		t.Errorf("Recv returned n=%d, want %d: only the chunk that arrived in full may be counted", n, len(first))
	}

	if buf.String() != string(first) {
		t.Errorf("written = %q, want only the complete first chunk %q", buf.String(), first)
	}

	assertSessionUnusable(t, sc, path)
}

// TestSyncAlreadyCancelledContextMarksSessionDead covers the other named gap:
// a context that is already Done() before the first byte goes on the wire.
// armDeadline refuses it before touching the socket at all, so the fake here
// is given no script — any write would fail the test outright — and the
// assertion is the same as the transport-death cases: this is not merely a
// failed call, the session must come out of it unusable, exactly as if the
// device had vanished mid-exchange.
func TestSyncAlreadyCancelledContextMarksSessionDead(t *testing.T) {
	sc := newSyncFake(t, nil)

	canceledCtx, cancel := context.WithCancel(t.Context())
	cancel()

	const path = "/sdcard/DCIM"

	_, err := sc.Lstat(canceledCtx, path)
	if err == nil {
		t.Fatal("Lstat: want an error for an already-cancelled context, got nil")
	}

	if !errors.Is(err, context.Canceled) {
		t.Errorf("err = %v, want it to wrap context.Canceled", err)
	}

	if !errors.Is(err, ErrProtocol) {
		t.Errorf("err = %v, want it to wrap ErrProtocol", err)
	}

	if !errors.Is(err, ErrSyncSessionDead) {
		t.Fatalf("err = %v, want it to wrap ErrSyncSessionDead: a call refused before it wrote anything must still retire the session, "+
			"since a caller cannot tell that case apart from one where a byte or two escaped onto the wire first", err)
	}

	// A live context this time, so a stray success here could only mean the
	// dead flag was never actually set.
	assertSessionUnusable(t, sc, path)
}

// assertSessionUnusable proves sc is retired: every remaining sync method must
// fail fast with ErrSyncSessionDead. The fake server is long gone or has no
// script left by the time this runs, so a call that instead tries the network
// would either hang until the fake's own 10-second deadline or desync against
// whatever is left on a closed socket — either way, a correct implementation
// never gets that far, which is what the elapsed-time check is for.
func assertSessionUnusable(t *testing.T, sc *SyncConn, path string) {
	t.Helper()

	start := time.Now()

	calls := map[string]func() error{
		"Lstat": func() error { _, err := sc.Lstat(t.Context(), path); return err },
		"Stat":  func() error { _, err := sc.Stat(t.Context(), path); return err },
		"List":  func() error { return sc.List(t.Context(), path, func(Dirent) error { return nil }) },
		"Recv":  func() error { _, err := sc.Recv(t.Context(), path, io.Discard); return err },
	}

	for name, call := range calls {
		if err := call(); !errors.Is(err, ErrSyncSessionDead) {
			t.Errorf("%s after the session died = %v, want ErrSyncSessionDead", name, err)
		}
	}

	if elapsed := time.Since(start); elapsed > time.Second {
		t.Errorf("the follow-up calls took %v; a dead session must fail fast, not touch the network", elapsed)
	}
}
