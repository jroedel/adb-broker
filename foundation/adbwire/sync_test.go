package adbwire

import (
	"bytes"
	"encoding/binary"
	"errors"
	"strings"
	"testing"
	"time"
)

// Recorded sync byte builders. As with the host builders these are written out
// by hand rather than by calling the implementation, so a framing bug cannot
// cancel itself out in the fixtures.

// syncPathReq is a 4-byte ID, a little-endian path length, and the raw path.
func syncPathReq(id, path string) []byte {
	b := make([]byte, 0, 8+len(path))
	b = append(b, id...)
	b = binary.LittleEndian.AppendUint32(b, uint32(len(path)))

	return append(b, path...)
}

// statReply is the 72-byte LST2/STA2 reply, in the measured field order.
func statReply(id string, st Stat) []byte {
	return statReplyRaw(id, st, uint64(st.Dev), uint64(st.Ino), uint64(st.Size))
}

// statReplyRaw builds the same reply with dev, ino and size supplied unsigned, so
// a value with the high bit set can be fed in.
func statReplyRaw(id string, st Stat, dev, ino, size uint64) []byte {
	le := binary.LittleEndian

	b := make([]byte, 0, syncStatLen)
	b = append(b, id...)
	b = le.AppendUint32(b, st.Errno)
	b = le.AppendUint64(b, dev)
	b = le.AppendUint64(b, ino)
	b = le.AppendUint32(b, st.Mode)
	b = le.AppendUint32(b, st.Nlink)
	b = le.AppendUint32(b, st.UID)
	b = le.AppendUint32(b, st.GID)
	b = le.AppendUint64(b, size)
	b = le.AppendUint64(b, uint64(st.Atime))
	b = le.AppendUint64(b, uint64(st.Mtime))
	b = le.AppendUint64(b, uint64(st.Ctime))

	return b
}

// dentRecord is a DNT2 record: the 72-byte stat body, a 4-byte name length, then
// the raw name bytes.
func dentRecord(st Stat, name []byte) []byte {
	b := statReply(syncDent, st)
	b = binary.LittleEndian.AppendUint32(b, uint32(len(name)))

	return append(b, name...)
}

// listDone is the LIS2 terminator. It is NOT a bare ID: it carries a fully zeroed
// 72-byte dirent body, and a reader that skips it desyncs the channel.
func listDone() []byte {
	return append([]byte(syncDone), make([]byte, syncStatLen)...)
}

// recvData is one DATA packet.
func recvData(chunk []byte) []byte {
	b := append([]byte(syncData), 0, 0, 0, 0)
	binary.LittleEndian.PutUint32(b[4:], uint32(len(chunk)))

	return append(b, chunk...)
}

// recvDone is the RECV terminator: the ID plus its four-byte zero argument, the
// way adb's own client reads it.
func recvDone() []byte {
	return append([]byte(syncDone), 0, 0, 0, 0)
}

// syncFailReply is a sync FAIL: the ID, a little-endian message length, then the
// prose. Note that the length is binary here, unlike the host layer's ASCII hex.
func syncFailReply(msg string) []byte {
	b := append([]byte(syncFail), 0, 0, 0, 0)
	binary.LittleEndian.PutUint32(b[4:], uint32(len(msg)))

	return append(b, msg...)
}

func concat(parts ...[]byte) []byte {
	var out []byte
	for _, p := range parts {
		out = append(out, p...)
	}

	return out
}

// newSyncFake returns a SyncConn talking to a fake that replays script.
func newSyncFake(t *testing.T, script []step) *SyncConn {
	t.Helper()

	f := startFakeServer(t, script)

	sc := newSyncConn(f.dial(t))
	t.Cleanup(func() { _ = sc.Close() })

	return sc
}

// measuredDirStat is a real directory from the capture: one of the allowlist
// roots, mode 0o2770 setgid, uid 10269, gid 1023, on dev 190.
var measuredDirStat = Stat{
	Errno: 0,
	Dev:   190,
	Ino:   4812,
	Mode:  0o42770,
	Nlink: 2,
	UID:   10269,
	GID:   1023,
	Size:  3452,
	Atime: 1753900000,
	Mtime: 1753900001,
	Ctime: 1753900002,
}

// TestStatDecode covers the 72-byte reply at exact field offsets, for both LST2
// and STA2. The fake asserts the request bytes, so it also proves Lstat sends
// LST2 and Stat sends STA2 — measured, those differ on /sdcard, which is a
// symlink.
func TestStatDecode(t *testing.T) {
	// The largest file measured on the device: size is genuinely 64-bit.
	const measuredLargeFile = 27190943

	tests := []struct {
		name string
		id   string
		call func(*SyncConn, *testing.T, string) (Stat, error)
		want Stat
	}{
		{
			name: "LST2 on a directory",
			id:   syncLstat,
			want: measuredDirStat,
		},
		{
			name: "STA2 on a directory",
			id:   syncStat,
			want: measuredDirStat,
		},
		{
			name: "LST2 on the measured symlink /sdcard",
			id:   syncLstat,
			want: Stat{Dev: 65034, Ino: 48, Mode: 0o120644, Nlink: 1, Size: 21, Mtime: 1753900003},
		},
		{
			name: "a 27,190,943 byte file round-trips exactly",
			id:   syncStat,
			want: Stat{Dev: 190, Ino: 99999, Mode: 0o100644, Nlink: 1, UID: 10269, GID: 1023, Size: measuredLargeFile, Mtime: 1753900004},
		},
		{
			name: "ENOENT is data, not a failure",
			id:   syncLstat,
			want: Stat{Errno: 2},
		},
		{
			name: "EACCES is data, not a failure",
			id:   syncLstat,
			want: Stat{Errno: 13},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			const path = "/sdcard/DCIM"

			sc := newSyncFake(t, []step{{
				want: syncPathReq(tc.id, path),
				send: statReply(tc.id, tc.want),
			}})

			ctx := t.Context()

			var (
				got Stat
				err error
			)

			switch tc.id {
			case syncLstat:
				got, err = sc.Lstat(ctx, path)

			default:
				got, err = sc.Stat(ctx, path)
			}

			// An in-band errno never produces an error: measured, the channel
			// stays usable after error=2 and two further commands succeeded.
			if err != nil {
				t.Fatalf("stat: %v", err)
			}

			if got != tc.want {
				t.Errorf("stat = %+v, want %+v", got, tc.want)
			}
		})
	}
}

// TestStatSurvivesInBandErrno is the channel-lifetime half of the same finding:
// an errno reply leaves the session usable, so a second command must work.
func TestStatSurvivesInBandErrno(t *testing.T) {
	const missing = "/sdcard/Download-private"

	sc := newSyncFake(t, []step{
		{want: syncPathReq(syncLstat, missing), send: statReply(syncLstat, Stat{Errno: 2})},
		{want: syncPathReq(syncLstat, "/sdcard/DCIM"), send: statReply(syncLstat, measuredDirStat)},
	})

	ctx := t.Context()

	first, err := sc.Lstat(ctx, missing)
	if err != nil {
		t.Fatalf("first Lstat: %v", err)
	}

	if first.Errno != 2 {
		t.Errorf("Errno = %d, want 2", first.Errno)
	}

	second, err := sc.Lstat(ctx, "/sdcard/DCIM")
	if err != nil {
		t.Fatalf("second Lstat on the same channel: %v", err)
	}

	if second.Ino != measuredDirStat.Ino {
		t.Errorf("Ino = %d, want %d", second.Ino, measuredDirStat.Ino)
	}
}

// TestStatHighBitFields covers the narrowing of unsigned 64-bit fields to int64.
// Real device and inode numbers are nowhere near 2^63, so this branch should
// never fire on a real device — which is exactly why it must be an error rather
// than a silent wrap to a negative number.
func TestStatHighBitFields(t *testing.T) {
	tests := map[string]struct{ dev, ino, size uint64 }{
		"dev has its high bit set":  {dev: 1 << 63, ino: 48},
		"ino has its high bit set":  {dev: 190, ino: 1 << 63},
		"size has its high bit set": {dev: 190, ino: 48, size: 0xffffffffffffffff},
	}

	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			const path = "/sdcard/DCIM"

			sc := newSyncFake(t, []step{{
				want: syncPathReq(syncLstat, path),
				send: statReplyRaw(syncLstat, Stat{}, tc.dev, tc.ino, tc.size),
			}})

			_, err := sc.Lstat(t.Context(), path)
			if !errors.Is(err, ErrProtocol) {
				t.Fatalf("error = %v, want ErrProtocol", err)
			}

			if !strings.Contains(err.Error(), "high bit") {
				t.Errorf("error %q does not explain which field could not be narrowed", err)
			}
		})
	}
}

// TestStatWrongReplyID keeps a desynced stream from being decoded as a stat.
func TestStatWrongReplyID(t *testing.T) {
	const path = "/sdcard/DCIM"

	sc := newSyncFake(t, []step{{
		want: syncPathReq(syncStat, path),
		send: statReply(syncLstat, measuredDirStat),
	}})

	_, err := sc.Stat(t.Context(), path)
	if !errors.Is(err, ErrProtocol) {
		t.Fatalf("error = %v, want ErrProtocol", err)
	}
}

// TestSyncRejectsNULPath is the measured truncation trap: adbd treats the path as
// a C string, so "/sdcard/DCIM\x00x" acts on "/sdcard/DCIM". A path validated in
// Go and truncated on the device would make the audit log describe an operation
// that never happened. The fake is given no steps, so any write fails the test.
func TestSyncRejectsNULPath(t *testing.T) {
	sc := newSyncFake(t, nil)

	ctx := t.Context()

	if _, err := sc.Lstat(ctx, "/sdcard/DCIM\x00x"); !errors.Is(err, ErrProtocol) {
		t.Fatalf("Lstat error = %v, want ErrProtocol", err)
	}
}

// TestListDoneBodyIsConsumed is the regression test for the most dangerous bug in
// this protocol. DONE carries a zeroed 72-byte dirent body; a reader that stops
// at the ID leaves those bytes in the stream and every later command on the
// channel desyncs. When it was hit during protocol discovery it presented as
// "all these directories are empty" — a confident, silent, wrong answer.
//
// So the assertion that matters is on the command issued AFTER the listing, not
// on the listing itself.
func TestListDoneBodyIsConsumed(t *testing.T) {
	const dir = "/sdcard/DCIM"

	camera := measuredDirStat
	camera.Ino = 4813

	screenshots := measuredDirStat
	screenshots.Ino = 4814

	after := measuredDirStat
	after.Ino = 987654

	sc := newSyncFake(t, []step{
		{
			want: syncPathReq(syncList, dir),
			send: concat(
				dentRecord(camera, []byte("Camera")),
				dentRecord(screenshots, []byte("Screenshots")),
				listDone(),
			),
		},
		{
			// The proof: this command's reply is only decodable if the DONE body
			// above was consumed.
			want: syncPathReq(syncStat, dir),
			send: statReply(syncStat, after),
		},
	})

	ctx := t.Context()

	var names []string

	if err := sc.List(ctx, dir, func(d Dirent) error {
		names = append(names, string(d.Name))

		return nil
	}); err != nil {
		t.Fatalf("List: %v", err)
	}

	if len(names) != 2 || names[0] != "Camera" || names[1] != "Screenshots" {
		t.Errorf("names = %q, want [Camera Screenshots]", names)
	}

	got, err := sc.Stat(ctx, dir)
	if err != nil {
		t.Fatalf("STA2 after a completed List failed, so the channel desynced: %v", err)
	}

	if got.Ino != after.Ino {
		t.Errorf("Ino = %d, want %d; the channel is misaligned", got.Ino, after.Ino)
	}
}

// TestListEmptyDirectory is the honest empty listing: DONE and nothing else. It
// must be distinguishable from the desync above only by the following command,
// which is why the previous test exists.
func TestListEmptyDirectory(t *testing.T) {
	const dir = "/sdcard/Recordings"

	sc := newSyncFake(t, []step{
		{want: syncPathReq(syncList, dir), send: listDone()},
		{want: syncPathReq(syncStat, dir), send: statReply(syncStat, measuredDirStat)},
	})

	ctx := t.Context()

	count := 0

	if err := sc.List(ctx, dir, func(Dirent) error {
		count++

		return nil
	}); err != nil {
		t.Fatalf("List: %v", err)
	}

	if count != 0 {
		t.Errorf("got %d entries, want 0", count)
	}

	if _, err := sc.Stat(ctx, dir); err != nil {
		t.Fatalf("STA2 after an empty List: %v", err)
	}
}

// TestListPreservesRawNameBytes covers a name that is not valid UTF-8. Filenames
// on the device are bytes; coercing them would produce a name that cannot be
// fetched back.
func TestListPreservesRawNameBytes(t *testing.T) {
	const dir = "/sdcard/DCIM"

	// Invalid UTF-8: a lone continuation byte, a truncated sequence, and 0xff.
	raw := []byte{0x80, 0xff, 'p', 'h', 'o', 't', 'o', 0xc3}

	sc := newSyncFake(t, []step{{
		want: syncPathReq(syncList, dir),
		send: concat(dentRecord(measuredDirStat, raw), listDone()),
	}})

	var got [][]byte

	if err := sc.List(t.Context(), dir, func(d Dirent) error {
		got = append(got, bytes.Clone(d.Name))

		return nil
	}); err != nil {
		t.Fatalf("List: %v", err)
	}

	if len(got) != 1 {
		t.Fatalf("got %d entries, want 1", len(got))
	}

	if !bytes.Equal(got[0], raw) {
		t.Errorf("Name = % x, want % x", got[0], raw)
	}
}

// TestListDotEntriesArePassedThrough documents the contract: adbd is measured not
// to return "." or "..", but List does not filter them, because relying on that
// measurement is the caller's choice to make.
func TestListDotEntriesArePassedThrough(t *testing.T) {
	const dir = "/sdcard/DCIM"

	sc := newSyncFake(t, []step{{
		want: syncPathReq(syncList, dir),
		send: concat(
			dentRecord(measuredDirStat, []byte(".")),
			dentRecord(measuredDirStat, []byte("..")),
			listDone(),
		),
	}})

	var names []string

	if err := sc.List(t.Context(), dir, func(d Dirent) error {
		names = append(names, string(d.Name))

		return nil
	}); err != nil {
		t.Fatalf("List: %v", err)
	}

	if len(names) != 2 || names[0] != "." || names[1] != ".." {
		t.Errorf("names = %q, want [. ..] passed through unfiltered", names)
	}
}

// TestListCallbackAbortRetiresSession covers an early stop: the rest of the
// stream is still on the socket, so the session cannot be reused.
func TestListCallbackAbortRetiresSession(t *testing.T) {
	const dir = "/sdcard/DCIM"

	stop := errors.New("caller stopped")

	sc := newSyncFake(t, []step{{
		want: syncPathReq(syncList, dir),
		send: concat(
			dentRecord(measuredDirStat, []byte("Camera")),
			dentRecord(measuredDirStat, []byte("Screenshots")),
			listDone(),
		),
	}})

	ctx := t.Context()

	err := sc.List(ctx, dir, func(Dirent) error { return stop })
	if !errors.Is(err, stop) {
		t.Fatalf("error = %v, want it to wrap the callback's error", err)
	}

	if !errors.Is(err, ErrSyncSessionDead) {
		t.Errorf("error = %v, want it to wrap ErrSyncSessionDead", err)
	}

	if _, err := sc.Stat(ctx, dir); !errors.Is(err, ErrSyncSessionDead) {
		t.Fatalf("Stat after an aborted List = %v, want ErrSyncSessionDead", err)
	}
}

// TestListFailRetiresSession covers a FAIL mid-listing.
func TestListFailRetiresSession(t *testing.T) {
	const dir = "/sdcard/DCIM"

	sc := newSyncFake(t, []step{{
		want: syncPathReq(syncList, dir),
		send: syncFailReply("open failed: Permission denied"),
	}})

	err := sc.List(t.Context(), dir, func(Dirent) error { return nil })
	if !errors.Is(err, ErrSyncSessionDead) {
		t.Fatalf("error = %v, want ErrSyncSessionDead", err)
	}

	fe, ok := errors.AsType[FailError](err)
	if !ok {
		t.Fatalf("error %v does not carry a FailError", err)
	}

	if fe.Message != "open failed: Permission denied" {
		t.Errorf("FailError.Message = %q, want the prose verbatim", fe.Message)
	}
}

// TestRecvMultiChunk covers reassembly in order, including a full 64 KiB chunk,
// which is the measured maximum.
func TestRecvMultiChunk(t *testing.T) {
	const path = "/sdcard/DCIM/Camera/example.jpg"

	first := bytes.Repeat([]byte{0xa5}, syncMaxChunk)
	second := bytes.Repeat([]byte{0x5a}, 4096)
	third := []byte("tail")

	sc := newSyncFake(t, []step{{
		want: syncPathReq(syncRecv, path),
		send: concat(recvData(first), recvData(second), recvData(third), recvDone()),
	}})

	var buf bytes.Buffer

	n, err := sc.Recv(t.Context(), path, &buf)
	if err != nil {
		t.Fatalf("Recv: %v", err)
	}

	want := concat(first, second, third)

	if n != int64(len(want)) {
		t.Errorf("Recv returned %d bytes, want %d", n, len(want))
	}

	if !bytes.Equal(buf.Bytes(), want) {
		t.Error("the reassembled bytes differ from the recorded stream")
	}
}

// TestRecvZeroByteFile is the measured empty-file case: no DATA packets at all,
// just an immediate DONE. Zero bytes is success, and such a file exists on the
// target device.
func TestRecvZeroByteFile(t *testing.T) {
	const path = "/sdcard/DCIM/empty"

	sc := newSyncFake(t, []step{
		{want: syncPathReq(syncRecv, path), send: recvDone()},
		// And the session is still usable afterwards, which is only true if
		// DONE's four-byte argument was consumed with its ID.
		{want: syncPathReq(syncStat, path), send: statReply(syncStat, Stat{Dev: 190, Ino: 55, Mode: 0o100644, Nlink: 1})},
	})

	ctx := t.Context()

	var buf bytes.Buffer

	n, err := sc.Recv(ctx, path, &buf)
	if err != nil {
		t.Fatalf("Recv on a zero-byte file: %v", err)
	}

	if n != 0 {
		t.Errorf("Recv returned %d bytes, want 0", n)
	}

	if buf.Len() != 0 {
		t.Errorf("wrote %d bytes, want none", buf.Len())
	}

	if _, err := sc.Stat(ctx, path); err != nil {
		t.Fatalf("STA2 after a zero-byte Recv failed, so the channel desynced: %v", err)
	}
}

// TestRecvSizeMatchesListing is the archiver's cheap path: the byte count equals
// the size the listing reported, exactly.
func TestRecvSizeMatchesListing(t *testing.T) {
	const path = "/sdcard/DCIM/Camera/large.mp4"
	const size = 27190943

	chunks := make([][]byte, 0, size/syncMaxChunk+2)

	for remaining := size; remaining > 0; {
		n := min(remaining, syncMaxChunk)
		chunks = append(chunks, recvData(bytes.Repeat([]byte{0x7f}, n)))
		remaining -= n
	}

	chunks = append(chunks, recvDone())

	sc := newSyncFake(t, []step{{want: syncPathReq(syncRecv, path), send: concat(chunks...)}})

	n, err := sc.Recv(t.Context(), path, discardWriter{})
	if err != nil {
		t.Fatalf("Recv: %v", err)
	}

	if n != size {
		t.Errorf("Recv returned %d bytes, want the listing's %d", n, size)
	}
}

// discardWriter counts nothing and keeps the large transfer out of memory.
type discardWriter struct{}

func (discardWriter) Write(p []byte) (int, error) { return len(p), nil }

// TestRecvFailKillsSession covers all three observed RECV failures. Each was
// re-tested on a fresh channel and the channel was dead every time, so the error
// wraps ErrSyncSessionDead and every later call must fail fast.
func TestRecvFailKillsSession(t *testing.T) {
	tests := []struct {
		name string
		path string
		msg  string
	}{
		{"nonexistent path", "/sdcard/DCIM/nope", "open failed: No such file or directory"},
		{"unreadable file", "/init", "open failed: Permission denied"},
		{"a directory", "/sdcard/DCIM", "read failed: Is a directory"},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			sc := newSyncFake(t, []step{{
				want: syncPathReq(syncRecv, tc.path),
				send: syncFailReply(tc.msg),
			}})

			ctx := t.Context()

			var buf bytes.Buffer

			_, err := sc.Recv(ctx, tc.path, &buf)
			if !errors.Is(err, ErrSyncSessionDead) {
				t.Fatalf("error = %v, want it to wrap ErrSyncSessionDead", err)
			}

			fe, ok := errors.AsType[FailError](err)
			if !ok {
				t.Fatalf("error %v does not carry a FailError", err)
			}

			if fe.Message != tc.msg {
				t.Errorf("FailError.Message = %q, want %q", fe.Message, tc.msg)
			}

			if fe.Service != syncRecv {
				t.Errorf("FailError.Service = %q, want %q", fe.Service, syncRecv)
			}

			// Every later call must fail fast rather than desync or hang. The
			// fake has no further steps, so anything written here would fail the
			// test.
			start := time.Now()

			for name, call := range map[string]func() error{
				"Lstat": func() error { _, err := sc.Lstat(ctx, tc.path); return err },
				"Stat":  func() error { _, err := sc.Stat(ctx, tc.path); return err },
				"List":  func() error { return sc.List(ctx, tc.path, func(Dirent) error { return nil }) },
				"Recv":  func() error { _, err := sc.Recv(ctx, tc.path, &buf); return err },
			} {
				if err := call(); !errors.Is(err, ErrSyncSessionDead) {
					t.Errorf("%s after a RECV FAIL = %v, want ErrSyncSessionDead", name, err)
				}
			}

			if elapsed := time.Since(start); elapsed > time.Second {
				t.Errorf("the follow-up calls took %v; they must fail fast, not wait on the socket", elapsed)
			}
		})
	}
}

// TestRecvChunkTooLarge treats an implausible DATA length as a framing violation
// rather than an allocation request.
func TestRecvChunkTooLarge(t *testing.T) {
	const path = "/sdcard/DCIM/Camera/example.jpg"

	oversized := append([]byte(syncData), 0, 0, 0, 0)
	binary.LittleEndian.PutUint32(oversized[4:], syncMaxChunk+1)

	sc := newSyncFake(t, []step{{want: syncPathReq(syncRecv, path), send: oversized}})

	var buf bytes.Buffer

	if _, err := sc.Recv(t.Context(), path, &buf); !errors.Is(err, ErrProtocol) {
		t.Fatalf("error = %v, want ErrProtocol", err)
	}
}

// TestRecvUnexpectedID keeps an unknown reply ID from being ignored.
func TestRecvUnexpectedID(t *testing.T) {
	const path = "/sdcard/DCIM/Camera/example.jpg"

	sc := newSyncFake(t, []step{{
		want: syncPathReq(syncRecv, path),
		send: append([]byte("OKAY"), 0, 0, 0, 0),
	}})

	var buf bytes.Buffer

	if _, err := sc.Recv(t.Context(), path, &buf); !errors.Is(err, ErrProtocol) {
		t.Fatalf("error = %v, want ErrProtocol", err)
	}
}

// TestSyncCloseIsIdempotent because callers defer it on every path.
func TestSyncCloseIsIdempotent(t *testing.T) {
	sc := newSyncFake(t, nil)

	if err := sc.Close(); err != nil {
		t.Fatalf("first Close: %v", err)
	}

	if err := sc.Close(); err != nil {
		t.Fatalf("second Close: %v", err)
	}

	if _, err := sc.Lstat(t.Context(), "/sdcard"); !errors.Is(err, ErrSyncSessionDead) {
		t.Fatalf("Lstat after Close = %v, want ErrSyncSessionDead", err)
	}
}

// TestSyncStatLayout pins the constants that describe the measured wire shapes,
// so a change to one of them is a deliberate change.
func TestSyncStatLayout(t *testing.T) {
	if syncStatLen != 72 {
		t.Errorf("syncStatLen = %d, want the measured 72", syncStatLen)
	}

	if syncDentBodyLen != 72 {
		t.Errorf("syncDentBodyLen = %d, want 72 (a 76-byte record minus its ID)", syncDentBodyLen)
	}

	if syncMaxChunk != 65536 {
		t.Errorf("syncMaxChunk = %d, want the measured 65536", syncMaxChunk)
	}

	if got := len(statReply(syncLstat, measuredDirStat)); got != syncStatLen {
		t.Errorf("the recorded stat reply is %d bytes, want %d", got, syncStatLen)
	}

	if got := len(listDone()); got != syncIDLen+syncStatLen {
		t.Errorf("the recorded DONE record is %d bytes, want %d", got, syncIDLen+syncStatLen)
	}

	if got := len(dentRecord(measuredDirStat, []byte("Camera"))); got != syncStatLen+4+len("Camera") {
		t.Errorf("the recorded DNT2 record is %d bytes, want %d", got, syncStatLen+4+len("Camera"))
	}
}
