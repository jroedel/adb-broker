package audit

import (
	"encoding/hex"
	"errors"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// tempSocketDir returns a directory short enough to hold a unix socket path.
// AF_UNIX paths are capped near 108 bytes, and t.TempDir() honours $TMPDIR,
// which is not always short.
func tempSocketDir(t *testing.T) string {
	t.Helper()

	if dir := t.TempDir(); len(dir) < 80 {
		return dir
	}

	dir, err := os.MkdirTemp("/tmp", "audit")
	if err != nil {
		t.Fatalf("temp dir: %v", err)
	}
	t.Cleanup(func() { os.RemoveAll(dir) })

	return dir
}

// useSocketPath points the package at path for the duration of the test. The
// socket location is an unexported variable precisely so tests can do this
// without the exported API growing a knob no production caller should touch.
func useSocketPath(t *testing.T, path string) {
	t.Helper()

	saved := journalSocketPath
	journalSocketPath = path
	t.Cleanup(func() { journalSocketPath = saved })
}

// listen starts a datagram listener standing in for journald.
func listen(t *testing.T) (*net.UnixConn, string) {
	t.Helper()

	path := filepath.Join(tempSocketDir(t), "journal.sock")

	conn, err := net.ListenUnixgram("unixgram", &net.UnixAddr{Name: path, Net: "unixgram"})
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	t.Cleanup(func() { conn.Close() })

	return conn, path
}

// TestWriteAnchorSendsExactBytes asserts the wire form field by field. The
// reader in foundation/journal matches on these exact names, so a rename here is
// a silent break in a control nobody exercises until it is needed.
func TestWriteAnchorSendsExactBytes(t *testing.T) {
	conn, path := listen(t)
	useSocketPath(t, path)

	a := Anchor{
		Seq:     4213,
		Hash:    "87da0acf8292aa5b0be20c5ba0a307df395e14157cab6b83bb37d10e8d905210",
		LogPath: "/var/log/adb-broker/audit.log",
	}

	if err := WriteAnchor(a); err != nil {
		t.Fatalf("WriteAnchor: %v", err)
	}

	if err := conn.SetReadDeadline(time.Now().Add(5 * time.Second)); err != nil {
		t.Fatalf("set read deadline: %v", err)
	}

	buf := make([]byte, 4096)
	n, err := conn.Read(buf)
	if err != nil {
		t.Fatalf("read datagram: %v", err)
	}

	want := "MESSAGE_ID=8f3c1d7a5e4b42c9b1d06a2f7c93e5a4\n" +
		"MESSAGE=adb-broker audit anchor seq=4213\n" +
		"PRIORITY=5\n" +
		"SYSLOG_IDENTIFIER=adb-broker\n" +
		"ADB_BROKER_SEQ=4213\n" +
		"ADB_BROKER_HASH=87da0acf8292aa5b0be20c5ba0a307df395e14157cab6b83bb37d10e8d905210\n" +
		"ADB_BROKER_LOG=/var/log/adb-broker/audit.log\n"

	if got := string(buf[:n]); got != want {
		t.Errorf("anchor datagram changed.\n got:\n%s\nwant:\n%s", got, want)
	}
}

// TestWriteAnchorSendsOneDatagram checks that the journal protocol is used as
// intended: one entry per anchor, not a field per packet.
func TestWriteAnchorSendsOneDatagram(t *testing.T) {
	conn, path := listen(t)
	useSocketPath(t, path)

	if err := WriteAnchor(Anchor{Seq: 1, Hash: strings.Repeat("0", 64), LogPath: "/x"}); err != nil {
		t.Fatalf("WriteAnchor: %v", err)
	}

	if err := conn.SetReadDeadline(time.Now().Add(5 * time.Second)); err != nil {
		t.Fatalf("set read deadline: %v", err)
	}

	buf := make([]byte, 4096)
	if _, err := conn.Read(buf); err != nil {
		t.Fatalf("read first datagram: %v", err)
	}

	if err := conn.SetReadDeadline(time.Now().Add(100 * time.Millisecond)); err != nil {
		t.Fatalf("set read deadline: %v", err)
	}

	if n, err := conn.Read(buf); err == nil {
		t.Errorf("a second datagram arrived (%d bytes): %q", n, buf[:n])
	}
}

// TestWriteAnchorRejectsUnsendableFields covers the limits that keep an anchor
// readable by foundation/journal, which cannot decompress and does not implement
// journald's binary framing. Each case must be refused BEFORE any datagram is
// sent, which is why the socket path here points at nothing: reaching the dial
// would surface as ErrAuditUnavailable instead of ErrAnchorField.
func TestWriteAnchorRejectsUnsendableFields(t *testing.T) {
	useSocketPath(t, filepath.Join(tempSocketDir(t), "absent.sock"))

	tests := map[string]Anchor{
		"path over the field cap": {Seq: 1, Hash: strings.Repeat("0", 64), LogPath: "/var/log/" + strings.Repeat("d", MaxAnchorFieldBytes)},
		"hash over the field cap": {Seq: 1, Hash: strings.Repeat("0", MaxAnchorFieldBytes+1), LogPath: "/x"},
		"newline in path":         {Seq: 1, Hash: strings.Repeat("0", 64), LogPath: "/var/log/a\nMESSAGE=forged"},
		"newline in hash":         {Seq: 1, Hash: "abc\ndef", LogPath: "/x"},
		"nul in path":             {Seq: 1, Hash: strings.Repeat("0", 64), LogPath: "/var/log/a\x00b"},
		"nul in hash":             {Seq: 1, Hash: "abc\x00def", LogPath: "/x"},
	}

	for name, a := range tests {
		t.Run(name, func(t *testing.T) {
			err := WriteAnchor(a)
			if !errors.Is(err, ErrAnchorField) {
				t.Errorf("WriteAnchor = %v, want ErrAnchorField", err)
			}

			if errors.Is(err, ErrAuditUnavailable) {
				t.Error("the value reached the socket; it must be refused before the dial")
			}
		})
	}
}

// TestWriteAnchorAcceptsValueAtTheCap pins the boundary as inclusive.
func TestWriteAnchorAcceptsValueAtTheCap(t *testing.T) {
	conn, path := listen(t)
	useSocketPath(t, path)

	logPath := "/" + strings.Repeat("d", MaxAnchorFieldBytes-1)
	if len(logPath) != MaxAnchorFieldBytes {
		t.Fatalf("test setup: path is %d bytes", len(logPath))
	}

	if err := WriteAnchor(Anchor{Seq: 7, Hash: strings.Repeat("0", 64), LogPath: logPath}); err != nil {
		t.Fatalf("WriteAnchor at exactly the cap: %v", err)
	}

	if err := conn.SetReadDeadline(time.Now().Add(5 * time.Second)); err != nil {
		t.Fatalf("set read deadline: %v", err)
	}

	buf := make([]byte, 4096)
	n, err := conn.Read(buf)
	if err != nil {
		t.Fatalf("read datagram: %v", err)
	}

	if !strings.Contains(string(buf[:n]), "ADB_BROKER_LOG="+logPath+"\n") {
		t.Error("the field at exactly the cap was not sent verbatim")
	}
}

// TestWriteAnchorMissingSocket covers a non-systemd host: an ordinary error, no
// panic, and nothing that forces the caller to abort the recorded operation.
func TestWriteAnchorMissingSocket(t *testing.T) {
	useSocketPath(t, filepath.Join(tempSocketDir(t), "absent.sock"))

	err := WriteAnchor(Anchor{Seq: 1, Hash: strings.Repeat("0", 64), LogPath: "/var/log/adb-broker/audit.log"})
	if !errors.Is(err, ErrAuditUnavailable) {
		t.Errorf("WriteAnchor with no socket = %v, want ErrAuditUnavailable", err)
	}

	if errors.Is(err, ErrAnchorField) {
		t.Error("a transport failure must not be reported as a field rejection")
	}
}

// TestAnchorTailPublishesTheLogsOwnTail asserts the three values every caller of
// AnchorTail would otherwise have had to assemble itself: the log's sequence
// number, its chain head in hex, and its path. Getting any of them from somewhere
// else is a claim about a log that was never made.
func TestAnchorTailPublishesTheLogsOwnTail(t *testing.T) {
	conn, socket := listen(t)
	useSocketPath(t, socket)

	l, logPath := openTestLog(t)

	if _, err := l.Append(Record{TS: time.Now(), Op: "probe", Decision: "allow", Result: "ok"}); err != nil {
		t.Fatalf("append: %v", err)
	}

	if err := AnchorTail(l); err != nil {
		t.Fatalf("AnchorTail: %v", err)
	}

	head := l.Head()

	if err := conn.SetReadDeadline(time.Now().Add(5 * time.Second)); err != nil {
		t.Fatalf("set read deadline: %v", err)
	}

	buf := make([]byte, 4096)
	n, err := conn.Read(buf)
	if err != nil {
		t.Fatalf("read datagram: %v", err)
	}

	got := string(buf[:n])
	for _, want := range []string{
		"ADB_BROKER_SEQ=1\n",
		"ADB_BROKER_HASH=" + hex.EncodeToString(head[:]) + "\n",
		"ADB_BROKER_LOG=" + logPath + "\n",
	} {
		if !strings.Contains(got, want) {
			t.Errorf("the anchor does not carry %q:\n%s", want, got)
		}
	}
}

// TestAnchorTailReportsWhyItCouldNotPublish is the whole reason this function
// returns an error rather than swallowing one.
//
// Its callers are contractually forbidden from failing an operation over a failed
// anchor, so the error's only destination is an operator's stderr — and on the
// first setuid install it was discarded, which made a permanently broken anchor
// path indistinguishable from a working one. The message therefore has to name the
// log, the sequence number that went unanchored, and the transport reason.
func TestAnchorTailReportsWhyItCouldNotPublish(t *testing.T) {
	useSocketPath(t, filepath.Join(tempSocketDir(t), "absent.sock"))

	l, logPath := openTestLog(t)

	if _, err := l.Append(Record{TS: time.Now(), Op: "probe", Decision: "allow", Result: "ok"}); err != nil {
		t.Fatalf("append: %v", err)
	}

	err := AnchorTail(l)
	if !errors.Is(err, ErrAuditUnavailable) {
		t.Fatalf("AnchorTail with no socket = %v, want it to wrap ErrAuditUnavailable", err)
	}

	for _, want := range []string{logPath, "seq 1", "absent.sock", "truncated tail"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("the error %q does not mention %q", err, want)
		}
	}
}

// TestAnchorTailOnAnEmptyLogAnchorsTheEmptyChain covers a fresh install: 32 zero
// bytes at seq 0 is a valid state to anchor, and refusing to publish it would
// leave the very first record of a new chain uncovered.
func TestAnchorTailOnAnEmptyLogAnchorsTheEmptyChain(t *testing.T) {
	conn, socket := listen(t)
	useSocketPath(t, socket)

	l, _ := openTestLog(t)

	if err := AnchorTail(l); err != nil {
		t.Fatalf("AnchorTail on an empty log: %v", err)
	}

	if err := conn.SetReadDeadline(time.Now().Add(5 * time.Second)); err != nil {
		t.Fatalf("set read deadline: %v", err)
	}

	buf := make([]byte, 4096)
	n, err := conn.Read(buf)
	if err != nil {
		t.Fatalf("read datagram: %v", err)
	}

	got := string(buf[:n])
	for _, want := range []string{"ADB_BROKER_SEQ=0\n", "ADB_BROKER_HASH=" + strings.Repeat("0", 64) + "\n"} {
		if !strings.Contains(got, want) {
			t.Errorf("the anchor does not carry %q:\n%s", want, got)
		}
	}
}

// openTestLog opens a fresh, empty log the way the installer would create one:
// Open deliberately does not create the file (see its doc comment).
func openTestLog(t *testing.T) (*Log, string) {
	t.Helper()

	path := filepath.Join(t.TempDir(), "audit.log")
	if err := os.WriteFile(path, nil, 0o600); err != nil {
		t.Fatalf("create the test log: %v", err)
	}

	l, err := Open(path)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	t.Cleanup(func() { _ = l.Close() })

	return l, path
}

// TestMessageIDIsAStableJournalMatch guards the constant a verifier greps for.
func TestMessageIDIsAStableJournalMatch(t *testing.T) {
	if MessageID != "8f3c1d7a5e4b42c9b1d06a2f7c93e5a4" {
		t.Errorf("MessageID changed to %q; every anchor already in the journal carries the old value", MessageID)
	}

	if len(MessageID) != 32 {
		t.Errorf("MessageID must be 32 hex characters, got %d", len(MessageID))
	}
}
