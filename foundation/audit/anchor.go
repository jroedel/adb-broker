package audit

import (
	"errors"
	"fmt"
	"net"
	"strconv"
	"strings"
	"time"
)

const (
	// MessageID is the journal MESSAGE_ID that identifies an adb-broker audit
	// anchor. It is a fixed 128-bit value so a verifier can select anchors with
	// a single indexed journal match instead of grepping message text.
	MessageID = "8f3c1d7a5e4b42c9b1d06a2f7c93e5a4"

	// MaxAnchorFieldBytes is the hard limit on the length of any single field
	// value in an anchor. It is load bearing, not decoration.
	//
	// journald compresses an individual data object once it grows past roughly
	// 512 bytes, and the compression is zstd. The reader that verifies anchors
	// (foundation/journal) parses journal files directly and CANNOT decompress,
	// because zstd is not in the Go standard library. A field long enough to be
	// compressed is therefore a field the verifier cannot read — and an anchor
	// that cannot be read is the same as an anchor that was never written,
	// except that it looks like it succeeded.
	//
	// So WriteAnchor refuses to send an over-long value rather than emitting an
	// entry the reader will choke on: the writer is made structurally incapable
	// of producing an unverifiable anchor. 256 leaves generous headroom below
	// the compression threshold once the short key name and separator are added.
	//
	// Do not raise this limit to accommodate a long path. Either shorten the
	// path or teach the reader to decompress first; relaxing the cap here just
	// moves a loud failure to a silent one.
	MaxAnchorFieldBytes = 256

	// anchorWriteTimeout bounds a send so a full journal socket cannot stall an
	// operation on the broker's hot path.
	anchorWriteTimeout = 2 * time.Second
)

// journalSocketPath is the journald datagram socket. It is a variable, not a
// constant, only so tests can point it at a temporary socket; the exported API
// deliberately offers no way to change it.
var journalSocketPath = "/run/systemd/journal/socket"

// ErrAnchorField reports that an anchor field value was refused before any
// datagram was sent. It signals a programming or configuration fault — an
// over-long value, or one containing a newline or NUL — not a transport failure.
var ErrAnchorField = errors.New("anchor field rejected")

// Anchor is a published claim about the state of the audit log: at some moment,
// the log at LogPath had Seq records and chain head Hash.
type Anchor struct {
	Seq     uint64
	Hash    string
	LogPath string
}

// WriteAnchor publishes a as one datagram to the systemd journal.
//
// It speaks journald's native protocol directly — a single AF_UNIX/SOCK_DGRAM
// send of newline-separated KEY=value pairs to /run/systemd/journal/socket. No
// library, no subprocess, no reply to wait for. The socket is mode 0666, so no
// group membership is needed to write to it.
//
// The fields sent are:
//
//	MESSAGE_ID=<MessageID>
//	MESSAGE=adb-broker audit anchor seq=<seq>
//	PRIORITY=5
//	SYSLOG_IDENTIFIER=adb-broker
//	ADB_BROKER_SEQ=<seq>
//	ADB_BROKER_HASH=<hex>
//	ADB_BROKER_LOG=<path>
//
// Trust model. journald stamps _UID, _GID, _PID, _COMM, _EXE, _CMDLINE and
// _AUDIT_LOGINUID onto the entry from the sending socket's credentials, so a
// sender cannot forge them. _UID IS THE ONLY THING THAT MAKES AN ANCHOR
// TRUSTWORTHY: because the socket is world-writable, any local process can
// publish a well-formed entry carrying this MESSAGE_ID with fabricated seq and
// hash values. One such forged anchor exists in this host's journal, published
// deliberately during an experiment. Verifying _UID is the reader's job, but the
// reason is recorded here so nobody later "simplifies" the writer by dropping
// the identifying fields or by treating a MESSAGE_ID match as proof of origin.
//
// Every value is checked before anything is sent: no value may exceed
// MaxAnchorFieldBytes (see that constant — the reader cannot decompress), and no
// value may contain a newline or a NUL. A value with a newline would require
// journald's binary framing (KEY\n<little-endian uint64 length><raw bytes>\n);
// rather than implement a second encoding for a case none of these fields has
// legitimately, such a value is refused. Rejections wrap ErrAnchorField.
//
// A missing socket — a non-systemd host — is an ordinary error wrapping
// ErrAuditUnavailable, not a panic. The caller decides what that means; failing
// to publish an anchor should not by itself abort the operation being recorded.
func WriteAnchor(a Anchor) error {
	seq := strconv.FormatUint(a.Seq, 10)

	fields := [][2]string{
		{"MESSAGE_ID", MessageID},
		{"MESSAGE", "adb-broker audit anchor seq=" + seq},
		{"PRIORITY", "5"},
		{"SYSLOG_IDENTIFIER", "adb-broker"},
		{"ADB_BROKER_SEQ", seq},
		{"ADB_BROKER_HASH", a.Hash},
		{"ADB_BROKER_LOG", a.LogPath},
	}

	var payload []byte
	for _, f := range fields {
		key, value := f[0], f[1]
		if err := checkAnchorValue(key, value); err != nil {
			return err
		}

		payload = append(payload, key...)
		payload = append(payload, '=')
		payload = append(payload, value...)
		payload = append(payload, '\n')
	}

	conn, err := net.Dial("unixgram", journalSocketPath)
	if err != nil {
		return fmt.Errorf("audit: %w: dial journal socket %s: %w", ErrAuditUnavailable, journalSocketPath, err)
	}
	defer conn.Close()

	if err := conn.SetWriteDeadline(time.Now().Add(anchorWriteTimeout)); err != nil {
		return fmt.Errorf("audit: %w: set anchor write deadline: %w", ErrAuditUnavailable, err)
	}

	if _, err := conn.Write(payload); err != nil {
		return fmt.Errorf("audit: %w: send anchor seq %d: %w", ErrAuditUnavailable, a.Seq, err)
	}

	return nil
}

// checkAnchorValue enforces the two limits that keep an anchor readable: length,
// and the absence of the bytes that would demand journald's binary framing.
func checkAnchorValue(key, value string) error {
	if len(value) > MaxAnchorFieldBytes {
		return fmt.Errorf("audit: %w: %s is %d bytes, limit %d", ErrAnchorField, key, len(value), MaxAnchorFieldBytes)
	}

	if i := strings.IndexAny(value, "\n\x00"); i >= 0 {
		return fmt.Errorf("audit: %w: %s contains %q at byte %d", ErrAnchorField, key, value[i], i)
	}

	return nil
}
