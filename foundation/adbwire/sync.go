package adbwire

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"math"
	"net"
	"strconv"
	"strings"
	"sync"
	"time"
)

// The sync commands this package sends. This is the complete set: there is no
// SEND, and no QUIT (Close simply closes the socket, which adbd handles).
const (
	syncLstat = "LST2" // ID_LSTAT_V2 — does NOT follow symlinks
	syncStat  = "STA2" // ID_STAT_V2  — DOES follow symlinks
	syncList  = "LIS2" // ID_LIST_V2
	syncRecv  = "RECV" // ID_RECV
)

// The reply IDs the device sends back.
const (
	syncDent = "DNT2"
	syncData = "DATA"
	syncDone = "DONE"
	syncFail = "FAIL"
)

const (
	// syncIDLen is the length of every sync ID, and of the little-endian
	// argument that follows it.
	syncIDLen  = 4
	syncArgLen = 4

	// syncStatLen is the whole LST2/STA2 reply, ID included. Measured exactly:
	//
	//	id(4) error(4) dev(8) ino(8) mode(4) nlink(4) uid(4) gid(4)
	//	size(8) atime(8) mtime(8) ctime(8)
	//
	// All little-endian. size is genuinely 64-bit — a 27,190,943-byte file round
	// tripped exactly. The times are whole seconds; there is no sub-second
	// field, so mtime nanoseconds are unavailable over this protocol rather than
	// merely unimplemented.
	syncStatLen = 72

	// syncDentBodyLen is what follows a DNT2 or DONE ID: the remaining 68 bytes
	// of the stat body plus a 4-byte name length. A DNT2 record is therefore 76
	// bytes plus the name.
	syncDentBodyLen = syncStatLen - syncIDLen + 4

	// syncMaxChunk is the largest DATA payload measured: 65536, exactly 64 KiB.
	// A larger one is treated as a framing violation rather than an allocation
	// request.
	syncMaxChunk = 65536

	// syncMaxName bounds one directory entry name (Linux NAME_MAX is 255; this
	// is generous). It exists so a desynced stream cannot ask for a huge
	// allocation.
	syncMaxName = 4096

	// syncMaxPath bounds an outbound path (Linux PATH_MAX).
	syncMaxPath = 4096

	// syncMaxFailMessage bounds a FAIL message.
	syncMaxFailMessage = 4096
)

// Stat is one stat_v2 reply. Fields are the device's, unconverted.
type Stat struct {
	// Errno is a plain errno: 0, 2 (ENOENT), 13 (EACCES). It is data, not a
	// failure — Lstat and Stat return it with a nil error, because measured, an
	// LST2 error is in-band and the channel stays usable: a nonexistent path
	// returns error=2 and further commands succeed on the same socket.
	//
	// Note that ENOENT does not prove absence. adbd returns it for paths it can
	// see but is not allowed to read.
	Errno uint32

	// Dev and Ino arrive as unsigned 64-bit values and are narrowed to int64. A
	// value with the high bit set is a decode error, not a negative number.
	Dev, Ino int64

	Mode            uint32
	Nlink, UID, GID uint32

	Size int64

	// Atime, Mtime and Ctime are whole seconds. The protocol carries no
	// sub-second component.
	Atime, Mtime, Ctime int64
}

// Dirent is one entry of a LIS2 listing.
type Dirent struct {
	Stat

	// Name is the raw bytes adbd sent. It is never coerced to UTF-8 and never
	// stored as a string: a filename on the device is a byte string, and
	// round-tripping it through Go's UTF-8 replacement would produce a name that
	// cannot be fetched. Callers that must display it should escape it.
	Name []byte
}

// SyncConn is a sync session on a transport, obtained from Conn.Sync. It is safe
// for sequential use from multiple goroutines; commands on one session cannot be
// interleaved.
//
// A session is reusable: measured, one socket carried nine consecutive LST2
// commands and later a mixed sequence of LIS2 and RECV. It is also fragile —
// see ErrSyncSessionDead.
type SyncConn struct {
	mu   sync.Mutex
	nc   net.Conn
	dead error  // non-nil once the session is unusable, holding why
	buf  []byte // reused RECV chunk buffer, allocated on first use
}

// newSyncConn takes ownership of a socket that has completed the sync: handshake.
// It is unexported because a SyncConn with no deadlines behind it must not be
// constructible: the only way in is Conn.Sync, whose exchanges are all bounded.
func newSyncConn(nc net.Conn) *SyncConn {
	return &SyncConn{nc: nc}
}

// Close ends the session and releases the socket. It is safe to call more than
// once.
//
// It does not send QUIT: QUIT is outside this package's compiled vocabulary and
// closing the socket is sufficient — adbd tears the session down on EOF.
func (s *SyncConn) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()

	nc := s.nc
	s.nc = nil

	if s.dead == nil {
		s.dead = errors.New("closed by the caller")
	}

	if nc == nil {
		return nil
	}

	return nc.Close()
}

// alive reports the session's state. Once dead, every call fails fast rather
// than writing a command into a desynced stream or blocking on a reply that will
// never come.
func (s *SyncConn) alive() error {
	switch {
	case s.dead != nil:
		return fmt.Errorf("adbwire: sync session unusable (%v): %w", s.dead, ErrSyncSessionDead)

	case s.nc == nil:
		// A zero-value SyncConn has no socket and therefore no deadlines behind
		// it. Conn.Sync is the only way in; this refuses rather than panicking.
		return fmt.Errorf("adbwire: SyncConn was not created by Conn.Sync: %w", ErrSyncSessionDead)

	default:
		return nil
	}
}

// kill marks the session dead and returns err with ErrSyncSessionDead attached.
//
// Every failure that reaches here leaves bytes the broker cannot account for:
// an unread FAIL body, a half-read record, an aborted listing. Continuing on
// such a channel is how "every directory is empty" gets reported confidently and
// wrongly, so the channel is retired instead.
func (s *SyncConn) kill(err error) error {
	if s.dead == nil {
		s.dead = err
	}

	if s.nc != nil {
		_ = s.nc.Close()
		s.nc = nil
	}

	return fmt.Errorf("%w: %w", err, ErrSyncSessionDead)
}

// sendPath writes a sync command whose argument is a path length, followed by the
// raw path bytes.
func (s *SyncConn) sendPath(ctx context.Context, id, path string, def time.Duration) error {
	switch {
	case strings.ContainsRune(path, 0):
		// Measured, and the nastiest result of the protocol survey: adbd treats
		// the path as a C string, so "/sdcard/DCIM\x00x" acts on /sdcard/DCIM.
		// A path validated in Go and truncated on the device would make the
		// audit log a faithful record of something that never happened.
		return fmt.Errorf("adbwire: %s: path contains a NUL byte, which the device would silently truncate at: %w", id, ErrProtocol)

	case len(path) > syncMaxPath:
		return fmt.Errorf("adbwire: %s: path is %d bytes, over the %d byte limit: %w", id, len(path), syncMaxPath, ErrProtocol)
	}

	req := make([]byte, 0, syncIDLen+syncArgLen+len(path))
	req = append(req, id...)
	req = binary.LittleEndian.AppendUint32(req, uint32(len(path)))
	req = append(req, path...)

	return writeAll(ctx, s.nc, id, req, def)
}

// readSyncHeader reads a sync ID and its four-byte little-endian argument. Every
// reply shape begins this way: for DATA the argument is the chunk length, for
// FAIL the message length, for DONE it is zero, and for DNT2 it is the errno.
func (s *SyncConn) readSyncHeader(ctx context.Context, op string, def time.Duration) (string, uint32, []byte, error) {
	var hdr [syncIDLen + syncArgLen]byte
	if err := readFull(ctx, s.nc, op, hdr[:], def); err != nil {
		return "", 0, nil, err
	}

	return string(hdr[:syncIDLen]), binary.LittleEndian.Uint32(hdr[syncIDLen:]), hdr[:], nil
}

// readFailMessage reads a sync FAIL body: a four-byte little-endian length that
// has already been read as the header argument, then that many prose bytes.
func (s *SyncConn) readFailMessage(ctx context.Context, op string, n uint32) (string, error) {
	if n > syncMaxFailMessage {
		return "", fmt.Errorf("adbwire: %s: FAIL message length %d is implausible: %w", op, n, ErrProtocol)
	}

	msg := make([]byte, n)
	if err := readFull(ctx, s.nc, op+" FAIL message", msg, defaultHostDeadline); err != nil {
		return "", err
	}

	return string(msg), nil
}

// Lstat stats a path without following symlinks (LST2).
//
// The returned error is nil for a device-side error: the errno lands in
// Stat.Errno and the session stays usable. Measured, /sdcard is itself a
// symlink, so Lstat and Stat genuinely disagree there — 0o120644 versus
// 0o42770.
func (s *SyncConn) Lstat(ctx context.Context, path string) (Stat, error) {
	return s.statCommand(ctx, syncLstat, path)
}

// Stat stats a path, following symlinks (STA2).
//
// This is the call that resolves a symlinked root. It is also the reason the
// broker's confinement check cannot be "refuse a symlink at every component":
// measured, both /sdcard and /storage/self/primary are symlinks on a stock
// device, so that rule would refuse every allowed path.
func (s *SyncConn) Stat(ctx context.Context, path string) (Stat, error) {
	return s.statCommand(ctx, syncStat, path)
}

// statCommand implements Lstat and Stat, which differ only in the ID they send.
func (s *SyncConn) statCommand(ctx context.Context, id, path string) (Stat, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if err := s.alive(); err != nil {
		return Stat{}, err
	}

	op := id + " " + strconv.Quote(path)

	if err := s.sendPath(ctx, id, path, defaultHostDeadline); err != nil {
		return Stat{}, s.kill(err)
	}

	replyID, arg, hdr, err := s.readSyncHeader(ctx, op, defaultHostDeadline)
	if err != nil {
		return Stat{}, s.kill(err)
	}

	switch replyID {
	case id:
		// The remaining 64 bytes of the 72-byte reply; the errno already came
		// back in the header argument.
		rest := make([]byte, syncStatLen-syncIDLen-syncArgLen)
		if err := readFull(ctx, s.nc, op, rest, defaultHostDeadline); err != nil {
			return Stat{}, s.kill(err)
		}

		st, err := decodeStat(hdr[syncIDLen:], rest)
		if err != nil {
			return Stat{}, s.kill(fmt.Errorf("adbwire: %s: %w", op, err))
		}

		return st, nil

	case syncFail:
		msg, err := s.readFailMessage(ctx, op, arg)
		if err != nil {
			return Stat{}, s.kill(err)
		}

		return Stat{}, s.kill(fmt.Errorf("adbwire: %s: %w", op, newSyncFailError(id, msg)))

	default:
		return Stat{}, s.kill(fmt.Errorf("adbwire: %s: reply ID %q, want %q: %w", op, replyID, id, ErrProtocol))
	}
}

// decodeStat decodes a stat_v2 body. errnoField is the four-byte error field,
// which arrives in the same read as the ID; rest is the 64 bytes after it.
// Splitting the buffer this way is an artefact of reading the ID and its
// argument together, which is what telling the reply shapes apart requires.
func decodeStat(errnoField, rest []byte) (Stat, error) {
	if len(errnoField) < syncArgLen || len(rest) != syncStatLen-syncIDLen-syncArgLen {
		return Stat{}, fmt.Errorf("adbwire: stat body is %d bytes, want %d: %w", syncIDLen+syncArgLen+len(rest), syncStatLen, ErrProtocol)
	}

	le := binary.LittleEndian

	// Offsets within rest, i.e. the 72-byte reply minus its id(4) and error(4):
	// dev 0, ino 8, mode 16, nlink 20, uid 24, gid 28, size 32, atime 40,
	// mtime 48, ctime 56.
	dev := le.Uint64(rest[0:])
	ino := le.Uint64(rest[8:])
	size := le.Uint64(rest[32:])

	// dev, ino and size arrive unsigned and are stored signed. A value with the
	// high bit set cannot be represented, and real inode and device numbers are
	// nowhere near 2^63 — so this branch should never fire, which is exactly why
	// it must be an error instead of a silent wrap to a negative number.
	for _, f := range []struct {
		name string
		v    uint64
	}{{"dev", dev}, {"ino", ino}, {"size", size}} {
		if f.v > math.MaxInt64 {
			return Stat{}, fmt.Errorf("adbwire: stat %s=%d has its high bit set and does not fit in an int64: %w", f.name, f.v, ErrProtocol)
		}
	}

	return Stat{
		Errno: le.Uint32(errnoField),
		Dev:   int64(dev),
		Ino:   int64(ino),
		Mode:  le.Uint32(rest[16:]),
		Nlink: le.Uint32(rest[20:]),
		UID:   le.Uint32(rest[24:]),
		GID:   le.Uint32(rest[28:]),
		Size:  int64(size),
		Atime: int64(le.Uint64(rest[40:])),
		Mtime: int64(le.Uint64(rest[48:])),
		Ctime: int64(le.Uint64(rest[56:])),
	}, nil
}

// List streams one directory level (LIS2), calling fn for each entry. Recursion
// is the caller's job: adbd lists one level only.
//
// "." and ".." are not returned by adbd, but List passes through whatever the
// device sends and does not filter them — the caller owns that decision, and
// relying on adbd's current behaviour would be relying on something this package
// cannot enforce.
//
// If fn returns an error, List stops, returns it wrapped, and retires the
// session: the rest of the stream is still on the socket and cannot be accounted
// for.
func (s *SyncConn) List(ctx context.Context, path string, fn func(Dirent) error) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if err := s.alive(); err != nil {
		return err
	}

	if fn == nil {
		return errors.New("adbwire: List needs a callback")
	}

	op := syncList + " " + strconv.Quote(path)

	if err := s.sendPath(ctx, syncList, path, defaultHostDeadline); err != nil {
		return s.kill(err)
	}

	// The 68 bytes of a DNT2 record that follow its ID and errno, plus the
	// 4-byte name length.
	body := make([]byte, syncDentBodyLen-syncArgLen)

	for {
		replyID, arg, hdr, err := s.readSyncHeader(ctx, op, defaultHostDeadline)
		if err != nil {
			return s.kill(err)
		}

		switch replyID {
		case syncDone:
			// MEASURED LANDMINE — do not "simplify" this read away.
			//
			// DONE is not a bare four-byte ID here: adbd writes a whole
			// dent_v2, so DONE carries a fully zeroed 72-byte dirent body that
			// must be consumed. A reader that stops at the ID leaves 72 stray
			// zero bytes in the stream and desyncs every later command on the
			// channel. When this was hit during protocol discovery it presented
			// as "all these directories are empty" — a confident, silent, wrong
			// answer rather than an error.
			//
			// The 8 bytes already read plus these are the full 76.
			if err := readFull(ctx, s.nc, op+" DONE body", body, defaultHostDeadline); err != nil {
				return s.kill(err)
			}

			return nil

		case syncDent:
			if err := readFull(ctx, s.nc, op+" DNT2 body", body, defaultHostDeadline); err != nil {
				return s.kill(err)
			}

			st, err := decodeStat(hdr[syncIDLen:], body[:len(body)-4])
			if err != nil {
				return s.kill(fmt.Errorf("adbwire: %s: %w", op, err))
			}

			nameLen := binary.LittleEndian.Uint32(body[len(body)-4:])
			if nameLen > syncMaxName {
				return s.kill(fmt.Errorf("adbwire: %s: entry name length %d is implausible: %w", op, nameLen, ErrProtocol))
			}

			name := make([]byte, nameLen)
			if err := readFull(ctx, s.nc, op+" DNT2 name", name, defaultHostDeadline); err != nil {
				return s.kill(err)
			}

			if err := fn(Dirent{Stat: st, Name: name}); err != nil {
				return s.kill(fmt.Errorf("adbwire: %s: callback stopped the listing, leaving the stream undrained: %w", op, err))
			}

		case syncFail:
			msg, err := s.readFailMessage(ctx, op, arg)
			if err != nil {
				return s.kill(err)
			}

			return s.kill(fmt.Errorf("adbwire: %s: %w", op, newSyncFailError(syncList, msg)))

		default:
			return s.kill(fmt.Errorf("adbwire: %s: reply ID %q, want %s, %s or %s: %w", op, replyID, syncDent, syncDone, syncFail, ErrProtocol))
		}
	}
}

// Recv streams a file's contents to w and returns the byte count (RECV).
//
// Measured behaviours this implements deliberately:
//
//   - A zero-byte file produces NO DATA packets at all, just an immediate DONE.
//     Zero bytes is success. An implementation that requires at least one DATA
//     packet breaks on empty files, and such files exist on real devices.
//   - The byte count matches the size the listing reported, exactly.
//   - Chunks are at most 64 KiB.
//   - Any RECV FAIL kills the session. Measured on fresh channels for "open
//     failed: No such file or directory", "open failed: Permission denied" and
//     "read failed: Is a directory" — the channel was dead after every one. The
//     returned error wraps ErrSyncSessionDead alongside a FailError carrying
//     adb's prose, and every later call on this SyncConn fails fast.
//
// RECV follows symlinks, while Lstat does not, so there is a real gap between
// what was stat'ed and what is read. That gap is the caller's to reason about.
func (s *SyncConn) Recv(ctx context.Context, path string, w io.Writer) (int64, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if err := s.alive(); err != nil {
		return 0, err
	}

	op := syncRecv + " " + strconv.Quote(path)

	if err := s.sendPath(ctx, syncRecv, path, defaultDataDeadline); err != nil {
		return 0, s.kill(err)
	}

	if s.buf == nil {
		s.buf = make([]byte, syncMaxChunk)
	}

	var total int64

	for {
		replyID, arg, _, err := s.readSyncHeader(ctx, op, defaultDataDeadline)
		if err != nil {
			return total, s.kill(err)
		}

		switch replyID {
		case syncDone:
			// DONE's four-byte argument was consumed with the ID above, the way
			// adb's own client reads it and the way SYNC.TXT describes it ("a
			// sync response DONE ... the length is ignored"). Nothing else
			// follows, and the session stays usable for the next command —
			// TestRecvZeroByteFile asserts exactly that by issuing a STA2
			// afterwards. Reading only the ID here would leave four stray zero
			// bytes and desync the channel, the same class of bug as the LIS2
			// terminator above.
			return total, nil

		case syncData:
			if arg > syncMaxChunk {
				return total, s.kill(fmt.Errorf("adbwire: %s: DATA chunk of %d bytes is over the measured %d byte maximum: %w", op, arg, syncMaxChunk, ErrProtocol))
			}

			chunk := s.buf[:arg]
			if err := readFull(ctx, s.nc, op+" DATA", chunk, defaultDataDeadline); err != nil {
				return total, s.kill(err)
			}

			n, err := w.Write(chunk)
			total += int64(n)

			if err != nil {
				return total, s.kill(fmt.Errorf("adbwire: %s: writing to the destination failed mid-transfer: %w", op, err))
			}

		case syncFail:
			msg, err := s.readFailMessage(ctx, op, arg)
			if err != nil {
				return total, s.kill(err)
			}

			return total, s.kill(fmt.Errorf("adbwire: %s: %w", op, newSyncFailError(syncRecv, msg)))

		default:
			return total, s.kill(fmt.Errorf("adbwire: %s: reply ID %q, want %s, %s or %s: %w", op, replyID, syncData, syncDone, syncFail, ErrProtocol))
		}
	}
}
