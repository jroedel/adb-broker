package adbsyncdb

import (
	"context"

	"github.com/jroedel/adb-broker/business/domain/device/devicebus"
	"github.com/jroedel/adb-broker/business/types/devicepath"
	"github.com/jroedel/adb-broker/business/types/errcode"
	"github.com/jroedel/adb-broker/business/types/filekind"
	"github.com/jroedel/adb-broker/foundation/adbwire"
)

// maxWalkDepth bounds how deep a walk will descend.
//
// The depth of the tree is device-supplied: every level below the root exists because adbd
// said an entry there was a directory, and adbd applies no confinement or sanity rule of
// its own. Nothing in the protocol stops it answering "this directory contains a
// directory" forever. Path length would eventually stop it — adbwire refuses a path over
// 4096 bytes — but that is an accident of the framing rather than a decision, and a walk
// thousands of levels deep is not a listing anyone asked for. 128 is far past any real
// media tree.
const maxWalkDepth = 128

// walker carries one List invocation's state. It is not safe for concurrent use and does
// not need to be: the Store holds its mutex for the whole walk, because a sync channel
// cannot carry two interleaved exchanges.
type walker struct {
	store    *Store
	sess     *session
	vol      devicepath.Volume
	fn       func(devicebus.FileRecord) error
	maxDepth int

	summary devicebus.ListSummary

	// callerErr holds the error fn returned, if any. adbwire wraps a callback error
	// together with ErrSyncSessionDead — correctly, since the rest of the listing is still
	// on the socket — and the caller should get its own error back rather than that
	// wrapping.
	callerErr error

	// rootRechecked records that the volume root has already been re-stat'ed during this
	// walk. The re-check happens at most once per List invocation, which is the whole point
	// of it: see recheckRoot.
	rootRechecked bool
}

// walkRoot checks the listing root and then walks it.
//
// The root's own failures are returned as an error rather than recorded per-path, because
// they end the source rather than one file: a consumer that cannot read a root skips that
// root, and a per-path warning would leave it believing the root was read and empty.
func (w *walker) walkRoot(ctx context.Context, root devicepath.AuthorizedPath) error {
	// LST2, not STA2: a root that is a symlink is refused here rather than followed. The
	// one symlink this binary follows is the compiled volume root, in ResolveVolume.
	st, err := w.sess.sc.Lstat(ctx, toSyncPath(root))
	if err != nil {
		w.store.dropSessionIfDeadLocked(err)

		return codeErr(codeForWire(err, errcode.CodeDeviceDisconnected), err, "lstat the listing root %q", root.String())
	}

	switch {
	case st.Errno != 0:
		// Deliberate wording: the root could not be READ. Measured,
		// /data/data/com.android.providers.media answers error=2 although it exists, so
		// ENOENT from adbd is not evidence of absence and must never be reported as such.
		return codeErr(codeForErrno(st.Errno, errcode.CodeRootNotFound), nil, "the listing root %q could not be read (the device answered errno %d, which does not prove the path is absent)", root.String(), st.Errno)

	case !filekind.ParseKind(st.Mode).IsDir():
		return codeErr(errcode.CodeNotADirectory, nil, "the listing root %q is a %s (mode 0o%o), not a directory", root.String(), filekind.ParseKind(st.Mode), st.Mode)

	case !w.vol.Contains(st.Dev):
		// The root itself is not on the volume that was pinned moments ago. That is the
		// ground moving, not a policy question about one file, so it aborts the source.
		return codeErr(errcode.CodeVolumeUnresolved, nil, "the listing root %q is on dev=%d, not the pinned volume dev=%d", root.String(), st.Dev, w.vol.Dev())
	}

	return w.walkDir(ctx, root, 1)
}

// walkDir lists one directory and then descends into the subdirectories it accepted.
//
// depth is the depth of the ENTRIES this call will see: the root's own children are at
// depth 1, which is what MaxDepth: 1 means.
//
// The two phases are not a style choice. adbwire holds the sync session's lock for the
// whole of one LIS2 listing, so issuing any other sync command from inside the callback
// would deadlock — and every confinement re-check is a sync command. So one level's
// directory names are collected while the listing streams, and the descents happen after it
// has finished. Regular files are still emitted from inside the callback, as each one is
// discovered: nothing buffers a listing, only the directory names of a single level.
func (w *walker) walkDir(ctx context.Context, dir devicepath.AuthorizedPath, depth int) error {
	if err := ctx.Err(); err != nil {
		return codeErr(errcode.CodeInternal, err, "listing %q was cancelled", dir.String())
	}

	if depth > maxWalkDepth {
		w.summary.Errors = append(w.summary.Errors, devicebus.PathError{Path: dir, Code: errcode.CodePathDenied})

		return nil
	}

	// descend is decided per level rather than per entry: below the requested depth there
	// is no reason to name a child path at all.
	descend := w.maxDepth == 0 || depth < w.maxDepth

	var (
		children    []devicepath.AuthorizedPath
		sawOffPin   bool
		listErrHint = dir
	)

	err := w.sess.sc.List(ctx, toSyncPath(dir), func(d adbwire.Dirent) error {
		child, keep := w.classify(dir, d, &sawOffPin)
		if keep && descend {
			children = append(children, child)
		}

		return w.callerErr
	})
	if err != nil {
		w.store.dropSessionIfDeadLocked(err)

		if w.callerErr != nil {
			// The caller stopped the walk. Its own error is what it gets back; the session
			// is gone either way, and the next operation rebuilds it.
			return w.callerErr
		}

		// A listing that failed part way is not an empty listing. CodeDeviceDisconnected is
		// fatal in the taxonomy, deliberately: a truncated listing reported as a per-file
		// warning would let a consumer treat "half the tree" as "the whole tree".
		return codeErr(codeForWire(err, errcode.CodeDeviceDisconnected), err, "listing %q", listErrHint.String())
	}

	// Now that the listing has finished the session is usable again, so this is the first
	// point at which the volume can be re-checked. See recheckRoot for why one entry off
	// the pin is not treated as a per-file denial.
	if sawOffPin {
		if err := w.recheckRoot(ctx); err != nil {
			return err
		}
	}

	for _, child := range children {
		if err := w.descend(ctx, child, depth+1); err != nil {
			return err
		}
	}

	return nil
}

// classify applies the per-entry rules to one dirent, emitting a record for a regular file
// and reporting whether the entry is a directory this walk should descend into.
//
// It runs inside the LIS2 callback, so it must not issue a sync command: the session's lock
// is held by the listing. Anything needing a round trip is deferred to the caller — that is
// what sawOffPin is for.
func (w *walker) classify(dir devicepath.AuthorizedPath, d adbwire.Dirent, sawOffPin *bool) (devicepath.AuthorizedPath, bool) {
	// adbd does not return "." or "..", measured. They are skipped anyway: relying on the
	// device to filter the two names that mean "go back up" is relying on the wrong party.
	if name := string(d.Name); name == "." || name == ".." {
		return devicepath.AuthorizedPath{}, false
	}

	// The errno check comes first because a dirent that carries one carries nothing else:
	// its dev is zero, and testing that against the pin would read as "this entry is on
	// another filesystem" and could trip the volume re-check for a path that was merely
	// unreadable.
	if d.Errno != 0 {
		child, ok := w.childOf(dir, d)
		if !ok {
			return devicepath.AuthorizedPath{}, false
		}

		w.summary.Errors = append(w.summary.Errors, devicebus.PathError{
			Path: child,
			Code: codeForErrno(d.Errno, errcode.CodePathNotFound),
		})

		return devicepath.AuthorizedPath{}, false
	}

	// The dev check. An entry on any other filesystem is refused regardless of its name or
	// its kind: measured, media is dev=190, /data is dev=65088 and the root filesystem is
	// dev=65034, so a symlink or bind mount leading off shared storage is caught by where it
	// leads. A bind mount is caught by nothing else — no string rule can see one.
	if !w.vol.Contains(d.Dev) {
		w.summary.RefusedEntries++
		*sawOffPin = true

		return devicepath.AuthorizedPath{}, false
	}

	switch kind := filekind.ParseKind(d.Mode); kind {
	case filekind.KindDir:
		child, ok := w.childOf(dir, d)

		return child, ok

	case filekind.KindRegular:
		w.emit(dir, d)

		return devicepath.AuthorizedPath{}, false

	default:
		// A symlink, socket, FIFO, block or character device. The dev check above cannot
		// catch a symlink that stays on the volume — the link itself lives on shared
		// storage whatever it points at — so the kind check is what refuses it, and it is
		// never followed and never emitted. Counting it keeps the cost of that rule visible
		// instead of silent.
		w.summary.RefusedEntries++

		return devicepath.AuthorizedPath{}, false
	}
}

// emit converts one accepted regular file and streams it to the caller's callback.
func (w *walker) emit(dir devicepath.AuthorizedPath, d adbwire.Dirent) {
	child, ok := w.childOf(dir, d)
	if !ok {
		return
	}

	rec, err := toBusFileRecord(child, d.Stat)
	if err != nil {
		// The device described a file this broker cannot represent. It is reported rather
		// than emitted with a repaired value, because a repaired byte count is a wrong
		// number wearing a measurement's clothes.
		w.summary.Errors = append(w.summary.Errors, devicebus.PathError{Path: child, Code: errcode.CodeInternal})

		return
	}

	if err := w.fn(rec); err != nil {
		w.callerErr = err

		return
	}

	w.summary.Files++
}

// childOf builds the path for one directory entry.
//
// It goes through AuthorizedPath.Child, never string concatenation. Child rejects a name
// containing '/' or NUL, rejects "." and "..", and then revalidates the whole joined path
// against the allowlist — so a device-supplied name cannot assemble a path
// ParseAuthorizedPath would have refused. That is the guarantee that makes the rest of this
// walk safe to write: names arrive from adbd, which confines nothing.
//
// A name the constructor refuses is reported against the parent directory, which is a path
// that can legitimately be named. Recording nothing would be worse — the entry would vanish
// from both the records and the errors.
func (w *walker) childOf(dir devicepath.AuthorizedPath, d adbwire.Dirent) (devicepath.AuthorizedPath, bool) {
	child, err := dir.Child(d.Name)
	if err != nil {
		w.summary.Errors = append(w.summary.Errors, devicebus.PathError{Path: dir, Code: errcode.CodePathDenied})

		return devicepath.AuthorizedPath{}, false
	}

	return child, true
}

// descend re-checks a subdirectory and walks it.
//
// The stat here is not redundant. The dev and mode this entry was accepted on came from a
// record the DEVICE produced while listing the parent, and confinement is re-established at
// each step rather than inherited from that record: this is a fresh LST2 against the child
// itself, immediately before it is opened. It is also where a per-path errno surfaces —
// in-band, with the channel intact — which is what lets one unreadable subdirectory be
// recorded and stepped over instead of ending the walk.
func (w *walker) descend(ctx context.Context, child devicepath.AuthorizedPath, depth int) error {
	st, err := w.sess.sc.Lstat(ctx, toSyncPath(child))
	if err != nil {
		w.store.dropSessionIfDeadLocked(err)

		return codeErr(codeForWire(err, errcode.CodeDeviceDisconnected), err, "lstat %q before descending into it", child.String())
	}

	switch {
	case st.Errno != 0:
		// Recorded and stepped over. A subdirectory this run may not read says nothing
		// about its siblings, so ending the walk here would throw away the rest of the
		// tree over one permission.
		w.summary.Errors = append(w.summary.Errors, devicebus.PathError{
			Path: child,
			Code: codeForErrno(st.Errno, errcode.CodePathNotFound),
		})

		return nil

	case !w.vol.Contains(st.Dev):
		// It was on the pinned volume when the parent listed it and is not now.
		w.summary.RefusedEntries++

		return w.recheckRoot(ctx)

	case !filekind.ParseKind(st.Mode).IsDir():
		// The parent's listing called it a directory and this stat does not. Refused
		// without argument: whatever happened in between, it is not something to descend
		// into.
		w.summary.RefusedEntries++

		return nil
	}

	return w.walkDir(ctx, child, depth)
}

// recheckRoot re-stats the volume root once per walk, after an entry was found off the pin,
// and aborts the whole listing if the pin no longer holds.
//
// This exists because of what the alternative looks like. A replug or a storage remount
// changes the media volume's dev with no adversary involved anywhere, and every entry under
// the root is then off the pin. Refusing them one by one would produce a thousand
// path_denied errors, which reads as "these files are all forbidden" when what happened is
// "the ground moved" — and a consumer acting on the first reading would be acting on a
// misdiagnosis. So the volume is asked once, and if it changed the listing fails as a whole,
// with volume_unresolved.
//
// If the pin still holds, the offending entry really is off the volume: a symlink or a bind
// mount leading somewhere else. It stays counted in RefusedEntries and the walk continues.
//
// STA2 is used here, against the compiled devicepath.VolumeRoot constant and never against
// a device-supplied name — the same single deliberate symlink follow as ResolveVolume, for
// the same measured reason: /sdcard is itself a symlink.
func (w *walker) recheckRoot(ctx context.Context) error {
	if w.rootRechecked {
		return nil
	}

	w.rootRechecked = true

	st, err := w.sess.sc.Stat(ctx, devicepath.VolumeRoot)
	if err != nil {
		w.store.dropSessionIfDeadLocked(err)

		return codeErr(errcode.CodeVolumeUnresolved, err, "re-stat %s after an entry was found off the pinned volume", devicepath.VolumeRoot)
	}

	switch {
	case st.Errno != 0:
		return codeErr(errcode.CodeVolumeUnresolved, nil, "%s could not be read on re-check (the device answered errno %d)", devicepath.VolumeRoot, st.Errno)

	case !w.vol.Contains(st.Dev):
		return codeErr(errcode.CodeVolumeUnresolved, nil, "%s now resolves to dev=%d, not the pinned dev=%d; the storage volume changed during this listing", devicepath.VolumeRoot, st.Dev, w.vol.Dev())
	}

	return nil
}
