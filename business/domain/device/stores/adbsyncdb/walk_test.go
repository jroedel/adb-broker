package adbsyncdb

import (
	"errors"
	"fmt"
	"slices"
	"strings"
	"testing"

	"github.com/jroedel/adb-broker/business/domain/device/devicebus"
	"github.com/jroedel/adb-broker/business/types/devicepath"
	"github.com/jroedel/adb-broker/business/types/errcode"
	"github.com/jroedel/adb-broker/business/types/filekind"
	"github.com/jroedel/adb-broker/foundation/adbwire"
)

// listAll walks root with an unlimited depth and returns everything the walk produced.
func listAll(t *testing.T, st *Store, vol devicepath.Volume, root string) ([]devicebus.FileRecord, devicebus.ListSummary, error) {
	t.Helper()

	var recs []devicebus.FileRecord

	summary, err := st.List(
		t.Context(),
		devicebus.ListInput{Root: devicepath.MustParseAuthorizedPath(root)},
		vol,
		collect(&recs),
	)

	return recs, summary, err
}

// Only regular files are emitted, in discovery order, and each one reaches the callback as
// it is found rather than at the end.
//
// Note the shape of the fixture: the root holds only directories. Measured, that is what a
// real allowlist root looks like — there is not a single regular file at the top level of
// any of the six roots; all 7 entries of /sdcard/DCIM and all 8 of /sdcard/Movies are
// directories — so a fixture with files at the root would be testing a device that does not
// exist.
func TestListEmitsOnlyRegularFilesInDiscoveryOrder(t *testing.T) {
	st, tr := newTestStore()
	vol := pinVolume(t, st)

	tr.fs.lstat[testRoot] = dirStat(devMedia)
	tr.fs.list[testRoot] = []adbwire.Dirent{
		dirent("Camera", dirStat(devMedia)),
		dirent("Screenshots", dirStat(devMedia)),
	}

	tr.fs.lstat[testRoot+"/Camera"] = dirStat(devMedia)
	tr.fs.list[testRoot+"/Camera"] = []adbwire.Dirent{
		dirent("IMG_0001.jpg", regularStat(1024, devMedia)),
		dirent("IMG_0002.jpg", regularStat(2048, devMedia)),
		dirent("thumbs", dirStat(devMedia)),
	}

	tr.fs.lstat[testRoot+"/Camera/thumbs"] = dirStat(devMedia)
	tr.fs.list[testRoot+"/Camera/thumbs"] = []adbwire.Dirent{
		dirent("t1.jpg", regularStat(64, devMedia)),
	}

	tr.fs.lstat[testRoot+"/Screenshots"] = dirStat(devMedia)
	tr.fs.list[testRoot+"/Screenshots"] = []adbwire.Dirent{
		dirent("s1.png", regularStat(512, devMedia)),
	}

	// Streaming evidence: the ops recorded at the moment each record arrived.
	var recs []devicebus.FileRecord
	opsAt := map[string]int{}

	summary, err := st.List(
		t.Context(),
		devicebus.ListInput{Root: devicepath.MustParseAuthorizedPath(testRoot)},
		vol,
		func(rec devicebus.FileRecord) error {
			recs = append(recs, rec)
			opsAt[rec.Path.String()] = len(tr.ops)

			return nil
		},
	)
	if err != nil {
		t.Fatalf("List: %v", err)
	}

	want := []string{
		testRoot + "/Camera/IMG_0001.jpg",
		testRoot + "/Camera/IMG_0002.jpg",
		testRoot + "/Camera/thumbs/t1.jpg",
		testRoot + "/Screenshots/s1.png",
	}

	if got := paths(recs); !slices.Equal(got, want) {
		t.Errorf("paths = %v, want %v", got, want)
	}

	switch {
	case summary.Files != len(want):
		t.Errorf("Files = %d, want %d", summary.Files, len(want))
	case summary.RefusedEntries != 0:
		t.Errorf("RefusedEntries = %d, want 0", summary.RefusedEntries)
	case len(summary.Errors) != 0:
		t.Errorf("Errors = %v, want none", summary.Errors)
	}

	// The first record arrived before the last directory had been listed at all, which is
	// what "never buffer the whole listing" means in practice.
	firstAt := opsAt[want[0]]
	if firstAt >= len(tr.ops) {
		t.Errorf("the first record arrived after the walk finished (%d ops of %d)", firstAt, len(tr.ops))
	}

	if idx := slices.Index(tr.ops, "LIS2 "+testRoot+"/Screenshots"); idx >= 0 && idx < firstAt {
		t.Error("the whole tree was listed before the first record was emitted")
	}

	for _, rec := range recs {
		if !rec.Kind.IsRegular() {
			t.Errorf("%q was emitted as %s", rec.Path, rec.Kind)
		}
	}
}

// Records carry the natives the device reported, parsed but not repaired.
func TestListRecordCarriesTheDeviceValues(t *testing.T) {
	st, tr := newTestStore()
	vol := pinVolume(t, st)

	st2 := regularStat(27190943, devMedia)
	st2.Mtime = 1709828653

	tr.fs.lstat[testRoot] = dirStat(devMedia)
	tr.fs.list[testRoot] = []adbwire.Dirent{dirent("VID_0001.mp4", st2)}

	recs, _, err := listAll(t, st, vol, testRoot)
	if err != nil {
		t.Fatalf("List: %v", err)
	}

	if len(recs) != 1 {
		t.Fatalf("records = %d, want 1", len(recs))
	}

	switch rec := recs[0]; {
	case rec.Size != 27190943:
		t.Errorf("Size = %d, want 27190943 (size is 64-bit over the V2 commands)", rec.Size)
	case rec.Mtime.Seconds() != 1709828653:
		t.Errorf("Mtime = %d, want the value the device reported", rec.Mtime.Seconds())
	case rec.Kind != filekind.KindRegular:
		t.Errorf("Kind = %s, want regular", rec.Kind)
	}
}

// An entry on /data is refused whatever its name and whatever its kind. This is the check a
// bind mount cannot step around, because no rule about spellings can see a mount.
func TestListRefusesAnEntryOffThePinnedVolume(t *testing.T) {
	st, tr := newTestStore()
	vol := pinVolume(t, st)

	tr.fs.lstat[testRoot] = dirStat(devMedia)
	tr.fs.list[testRoot] = []adbwire.Dirent{
		dirent("ok.jpg", regularStat(10, devMedia)),
		dirent("escape.jpg", regularStat(10, devData)),
	}

	// The volume root still resolves to the pinned dev, so the entry really is off the
	// volume rather than the volume having moved.
	tr.fs.stat[devicepath.VolumeRoot] = []adbwire.Stat{dirStat(devMedia), dirStat(devMedia)}

	recs, summary, err := listAll(t, st, vol, testRoot)
	if err != nil {
		t.Fatalf("List: %v", err)
	}

	switch {
	case !slices.Equal(paths(recs), []string{testRoot + "/ok.jpg"}):
		t.Errorf("paths = %v, want only the on-volume file", paths(recs))
	case summary.RefusedEntries != 1:
		t.Errorf("RefusedEntries = %d, want 1", summary.RefusedEntries)
	case len(summary.Errors) != 0:
		t.Errorf("Errors = %v, want none: an off-volume entry is a refusal, not a path error", summary.Errors)
	}
}

// A symlink on the CORRECT dev is still refused: the link itself lives on shared storage
// whatever it points at, so the dev check cannot see it and the kind check must.
func TestListRefusesASymlinkOnThePinnedVolume(t *testing.T) {
	st, tr := newTestStore()
	vol := pinVolume(t, st)

	tr.fs.lstat[testRoot] = dirStat(devMedia)
	tr.fs.list[testRoot] = []adbwire.Dirent{
		dirent("ok.jpg", regularStat(10, devMedia)),
		dirent("sneaky.jpg", statWith(modeSymlink, devMedia)),
	}

	recs, summary, err := listAll(t, st, vol, testRoot)
	if err != nil {
		t.Fatalf("List: %v", err)
	}

	switch {
	case !slices.Equal(paths(recs), []string{testRoot + "/ok.jpg"}):
		t.Errorf("paths = %v, want only the regular file", paths(recs))
	case summary.RefusedEntries != 1:
		t.Errorf("RefusedEntries = %d, want 1", summary.RefusedEntries)
	}

	// Never followed: no stat and no listing of the link.
	for _, op := range tr.ops {
		if strings.Contains(op, "sneaky.jpg") {
			t.Errorf("the symlink was touched: %q", op)
		}
	}
}

// Sockets, FIFOs, block and character devices are not files a broker mediating a phone's
// storage has any business relaying.
func TestListRefusesNonRegularKinds(t *testing.T) {
	st, tr := newTestStore()
	vol := pinVolume(t, st)

	tr.fs.lstat[testRoot] = dirStat(devMedia)
	tr.fs.list[testRoot] = []adbwire.Dirent{
		dirent("sock", statWith(modeSocket, devMedia)),
		dirent("pipe", statWith(modeFIFO, devMedia)),
		dirent("tty", statWith(modeChar, devMedia)),
		dirent("disk", statWith(modeBlock, devMedia)),
		dirent("ok.jpg", regularStat(10, devMedia)),
	}

	recs, summary, err := listAll(t, st, vol, testRoot)
	if err != nil {
		t.Fatalf("List: %v", err)
	}

	switch {
	case !slices.Equal(paths(recs), []string{testRoot + "/ok.jpg"}):
		t.Errorf("paths = %v, want only the regular file", paths(recs))
	case summary.RefusedEntries != 4:
		t.Errorf("RefusedEntries = %d, want 4", summary.RefusedEntries)
	case len(summary.Errors) != 0:
		t.Errorf("Errors = %v, want none", summary.Errors)
	}
}

func TestListMaxDepth(t *testing.T) {
	// A root with a regular file directly in it is not what a real allowlist root looks
	// like — measured, every top-level entry of the real roots is a directory — but a depth
	// test needs something at depth 1 to find, so the fixture is deliberately unlike the
	// device here.
	setup := func(t *testing.T) (*Store, devicepath.Volume, *fakeTransport) {
		t.Helper()

		st, tr := newTestStore()
		vol := pinVolume(t, st)

		tr.fs.lstat[testRoot] = dirStat(devMedia)
		tr.fs.list[testRoot] = []adbwire.Dirent{
			dirent("top.jpg", regularStat(1, devMedia)),
			dirent("Camera", dirStat(devMedia)),
		}

		tr.fs.lstat[testRoot+"/Camera"] = dirStat(devMedia)
		tr.fs.list[testRoot+"/Camera"] = []adbwire.Dirent{
			dirent("deep.jpg", regularStat(2, devMedia)),
			dirent("thumbs", dirStat(devMedia)),
		}

		tr.fs.lstat[testRoot+"/Camera/thumbs"] = dirStat(devMedia)
		tr.fs.list[testRoot+"/Camera/thumbs"] = []adbwire.Dirent{
			dirent("t1.jpg", regularStat(3, devMedia)),
		}

		return st, vol, tr
	}

	t.Run("depth 1 is immediate children only", func(t *testing.T) {
		st, vol, tr := setup(t)

		var recs []devicebus.FileRecord

		if _, err := st.List(t.Context(), devicebus.ListInput{Root: devicepath.MustParseAuthorizedPath(testRoot), MaxDepth: 1}, vol, collect(&recs)); err != nil {
			t.Fatalf("List: %v", err)
		}

		if got := paths(recs); !slices.Equal(got, []string{testRoot + "/top.jpg"}) {
			t.Errorf("paths = %v, want only the immediate child", got)
		}

		// The subdirectory is not even named, let alone listed.
		for _, op := range tr.ops {
			if strings.Contains(op, "/Camera") {
				t.Errorf("descended past depth 1: %q", op)
			}
		}
	})

	t.Run("depth 0 is unlimited", func(t *testing.T) {
		st, vol, _ := setup(t)

		recs, _, err := listAll(t, st, vol, testRoot)
		if err != nil {
			t.Fatalf("List: %v", err)
		}

		want := []string{
			testRoot + "/top.jpg",
			testRoot + "/Camera/deep.jpg",
			testRoot + "/Camera/thumbs/t1.jpg",
		}

		if got := paths(recs); !slices.Equal(got, want) {
			t.Errorf("paths = %v, want %v", got, want)
		}
	})

	t.Run("depth 2 stops one level down", func(t *testing.T) {
		st, vol, _ := setup(t)

		var recs []devicebus.FileRecord

		if _, err := st.List(t.Context(), devicebus.ListInput{Root: devicepath.MustParseAuthorizedPath(testRoot), MaxDepth: 2}, vol, collect(&recs)); err != nil {
			t.Fatalf("List: %v", err)
		}

		want := []string{testRoot + "/top.jpg", testRoot + "/Camera/deep.jpg"}
		if got := paths(recs); !slices.Equal(got, want) {
			t.Errorf("paths = %v, want %v", got, want)
		}
	})
}

// A subdirectory this run may not read says nothing about its siblings, so it is recorded
// and stepped over. The errno arrives in-band with the channel intact, which is what makes
// continuing possible at all.
func TestListRecordsAnUnreadableSubdirectoryAndContinues(t *testing.T) {
	st, tr := newTestStore()
	vol := pinVolume(t, st)

	tr.fs.lstat[testRoot] = dirStat(devMedia)
	tr.fs.list[testRoot] = []adbwire.Dirent{
		dirent("locked", dirStat(devMedia)),
		dirent("open", dirStat(devMedia)),
	}

	tr.fs.lstat[testRoot+"/locked"] = adbwire.Stat{Errno: errnoEACCES}

	tr.fs.lstat[testRoot+"/open"] = dirStat(devMedia)
	tr.fs.list[testRoot+"/open"] = []adbwire.Dirent{dirent("ok.jpg", regularStat(10, devMedia))}

	recs, summary, err := listAll(t, st, vol, testRoot)
	if err != nil {
		t.Fatalf("List: %v, want the walk to continue past one unreadable directory", err)
	}

	if got := paths(recs); !slices.Equal(got, []string{testRoot + "/open/ok.jpg"}) {
		t.Errorf("paths = %v, want the sibling's file", got)
	}

	want := []devicebus.PathError{{
		Path: devicepath.MustParseAuthorizedPath(testRoot + "/locked"),
		Code: errcode.CodePermissionDenied,
	}}

	if !slices.Equal(summary.Errors, want) {
		t.Errorf("Errors = %v, want %v", summary.Errors, want)
	}
}

// An errno on a dirent is recorded too. adbd normally reports 0 for every entry of a
// readable directory, but the field exists and nothing guarantees it stays that way.
func TestListRecordsADirentErrno(t *testing.T) {
	st, tr := newTestStore()
	vol := pinVolume(t, st)

	tr.fs.lstat[testRoot] = dirStat(devMedia)
	tr.fs.list[testRoot] = []adbwire.Dirent{
		dirent("gone.jpg", adbwire.Stat{Errno: errnoENOENT}),
		dirent("ok.jpg", regularStat(10, devMedia)),
	}

	// A dirent carrying an errno carries dev=0. If the dev check ran first, that would read
	// as "this entry is on another filesystem" and could trip the volume re-check, so this
	// also asserts the order of the two checks.
	recs, summary, err := listAll(t, st, vol, testRoot)
	if err != nil {
		t.Fatalf("List: %v", err)
	}

	switch {
	case !slices.Equal(paths(recs), []string{testRoot + "/ok.jpg"}):
		t.Errorf("paths = %v", paths(recs))
	case len(summary.Errors) != 1 || summary.Errors[0].Code != errcode.CodePathNotFound:
		t.Errorf("Errors = %v, want one path_not_found", summary.Errors)
	case summary.RefusedEntries != 0:
		t.Errorf("RefusedEntries = %d, want 0: an errno is an error, not a refusal", summary.RefusedEntries)
	}

	if ops := tr.opsWith("STA2 " + devicepath.VolumeRoot); len(ops) != 1 {
		t.Errorf("STA2 %s ops = %v, want only the original pin", devicepath.VolumeRoot, ops)
	}
}

func TestListRootFailures(t *testing.T) {
	tests := []struct {
		name  string
		reply adbwire.Stat
		want  errcode.Code
	}{
		{
			// Measured: /data/data/com.android.providers.media answers error=2 although it
			// exists, so this code must never be worded as proof the tree is gone.
			name:  "errno 2",
			reply: adbwire.Stat{Errno: errnoENOENT},
			want:  errcode.CodeRootNotFound,
		},
		{
			name:  "errno 13",
			reply: adbwire.Stat{Errno: errnoEACCES},
			want:  errcode.CodePermissionDenied,
		},
		{
			// Neither ENOENT nor EACCES: an errno this broker has not measured (EIO,
			// say). This is the case codeForErrno's old hardcoded default got wrong —
			// it named the failure CodeTransferFailed, a code that means "one file's
			// transfer failed," even though walkRoot never attempts a transfer at all.
			// The root case wants the same code as errno 2: the root could not be
			// read, whatever the specific errno.
			name:  "unmeasured errno",
			reply: adbwire.Stat{Errno: 5}, // EIO
			want:  errcode.CodeRootNotFound,
		},
		{
			name:  "regular file",
			reply: regularStat(10, devMedia),
			want:  errcode.CodeNotADirectory,
		},
		{
			// LST2 does not follow symlinks, so a symlinked root lands here rather than
			// being resolved to whatever it points at.
			name:  "symlink",
			reply: statWith(modeSymlink, devMedia),
			want:  errcode.CodeNotADirectory,
		},
		{
			name:  "off the pinned volume",
			reply: dirStat(devData),
			want:  errcode.CodeVolumeUnresolved,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			st, tr := newTestStore()
			vol := pinVolume(t, st)

			tr.fs.lstat[testRoot] = tc.reply

			_, _, err := listAll(t, st, vol, testRoot)
			if got := codeOf(t, err); got != tc.want {
				t.Fatalf("code = %s, want %s", got, tc.want)
			}

			if ops := tr.opsWith("LIS2"); len(ops) != 0 {
				t.Errorf("the root was listed anyway: %v", ops)
			}
		})
	}

	t.Run("the message does not claim absence", func(t *testing.T) {
		st, tr := newTestStore()
		vol := pinVolume(t, st)

		tr.fs.lstat[testRoot] = adbwire.Stat{Errno: errnoENOENT}

		_, _, err := listAll(t, st, vol, testRoot)
		if !strings.Contains(err.Error(), "could not be read") {
			t.Errorf("error %q should say the root could not be read, since errno 2 does not prove absence", err)
		}
	})
}

// adbd does not send "." or "..", measured. They are skipped anyway, because relying on the
// device to filter the two names that mean "go back up" is relying on the wrong party.
func TestListSkipsDotEntries(t *testing.T) {
	st, tr := newTestStore()
	vol := pinVolume(t, st)

	tr.fs.lstat[testRoot] = dirStat(devMedia)
	tr.fs.list[testRoot] = []adbwire.Dirent{
		dirent(".", dirStat(devMedia)),
		dirent("..", dirStat(devMedia)),
		dirent("ok.jpg", regularStat(10, devMedia)),
	}

	recs, summary, err := listAll(t, st, vol, testRoot)
	if err != nil {
		t.Fatalf("List: %v", err)
	}

	switch {
	case !slices.Equal(paths(recs), []string{testRoot + "/ok.jpg"}):
		t.Errorf("paths = %v", paths(recs))
	case len(summary.Errors) != 0:
		t.Errorf("Errors = %v, want none", summary.Errors)
	}

	// No recursion, and no attempt to name them: Child would refuse both, but the walk must
	// not even ask.
	for _, op := range tr.ops {
		if strings.HasSuffix(op, "/.") || strings.HasSuffix(op, "/..") {
			t.Errorf("a traversal segment was followed: %q", op)
		}
	}
}

// A device filename is a byte string. Coercing an invalid one to UTF-8 would produce a name
// that cannot be fetched, so the bytes survive into the record unchanged.
func TestListPreservesInvalidUTF8Names(t *testing.T) {
	st, tr := newTestStore()
	vol := pinVolume(t, st)

	name := []byte{0xff, 0xfe, 'I', 'M', 'G', '.', 'j', 'p', 'g'}

	tr.fs.lstat[testRoot] = dirStat(devMedia)
	tr.fs.list[testRoot] = []adbwire.Dirent{direntBytes(name, regularStat(10, devMedia))}

	recs, _, err := listAll(t, st, vol, testRoot)
	if err != nil {
		t.Fatalf("List: %v", err)
	}

	if len(recs) != 1 {
		t.Fatalf("records = %d, want 1", len(recs))
	}

	want := append([]byte(testRoot+"/"), name...)
	if got := []byte(recs[0].Path.String()); !slices.Equal(got, want) {
		t.Errorf("path bytes = %v, want %v", got, want)
	}
}

// The measured reason this exists: a replug or a storage remount changes the media volume's
// dev with no adversary involved, and every entry is then off the pin. Refusing them one by
// one reads as "these files are all forbidden" when what happened is "the ground moved".
func TestListAbortsWhenTheVolumeChangesMidWalk(t *testing.T) {
	st, tr := newTestStore()
	vol := pinVolume(t, st)

	tr.fs.lstat[testRoot] = dirStat(devMedia)
	tr.fs.list[testRoot] = []adbwire.Dirent{
		dirent("a.jpg", regularStat(10, devMedia)),
		dirent("b.jpg", regularStat(10, devData)),
		dirent("c.jpg", regularStat(10, devData)),
		dirent("d.jpg", regularStat(10, devData)),
	}

	// The pin held when it was taken; on the re-check the root is on another filesystem.
	tr.fs.stat[devicepath.VolumeRoot] = []adbwire.Stat{dirStat(devMedia), dirStat(devRootFS)}

	recs, summary, err := listAll(t, st, vol, testRoot)

	if got := codeOf(t, err); got != errcode.CodeVolumeUnresolved {
		t.Fatalf("code = %s, want %s", got, errcode.CodeVolumeUnresolved)
	}

	// No denial storm: the whole listing failed once, rather than every file failing.
	if len(summary.Errors) != 0 {
		t.Errorf("Errors = %v, want none: one abort, not a per-file denial storm", summary.Errors)
	}

	// The root is re-stat'ed exactly once: once for the original pin, once for the check.
	if ops := tr.opsWith("STA2 " + devicepath.VolumeRoot); len(ops) != 2 {
		t.Errorf("STA2 %s ops = %v, want the pin plus exactly one re-check", devicepath.VolumeRoot, ops)
	}

	if len(recs) > 1 {
		t.Errorf("paths = %v, want at most the one file discovered before the abort", paths(recs))
	}
}

// The re-check is once per invocation, not once per off-volume entry.
func TestListRechecksTheRootOnlyOnce(t *testing.T) {
	st, tr := newTestStore()
	vol := pinVolume(t, st)

	tr.fs.lstat[testRoot] = dirStat(devMedia)
	tr.fs.list[testRoot] = []adbwire.Dirent{
		dirent("one.jpg", regularStat(10, devData)),
		dirent("Camera", dirStat(devMedia)),
	}

	tr.fs.lstat[testRoot+"/Camera"] = dirStat(devMedia)
	tr.fs.list[testRoot+"/Camera"] = []adbwire.Dirent{
		dirent("two.jpg", regularStat(10, devData)),
		dirent("three.jpg", regularStat(10, devData)),
	}

	tr.fs.stat[devicepath.VolumeRoot] = []adbwire.Stat{dirStat(devMedia)}

	_, summary, err := listAll(t, st, vol, testRoot)
	if err != nil {
		t.Fatalf("List: %v", err)
	}

	switch {
	case summary.RefusedEntries != 3:
		t.Errorf("RefusedEntries = %d, want 3", summary.RefusedEntries)
	case len(tr.opsWith("STA2 "+devicepath.VolumeRoot)) != 2:
		t.Errorf("STA2 ops = %v, want the pin plus one re-check", tr.opsWith("STA2 "+devicepath.VolumeRoot))
	}
}

// Confinement is re-established at each step: a subdirectory that stops being a directory,
// or moves off the volume, between the parent's listing and the descent is refused there.
func TestListRecheckOnDescent(t *testing.T) {
	tests := []struct {
		name  string
		reply adbwire.Stat
	}{
		{name: "no longer a directory", reply: statWith(modeSymlink, devMedia)},
		{name: "no longer on the volume", reply: dirStat(devData)},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			st, tr := newTestStore()
			vol := pinVolume(t, st)

			tr.fs.lstat[testRoot] = dirStat(devMedia)
			tr.fs.list[testRoot] = []adbwire.Dirent{dirent("Camera", dirStat(devMedia))}

			// The parent's listing said directory-on-volume; the fresh stat disagrees.
			tr.fs.lstat[testRoot+"/Camera"] = tc.reply
			tr.fs.list[testRoot+"/Camera"] = []adbwire.Dirent{dirent("must_not_appear.jpg", regularStat(1, devMedia))}
			tr.fs.stat[devicepath.VolumeRoot] = []adbwire.Stat{dirStat(devMedia)}

			recs, summary, err := listAll(t, st, vol, testRoot)
			if err != nil {
				t.Fatalf("List: %v", err)
			}

			switch {
			case len(recs) != 0:
				t.Errorf("paths = %v, want none", paths(recs))
			case summary.RefusedEntries != 1:
				t.Errorf("RefusedEntries = %d, want 1", summary.RefusedEntries)
			}

			if ops := tr.opsWith("LIS2 " + testRoot + "/Camera"); len(ops) != 0 {
				t.Errorf("the directory was listed anyway: %v", ops)
			}
		})
	}
}

// A device is free to answer "this directory contains a directory" forever; nothing in the
// protocol stops it. The walk stops itself.
func TestListStopsAtTheDepthCap(t *testing.T) {
	st, tr := newTestStore()
	vol := pinVolume(t, st)

	tr.fs.lstatFn = func(path string) (adbwire.Stat, bool) {
		if strings.HasPrefix(path, testRoot) {
			return dirStat(devMedia), true
		}

		return adbwire.Stat{}, false
	}

	tr.fs.listFn = func(path string) ([]adbwire.Dirent, bool) {
		if strings.HasPrefix(path, testRoot) {
			return []adbwire.Dirent{dirent("a", dirStat(devMedia))}, true
		}

		return nil, false
	}

	_, summary, err := listAll(t, st, vol, testRoot)
	if err != nil {
		t.Fatalf("List: %v", err)
	}

	if len(summary.Errors) != 1 || summary.Errors[0].Code != errcode.CodePathDenied {
		t.Fatalf("Errors = %v, want one path_denied at the cap", summary.Errors)
	}

	if got := len(tr.opsWith("LIS2 ")); got != maxWalkDepth {
		t.Errorf("listed %d directories, want the cap of %d", got, maxWalkDepth)
	}
}

// An error from the caller's callback stops the walk and comes back unchanged: the caller
// should not have to unwrap the transport's opinion of its own error.
func TestListCallbackErrorStopsTheWalk(t *testing.T) {
	st, tr := newTestStore()
	vol := pinVolume(t, st)

	tr.fs.lstat[testRoot] = dirStat(devMedia)
	tr.fs.list[testRoot] = []adbwire.Dirent{
		dirent("a.jpg", regularStat(1, devMedia)),
		dirent("b.jpg", regularStat(1, devMedia)),
	}

	stop := errors.New("consumer is done")
	seen := 0

	_, err := st.List(t.Context(), devicebus.ListInput{Root: devicepath.MustParseAuthorizedPath(testRoot)}, vol, func(devicebus.FileRecord) error {
		seen++

		return stop
	})

	switch {
	case !errors.Is(err, stop):
		t.Errorf("err = %v, want the caller's own error", err)
	case seen != 1:
		t.Errorf("callback ran %d times, want 1", seen)
	}

	// The listing was abandoned undrained, so the session is retired rather than reused.
	if st.sess != nil {
		t.Error("the session survived an abandoned listing")
	}
}

// A listing that failed part way is not an empty listing: reporting it as a per-path warning
// would let a consumer treat half a tree as the whole tree.
func TestListTransportFailureIsFatal(t *testing.T) {
	st, tr := newTestStore()
	vol := pinVolume(t, st)

	tr.fs.lstat[testRoot] = dirStat(devMedia)
	tr.fs.listErr[testRoot] = fmt.Errorf("adbwire: LIS2: %w", adbwire.ErrProtocol)

	_, _, err := listAll(t, st, vol, testRoot)

	code := codeOf(t, err)
	if code != errcode.CodeDeviceDisconnected {
		t.Fatalf("code = %s, want %s", code, errcode.CodeDeviceDisconnected)
	}

	if !code.Fatal() {
		t.Error("a truncated listing must classify as fatal")
	}

	if st.sess != nil {
		t.Error("the dead session was kept")
	}
}

func TestListPreconditions(t *testing.T) {
	root := devicepath.MustParseAuthorizedPath(testRoot)

	t.Run("unpinned volume", func(t *testing.T) {
		st, _ := newTestStore()

		_, err := st.List(t.Context(), devicebus.ListInput{Root: root}, devicepath.Volume{}, collect(new([]devicebus.FileRecord)))
		if got := codeOf(t, err); got != errcode.CodeVolumeUnresolved {
			t.Errorf("code = %s, want %s", got, errcode.CodeVolumeUnresolved)
		}
	})

	t.Run("zero root", func(t *testing.T) {
		st, _ := newTestStore()
		vol := pinVolume(t, st)

		_, err := st.List(t.Context(), devicebus.ListInput{}, vol, collect(new([]devicebus.FileRecord)))
		if got := codeOf(t, err); got != errcode.CodePathDenied {
			t.Errorf("code = %s, want %s", got, errcode.CodePathDenied)
		}
	})

	t.Run("negative depth", func(t *testing.T) {
		st, _ := newTestStore()
		vol := pinVolume(t, st)

		_, err := st.List(t.Context(), devicebus.ListInput{Root: root, MaxDepth: -1}, vol, collect(new([]devicebus.FileRecord)))
		if got := codeOf(t, err); got != errcode.CodeInternal {
			t.Errorf("code = %s, want %s", got, errcode.CodeInternal)
		}
	})

	t.Run("no callback", func(t *testing.T) {
		st, _ := newTestStore()
		vol := pinVolume(t, st)

		_, err := st.List(t.Context(), devicebus.ListInput{Root: root}, vol, nil)
		if got := codeOf(t, err); got != errcode.CodeInternal {
			t.Errorf("code = %s, want %s", got, errcode.CodeInternal)
		}
	})
}

// A name adbd could send but AuthorizedPath.Child refuses. adbd applies no confinement of
// its own — measured, it answers for /data and the root filesystem as readily as for media —
// so a device-supplied name is exactly as untrusted as a caller-supplied one, and Child is
// what says so.
func TestListRefusesADeviceSuppliedNameThatCannotBeJoined(t *testing.T) {
	st, tr := newTestStore()
	vol := pinVolume(t, st)

	tr.fs.lstat[testRoot] = dirStat(devMedia)
	tr.fs.list[testRoot] = []adbwire.Dirent{
		direntBytes([]byte("../../data/data/secret"), regularStat(10, devMedia)),
		direntBytes([]byte("truncate\x00me"), regularStat(10, devMedia)),
		dirent("ok.jpg", regularStat(10, devMedia)),
	}

	recs, summary, err := listAll(t, st, vol, testRoot)
	if err != nil {
		t.Fatalf("List: %v", err)
	}

	if got := paths(recs); !slices.Equal(got, []string{testRoot + "/ok.jpg"}) {
		t.Errorf("paths = %v, want only the joinable name", got)
	}

	// Reported against the parent, which is a path that can legitimately be named. Vanishing
	// silently would be worse.
	if len(summary.Errors) != 2 {
		t.Fatalf("Errors = %v, want one per unjoinable name", summary.Errors)
	}

	for _, pe := range summary.Errors {
		switch {
		case pe.Code != errcode.CodePathDenied:
			t.Errorf("Code = %s, want %s", pe.Code, errcode.CodePathDenied)
		case pe.Path.String() != testRoot:
			t.Errorf("Path = %q, want the parent %q", pe.Path, testRoot)
		}
	}

	// Nothing resembling those names reached the wire.
	for _, op := range tr.ops {
		if strings.Contains(op, "secret") || strings.Contains(op, "truncate") {
			t.Errorf("a refused name reached the wire: %q", op)
		}
	}
}

// Every path in a record came from AuthorizedPath.Child, so it is a path
// ParseAuthorizedPath would also have accepted — device-supplied names cannot widen the
// allowlist.
func TestListPathsRemainWithinTheAllowlist(t *testing.T) {
	st, tr := newTestStore()
	vol := pinVolume(t, st)

	tr.fs.lstat[testRoot] = dirStat(devMedia)
	tr.fs.list[testRoot] = []adbwire.Dirent{dirent("ok.jpg", regularStat(1, devMedia))}

	recs, _, err := listAll(t, st, vol, testRoot)
	if err != nil {
		t.Fatalf("List: %v", err)
	}

	for _, rec := range recs {
		if _, err := devicepath.ParseAuthorizedPath(rec.Path.String()); err != nil {
			t.Errorf("record path %q would not parse: %v", rec.Path, err)
		}
	}
}
