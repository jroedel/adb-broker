package adbsyncdb

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"slices"
	"strings"
	"testing"

	"github.com/jroedel/adb-broker/business/domain/device/devicebus"
	"github.com/jroedel/adb-broker/business/types/devicepath"
	"github.com/jroedel/adb-broker/business/types/errcode"
	"github.com/jroedel/adb-broker/business/types/serial"
	"github.com/jroedel/adb-broker/foundation/adbwire"
)

// There is no phone attached to a machine running these tests and there never will be, so
// every value below is one that was measured against a real device during the protocol
// survey. Using anything else here would make the traversal tests agree with a device that
// does not exist.
const (
	devMedia  = 190   // the shared-storage volume
	devData   = 65088 // /data — where a symlink escape lands
	devRootFS = 65034 // the root filesystem, and where /sdcard itself lives as a symlink
)

// Modes as the device reports them over the sync protocol.
const (
	modeRegular = 0o100644
	modeDir     = 0o42770
	modeSymlink = 0o120644
	modeSocket  = 0o140644
	modeFIFO    = 0o010644
	modeChar    = 0o020644
	modeBlock   = 0o060644
)

// In-band errnos. 0, 2 and 13 are the three the survey observed.
const (
	errnoOK = 0
)

const (
	testSerial      = "EXAMPLESERIAL1"
	otherSerial     = "EXAMPLESERIAL2"
	testServerVer   = "1.0.41"
	testBrokerVer   = "test-broker"
	testRoot        = "/sdcard/DCIM"
	emptyFileDigest = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
)

// =============================================================================
// The fake transport.
//
// The Store reaches adbwire only through the unexported transport/hostConn/syncConn
// interfaces, so the whole traversal — the security-critical part of this package — is
// exercised here with no device and no adb server. The fake speaks in the same natives
// adbwire delivers (adbwire.Stat, adbwire.Dirent, adbwire.DeviceEntry), so a confinement
// test cannot pass because the fake invented a friendlier shape.

// fakeTransport is the injected stand-in for adbwire. It records every service string and
// sync command the Store puts on the wire, which is what TestOutboundVocabulary asserts on.
type fakeTransport struct {
	version  string
	devices  []adbwire.DeviceEntry
	features map[string][]string
	fs       *fakeFS

	dialErr      error
	versionErr   error
	devicesErr   error
	featuresErr  error
	transportErr error
	syncErr      error

	ops   []string
	dials int
}

// fakeFS is the device-side filesystem the sync commands answer from.
type fakeFS struct {
	// lstat answers LST2. A path that is absent answers errno 2, the way adbd does.
	lstat map[string]adbwire.Stat

	// stat answers STA2 with successive replies, so a test can make the volume root
	// change under the walk. The last entry repeats once the list is exhausted.
	stat      map[string][]adbwire.Stat
	statCalls map[string]int

	list    map[string][]adbwire.Dirent
	listErr map[string]error

	files   map[string][]byte
	recvErr map[string]error

	// Hooks for trees that cannot be enumerated, such as the self-nesting one used to
	// prove the depth cap holds.
	lstatFn func(path string) (adbwire.Stat, bool)
	listFn  func(path string) ([]adbwire.Dirent, bool)
}

func newFakeFS() *fakeFS {
	return &fakeFS{
		lstat: map[string]adbwire.Stat{},
		stat: map[string][]adbwire.Stat{
			// The volume root, resolved through STA2 because /sdcard is itself a symlink.
			devicepath.VolumeRoot: {dirStat(devMedia)},
		},
		statCalls: map[string]int{},
		list:      map[string][]adbwire.Dirent{},
		listErr:   map[string]error{},
		files:     map[string][]byte{},
		recvErr:   map[string]error{},
	}
}

func newFakeTransport() *fakeTransport {
	return &fakeTransport{
		version:  testServerVer,
		devices:  []adbwire.DeviceEntry{{Serial: testSerial, State: "device"}},
		features: map[string][]string{testSerial: {"stat_v2", "ls_v2", "sendrecv_v2", "abb_exec", "shell_v2"}},
		fs:       newFakeFS(),
	}
}

func (f *fakeTransport) record(op string) { f.ops = append(f.ops, op) }

func (f *fakeTransport) dial(_ context.Context) (hostConn, error) {
	f.dials++

	if f.dialErr != nil {
		return nil, f.dialErr
	}

	return &fakeHost{tr: f}, nil
}

// opsWith returns every recorded op beginning with prefix.
func (f *fakeTransport) opsWith(prefix string) []string {
	var out []string
	for _, op := range f.ops {
		if strings.HasPrefix(op, prefix) {
			out = append(out, op)
		}
	}

	return out
}

type fakeHost struct {
	tr *fakeTransport
}

func (h *fakeHost) ServerVersion(_ context.Context) (string, error) {
	h.tr.record("host:version")

	return h.tr.version, h.tr.versionErr
}

func (h *fakeHost) Devices(_ context.Context) ([]adbwire.DeviceEntry, error) {
	h.tr.record("host:devices")

	if h.tr.devicesErr != nil {
		return nil, h.tr.devicesErr
	}

	return slices.Clone(h.tr.devices), nil
}

func (h *fakeHost) DeviceFeatures(_ context.Context, ser string) ([]string, error) {
	h.tr.record("host-serial:" + ser + ":features")

	if h.tr.featuresErr != nil {
		return nil, h.tr.featuresErr
	}

	return slices.Clone(h.tr.features[ser]), nil
}

func (h *fakeHost) TransportSerial(_ context.Context, ser string) error {
	h.tr.record("host:transport:" + ser)

	return h.tr.transportErr
}

func (h *fakeHost) Sync(_ context.Context) (syncConn, error) {
	h.tr.record("sync:")

	if h.tr.syncErr != nil {
		return nil, h.tr.syncErr
	}

	return &fakeSync{tr: h.tr, fs: h.tr.fs}, nil
}

func (h *fakeHost) Close() error { return nil }

// fakeSync is one sync channel. It goes dead exactly where a real one does: on any FAIL,
// on a RECV failure, and when a listing callback aborts mid-stream.
type fakeSync struct {
	tr     *fakeTransport
	fs     *fakeFS
	dead   bool
	closed bool
}

func (s *fakeSync) alive(op string) error {
	if s.dead || s.closed {
		return fmt.Errorf("fake: %s on a retired channel: %w", op, adbwire.ErrSyncSessionDead)
	}

	return nil
}

func (s *fakeSync) kill(err error) error {
	s.dead = true

	return fmt.Errorf("%w: %w", err, adbwire.ErrSyncSessionDead)
}

func (s *fakeSync) Lstat(_ context.Context, path string) (adbwire.Stat, error) {
	s.tr.record("LST2 " + path)

	if err := s.alive("LST2"); err != nil {
		return adbwire.Stat{}, err
	}

	if s.fs.lstatFn != nil {
		if st, ok := s.fs.lstatFn(path); ok {
			return st, nil
		}
	}

	st, ok := s.fs.lstat[path]
	if !ok {
		// Measured: adbd answers errno 2 in-band, with the channel intact.
		return adbwire.Stat{Errno: errnoENOENT}, nil
	}

	return st, nil
}

func (s *fakeSync) Stat(_ context.Context, path string) (adbwire.Stat, error) {
	s.tr.record("STA2 " + path)

	if err := s.alive("STA2"); err != nil {
		return adbwire.Stat{}, err
	}

	replies, ok := s.fs.stat[path]
	if !ok || len(replies) == 0 {
		return adbwire.Stat{Errno: errnoENOENT}, nil
	}

	i := min(s.fs.statCalls[path], len(replies)-1)
	s.fs.statCalls[path]++

	return replies[i], nil
}

func (s *fakeSync) List(_ context.Context, path string, fn func(adbwire.Dirent) error) error {
	s.tr.record("LIS2 " + path)

	if err := s.alive("LIS2"); err != nil {
		return err
	}

	if err := s.fs.listErr[path]; err != nil {
		return s.kill(err)
	}

	entries, ok := s.fs.list[path]
	if !ok && s.fs.listFn != nil {
		entries, ok = s.fs.listFn(path)
	}

	if !ok {
		return s.kill(fmt.Errorf("fake: no listing scripted for %q", path))
	}

	for _, d := range entries {
		if err := fn(d); err != nil {
			// Mirrors adbwire: the rest of the stream is undrained, so the channel is
			// retired and the caller's error is wrapped rather than replaced.
			return s.kill(fmt.Errorf("fake: callback stopped the listing: %w", err))
		}
	}

	return nil
}

func (s *fakeSync) Recv(_ context.Context, path string, w io.Writer) (int64, error) {
	s.tr.record("RECV " + path)

	if err := s.alive("RECV"); err != nil {
		return 0, err
	}

	if err := s.fs.recvErr[path]; err != nil {
		return 0, s.kill(err)
	}

	body, ok := s.fs.files[path]
	if !ok {
		return 0, s.kill(fmt.Errorf("fake: open failed: No such file or directory: %q", path))
	}

	n, err := w.Write(body)
	if err != nil {
		return int64(n), s.kill(err)
	}

	return int64(n), nil
}

func (s *fakeSync) Close() error {
	s.closed = true

	return nil
}

// =============================================================================
// Helpers.

func newTestStore() (*Store, *fakeTransport) {
	tr := newFakeTransport()

	st := NewStore(testBrokerVer)
	st.tr = tr

	return st, tr
}

func statWith(mode uint32, dev int64) adbwire.Stat {
	return adbwire.Stat{Errno: errnoOK, Dev: dev, Ino: 4812, Mode: mode, Nlink: 1, Size: 0, Mtime: 1709828653}
}

func dirStat(dev int64) adbwire.Stat { return statWith(modeDir, dev) }

func regularStat(size int64, dev int64) adbwire.Stat {
	st := statWith(modeRegular, dev)
	st.Size = size

	return st
}

func dirent(name string, st adbwire.Stat) adbwire.Dirent {
	return adbwire.Dirent{Stat: st, Name: []byte(name)}
}

func direntBytes(name []byte, st adbwire.Stat) adbwire.Dirent {
	return adbwire.Dirent{Stat: st, Name: name}
}

// codeOf recovers the broker's classification the way a consumer does: through an interface
// assertion, never by reading the message.
func codeOf(t *testing.T, err error) errcode.Code {
	t.Helper()

	if err == nil {
		t.Fatal("expected an error, got nil")
	}

	var coded interface{ Code() errcode.Code }
	if !errors.As(err, &coded) {
		t.Fatalf("error %v carries no errcode.Code", err)
	}

	return coded.Code()
}

// pinVolume runs the real ResolveVolume path against the fake, so tests pin a volume the
// same way the Business layer does.
func pinVolume(t *testing.T, st *Store) devicepath.Volume {
	t.Helper()

	vol, err := st.ResolveVolume(t.Context())
	if err != nil {
		t.Fatalf("ResolveVolume: %v", err)
	}

	return vol
}

// collect drains a List into a slice of raw path strings.
func collect(recs *[]devicebus.FileRecord) func(devicebus.FileRecord) error {
	return func(rec devicebus.FileRecord) error {
		*recs = append(*recs, rec)

		return nil
	}
}

func paths(recs []devicebus.FileRecord) []string {
	out := make([]string, len(recs))
	for i, rec := range recs {
		out[i] = rec.Path.String()
	}

	return out
}

// =============================================================================
// Probe.

func TestProbeZeroDevicesIsNoDevice(t *testing.T) {
	st, tr := newTestStore()
	tr.devices = nil

	// Measured: an empty device list arrives as OKAY with a zero-length payload, so it is
	// not an error from adbwire and this store is where "no phone" gets decided.
	_, err := st.Probe(t.Context(), serial.Serial{})
	if got := codeOf(t, err); got != errcode.CodeNoDevice {
		t.Errorf("code = %s, want %s", got, errcode.CodeNoDevice)
	}
}

func TestProbeMultipleDevicesNamesEveryOne(t *testing.T) {
	st, tr := newTestStore()
	tr.devices = []adbwire.DeviceEntry{
		{Serial: testSerial, State: "device"},
		{Serial: otherSerial, State: "device"},
	}
	tr.features[otherSerial] = tr.features[testSerial]

	_, err := st.Probe(t.Context(), serial.Serial{})
	if got := codeOf(t, err); got != errcode.CodeMultipleDevices {
		t.Fatalf("code = %s, want %s", got, errcode.CodeMultipleDevices)
	}

	// The operator's next action is to name one of them, and they cannot name what they
	// were not told.
	for _, want := range []string{testSerial, otherSerial} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("error %q does not name serial %q", err, want)
		}
	}

	// Never pick one silently.
	if ops := tr.opsWith("host:transport"); len(ops) != 0 {
		t.Errorf("a transport was selected anyway: %v", ops)
	}
}

func TestProbeSingleDeviceReportsStateVerbatim(t *testing.T) {
	st, tr := newTestStore()

	// A state token this broker has no opinion about: it is reported as it arrived, not
	// normalised, because the caller needs the raw value to say what happened.
	tr.devices = []adbwire.DeviceEntry{{Serial: testSerial, State: "device"}}

	dev, err := st.Probe(t.Context(), serial.Serial{})
	if err != nil {
		t.Fatalf("Probe: %v", err)
	}

	switch {
	case dev.Serial.String() != testSerial:
		t.Errorf("Serial = %q, want %q", dev.Serial, testSerial)
	case dev.State != "device":
		t.Errorf("State = %q, want %q", dev.State, "device")
	case dev.ServerVersion != testServerVer:
		t.Errorf("ServerVersion = %q, want %q", dev.ServerVersion, testServerVer)
	case dev.BrokerVersion != testBrokerVer:
		t.Errorf("BrokerVersion = %q, want %q", dev.BrokerVersion, testBrokerVer)
	case !slices.Contains(dev.Features, "stat_v2"):
		t.Errorf("Features = %v, want the device's own list", dev.Features)
	}
}

func TestProbeNamedDeviceAmongSeveral(t *testing.T) {
	st, tr := newTestStore()
	tr.devices = []adbwire.DeviceEntry{
		{Serial: otherSerial, State: "device"},
		{Serial: testSerial, State: "device"},
	}
	tr.features[otherSerial] = tr.features[testSerial]

	dev, err := st.Probe(t.Context(), serial.MustParseSerial(testSerial))
	if err != nil {
		t.Fatalf("Probe: %v", err)
	}

	if dev.Serial.String() != testSerial {
		t.Errorf("Serial = %q, want %q", dev.Serial, testSerial)
	}

	if ops := tr.opsWith("host:transport:"); !slices.Equal(ops, []string{"host:transport:" + testSerial}) {
		t.Errorf("transport ops = %v, want the named device only", ops)
	}
}

func TestProbeNamedDeviceAbsent(t *testing.T) {
	st, _ := newTestStore()

	_, err := st.Probe(t.Context(), serial.MustParseSerial(otherSerial))
	if got := codeOf(t, err); got != errcode.CodeNoDevice {
		t.Errorf("code = %s, want %s", got, errcode.CodeNoDevice)
	}
}

// A missing V2 feature is fatal and there is no fallback: legacy STAT and LIST report size
// as 32 bits, so a video over 4 GiB would list with a silently wrong size. That is
// discovered years later; a refusal is discovered now.
func TestProbeRequiresEveryV2Feature(t *testing.T) {
	for _, missing := range []string{"stat_v2", "ls_v2", "sendrecv_v2"} {
		t.Run("without_"+missing, func(t *testing.T) {
			st, tr := newTestStore()

			full := tr.features[testSerial]
			reduced := make([]string, 0, len(full))
			for _, f := range full {
				if f != missing {
					reduced = append(reduced, f)
				}
			}
			tr.features[testSerial] = reduced

			_, err := st.Probe(t.Context(), serial.Serial{})
			if got := codeOf(t, err); got != errcode.CodeUnsupported {
				t.Fatalf("code = %s, want %s", got, errcode.CodeUnsupported)
			}

			if !strings.Contains(err.Error(), missing) {
				t.Errorf("error %q does not name the missing feature %q", err, missing)
			}

			// No fallback means no sync session either.
			if ops := tr.opsWith("sync:"); len(ops) != 0 {
				t.Errorf("a sync session was opened anyway: %v", ops)
			}
		})
	}

	t.Run("empty_feature_list", func(t *testing.T) {
		st, tr := newTestStore()
		tr.features[testSerial] = nil

		_, err := st.Probe(t.Context(), serial.Serial{})
		if got := codeOf(t, err); got != errcode.CodeUnsupported {
			t.Fatalf("code = %s, want %s", got, errcode.CodeUnsupported)
		}
	})
}

// The capability gate must read the DEVICE's features. Measured, the server's own
// host:host-features answers "stat_v2,ls_v2,sendrecv_v2" with no device attached at all, so
// a gate wired to it can never fail — which is worse than no gate, because it reads as
// evidence.
func TestProbeReadsFeaturesFromThePerDeviceService(t *testing.T) {
	st, tr := newTestStore()

	if _, err := st.Probe(t.Context(), serial.Serial{}); err != nil {
		t.Fatalf("Probe: %v", err)
	}

	want := "host-serial:" + testSerial + ":features"
	if !slices.Contains(tr.ops, want) {
		t.Errorf("ops = %v, want one of them to be %q", tr.ops, want)
	}

	for _, forbidden := range []string{"host:host-features", "host:features"} {
		if slices.Contains(tr.ops, forbidden) {
			t.Errorf("the server's own feature list was consulted: %q", forbidden)
		}
	}
}

// Features are read before a transport is selected, because once a transport is selected on
// a socket only sync: may follow it.
func TestProbeReadsFeaturesBeforeSelectingATransport(t *testing.T) {
	st, tr := newTestStore()

	if _, err := st.Probe(t.Context(), serial.Serial{}); err != nil {
		t.Fatalf("Probe: %v", err)
	}

	features := slices.Index(tr.ops, "host-serial:"+testSerial+":features")
	transport := slices.Index(tr.ops, "host:transport:"+testSerial)

	if features < 0 || transport < 0 || features > transport {
		t.Errorf("ops = %v, want features before transport", tr.ops)
	}
}

func TestProbeMapsWireSentinels(t *testing.T) {
	tests := []struct {
		name string
		set  func(tr *fakeTransport)
		want errcode.Code
	}{
		{
			name: "no adb server",
			set:  func(tr *fakeTransport) { tr.dialErr = fmt.Errorf("dial: %w", adbwire.ErrNoServer) },
			want: errcode.CodeNoADBServer,
		},
		{
			name: "unauthorized",
			set:  func(tr *fakeTransport) { tr.featuresErr = fmt.Errorf("features: %w", adbwire.ErrUnauthorized) },
			want: errcode.CodeUnauthorized,
		},
		{
			name: "offline",
			set:  func(tr *fakeTransport) { tr.syncErr = fmt.Errorf("sync: %w", adbwire.ErrOffline) },
			want: errcode.CodeOffline,
		},
		{
			name: "server said no devices",
			set:  func(tr *fakeTransport) { tr.devicesErr = fmt.Errorf("devices: %w", adbwire.ErrNoDevices) },
			want: errcode.CodeNoDevice,
		},
		{
			name: "device not found",
			set:  func(tr *fakeTransport) { tr.transportErr = fmt.Errorf("transport: %w", adbwire.ErrDeviceNotFound) },
			want: errcode.CodeNoDevice,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			st, tr := newTestStore()
			tc.set(tr)

			_, err := st.Probe(t.Context(), serial.Serial{})
			if got := codeOf(t, err); got != tc.want {
				t.Errorf("code = %s, want %s", got, tc.want)
			}
		})
	}
}

// A device in a state other than "device" fails one of the steps after selection, and the
// prose adb returns is measured to be identical across several causes — so the verbatim
// state token has to travel in the message.
func TestProbeCarriesTheStateTokenIntoTheFailure(t *testing.T) {
	st, tr := newTestStore()
	tr.devices = []adbwire.DeviceEntry{{Serial: testSerial, State: "unauthorized"}}
	tr.featuresErr = fmt.Errorf("adbwire: %w", adbwire.ErrUnauthorized)

	_, err := st.Probe(t.Context(), serial.Serial{})
	if got := codeOf(t, err); got != errcode.CodeUnauthorized {
		t.Fatalf("code = %s, want %s", got, errcode.CodeUnauthorized)
	}

	if !strings.Contains(err.Error(), "unauthorized") {
		t.Errorf("error %q does not carry the state token", err)
	}
}

// The attached-device count comes from the host:devices reply the session already parsed to
// select a device, and from nowhere else.
//
// The point of the test is the two negatives. It must not be the number of devices that
// matched the requested serial — a consumer reading it that way would see 1 with two phones
// plugged in and then omit --serial on every fetch, which is exactly the ambiguity the count
// exists to reveal. And it must not cost a second request: the whole reason this is reported
// at probe time rather than asked for is that the reply was already in hand.
func TestProbeCountsTheDeviceListItAlreadyRead(t *testing.T) {
	third := "EXAMPLESERIAL3"

	tests := []struct {
		name    string
		devices []adbwire.DeviceEntry
		want    serial.Serial
		count   int
	}{
		{
			name:    "one attached device",
			devices: []adbwire.DeviceEntry{{Serial: testSerial, State: "device"}},
			count:   1,
		},
		{
			name: "a named device among three",
			devices: []adbwire.DeviceEntry{
				{Serial: otherSerial, State: "device"},
				{Serial: testSerial, State: "device"},
				{Serial: third, State: "device"},
			},
			want:  serial.MustParseSerial(testSerial),
			count: 3,
		},
		{
			// Measured: host:devices lists a phone that is attached but not usable, with
			// its state token. Such a device is counted, because a fetch naming no serial
			// would still be ambiguous with it plugged in — the count answers "could this
			// be ambiguous", never "how many devices could be served".
			name: "an unauthorized phone still counts as attached",
			devices: []adbwire.DeviceEntry{
				{Serial: testSerial, State: "device"},
				{Serial: otherSerial, State: "unauthorized"},
			},
			want:  serial.MustParseSerial(testSerial),
			count: 2,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			st, tr := newTestStore()
			tr.devices = tc.devices
			for _, e := range tc.devices {
				tr.features[e.Serial] = tr.features[testSerial]
			}

			dev, err := st.Probe(t.Context(), tc.want)
			if err != nil {
				t.Fatalf("Probe: %v", err)
			}

			if dev.AttachedDevices != tc.count {
				t.Errorf("AttachedDevices = %d, want %d: the count is of the whole device list", dev.AttachedDevices, tc.count)
			}

			// One reply, counted once. A second host:devices here would be a request for a
			// number the session had already been told.
			if ops := tr.opsWith("host:devices"); len(ops) != 1 {
				t.Errorf("host:devices ops = %v, want exactly one: the count comes from the reply already read", ops)
			}
		})
	}
}

func TestProbeReusesOneSession(t *testing.T) {
	st, tr := newTestStore()

	for range 3 {
		if _, err := st.Probe(t.Context(), serial.Serial{}); err != nil {
			t.Fatalf("Probe: %v", err)
		}
	}

	if tr.dials != 1 {
		t.Errorf("dials = %d, want 1: the session is established once", tr.dials)
	}
}

// =============================================================================
// ResolveVolume.

func TestResolveVolumePinsTheMediaVolume(t *testing.T) {
	st, tr := newTestStore()

	vol := pinVolume(t, st)

	switch {
	case vol.IsZero():
		t.Fatal("volume is unpinned")
	case vol.Dev() != devMedia:
		t.Errorf("Dev = %d, want %d", vol.Dev(), devMedia)
	case !vol.Contains(devMedia):
		t.Error("the pinned volume does not contain its own dev")
	case vol.Contains(devData):
		t.Errorf("the pinned volume contains /data (dev=%d)", devData)
	}

	// STA2, not LST2: /sdcard is itself a symlink (measured, mode 0o120644 on dev=65034),
	// so the one deliberate symlink follow in this binary happens here.
	if ops := tr.opsWith("STA2 " + devicepath.VolumeRoot); len(ops) == 0 {
		t.Errorf("ops = %v, want an STA2 against %s", tr.ops, devicepath.VolumeRoot)
	}

	if ops := tr.opsWith("LST2 " + devicepath.VolumeRoot); len(ops) != 0 {
		t.Errorf("the volume root was lstat'ed: %v", ops)
	}
}

func TestResolveVolumeFailures(t *testing.T) {
	tests := []struct {
		name  string
		reply adbwire.Stat
	}{
		{name: "errno", reply: adbwire.Stat{Errno: errnoENOENT}},
		{name: "not a directory", reply: regularStat(1, devMedia)},
		{name: "symlink that did not resolve", reply: statWith(modeSymlink, devRootFS)},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			st, tr := newTestStore()
			tr.fs.stat[devicepath.VolumeRoot] = []adbwire.Stat{tc.reply}

			_, err := st.ResolveVolume(t.Context())
			if got := codeOf(t, err); got != errcode.CodeVolumeUnresolved {
				t.Errorf("code = %s, want %s", got, errcode.CodeVolumeUnresolved)
			}
		})
	}
}

// =============================================================================
// Fetch.

func TestFetchRegularFile(t *testing.T) {
	st, tr := newTestStore()
	vol := pinVolume(t, st)

	const (
		path   = testRoot + "/Camera/IMG_0001.jpg"
		body   = "hello adb\n"
		digest = "ff27e7dbed2a73af237b312cb14102863c4285991f1f257ba6ef09b0a4223ac7"
	)

	tr.fs.lstat[path] = regularStat(int64(len(body)), devMedia)
	tr.fs.files[path] = []byte(body)

	var buf bytes.Buffer

	res, err := st.Fetch(t.Context(), devicepath.MustParseAuthorizedPath(path), vol, &buf, nil)
	if err != nil {
		t.Fatalf("Fetch: %v", err)
	}

	switch {
	case res.Bytes != int64(len(body)):
		t.Errorf("Bytes = %d, want %d", res.Bytes, len(body))
	case res.SHA256 != digest:
		t.Errorf("SHA256 = %s, want %s", res.SHA256, digest)
	case buf.String() != body:
		t.Errorf("written = %q, want %q", buf.String(), body)
	}
}

// Measured: a zero-byte file produces no DATA packets at all, just an immediate DONE. Zero
// bytes is success, and such files exist on real devices.
func TestFetchZeroByteFile(t *testing.T) {
	st, tr := newTestStore()
	vol := pinVolume(t, st)

	const path = testRoot + "/Camera/empty.jpg"

	tr.fs.lstat[path] = regularStat(0, devMedia)
	tr.fs.files[path] = nil

	var buf bytes.Buffer

	res, err := st.Fetch(t.Context(), devicepath.MustParseAuthorizedPath(path), vol, &buf, nil)
	if err != nil {
		t.Fatalf("Fetch: %v", err)
	}

	switch {
	case res.Bytes != 0:
		t.Errorf("Bytes = %d, want 0", res.Bytes)
	case res.SHA256 != emptyFileDigest:
		t.Errorf("SHA256 = %s, want the empty digest %s", res.SHA256, emptyFileDigest)
	}
}

// LST2 does not follow symlinks, which is the entire reason it is used here: RECV would
// have followed it, device-side, wherever it led.
//
// The refusal is what matters and it is unchanged; the code it carries is
// not_a_regular_file rather than path_denied, so a consumer skips this one file instead of
// abandoning the source that contains it. A listing never emits a symlink, so a symlink
// arriving at a fetch is a path whose kind changed since it was listed — one racing file.
func TestFetchRefusesASymlinkBeforeAnyRecv(t *testing.T) {
	st, tr := newTestStore()
	vol := pinVolume(t, st)

	const path = testRoot + "/Camera/IMG_0001.jpg"

	tr.fs.lstat[path] = statWith(modeSymlink, devMedia)
	tr.fs.files[path] = []byte("this must never be read")

	_, err := st.Fetch(t.Context(), devicepath.MustParseAuthorizedPath(path), vol, io.Discard, nil)
	if got := codeOf(t, err); got != errcode.CodeNotARegularFile {
		t.Fatalf("code = %s, want %s", got, errcode.CodeNotARegularFile)
	}

	if ops := tr.opsWith("RECV"); len(ops) != 0 {
		t.Errorf("RECV was issued for a symlink: %v", ops)
	}
}

func TestFetchRefusesAnOffVolumePathBeforeAnyRecv(t *testing.T) {
	st, tr := newTestStore()
	vol := pinVolume(t, st)

	const path = testRoot + "/Camera/IMG_0001.jpg"

	// A regular file by every string rule, on /data by the only rule that can see a bind
	// mount.
	tr.fs.lstat[path] = regularStat(10, devData)
	tr.fs.files[path] = []byte("this must never be read")

	_, err := st.Fetch(t.Context(), devicepath.MustParseAuthorizedPath(path), vol, io.Discard, nil)
	if got := codeOf(t, err); got != errcode.CodePathDenied {
		t.Fatalf("code = %s, want %s", got, errcode.CodePathDenied)
	}

	if ops := tr.opsWith("RECV"); len(ops) != 0 {
		t.Errorf("RECV was issued for an off-volume path: %v", ops)
	}

	if !strings.Contains(err.Error(), fmt.Sprint(devData)) {
		t.Errorf("error %q does not report the dev it found", err)
	}
}

// Every non-regular kind is refused before RECV and every one of them reports
// not_a_regular_file. The directory case is the one that was measured against the built
// binary and misread: it used to report path_denied, whose documented action is to abandon
// the whole source, so a file that was regular at list time and a directory at fetch time —
// one racing path — cost a consumer an entire tree. What is refused is unchanged.
func TestFetchRefusesNonRegularKinds(t *testing.T) {
	for name, mode := range map[string]uint32{
		"directory": modeDir,
		"socket":    modeSocket,
		"fifo":      modeFIFO,
		"chardev":   modeChar,
		"blockdev":  modeBlock,
	} {
		t.Run(name, func(t *testing.T) {
			st, tr := newTestStore()
			vol := pinVolume(t, st)

			const path = testRoot + "/Camera/thing"

			tr.fs.lstat[path] = statWith(mode, devMedia)

			_, err := st.Fetch(t.Context(), devicepath.MustParseAuthorizedPath(path), vol, io.Discard, nil)
			if got := codeOf(t, err); got != errcode.CodeNotARegularFile {
				t.Fatalf("code = %s, want %s", got, errcode.CodeNotARegularFile)
			}

			if ops := tr.opsWith("RECV"); len(ops) != 0 {
				t.Errorf("RECV was issued: %v", ops)
			}
		})
	}
}

func TestFetchMapsInBandErrnos(t *testing.T) {
	tests := []struct {
		name  string
		errno uint32
		want  errcode.Code
	}{
		{name: "ENOENT", errno: errnoENOENT, want: errcode.CodePathNotFound},
		{name: "EACCES", errno: errnoEACCES, want: errcode.CodePermissionDenied},
		{name: "unmeasured errno", errno: 5, want: errcode.CodeTransferFailed},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			st, tr := newTestStore()
			vol := pinVolume(t, st)

			const path = testRoot + "/Camera/IMG_0001.jpg"

			tr.fs.lstat[path] = adbwire.Stat{Errno: tc.errno}

			_, err := st.Fetch(t.Context(), devicepath.MustParseAuthorizedPath(path), vol, io.Discard, nil)
			if got := codeOf(t, err); got != tc.want {
				t.Errorf("code = %s, want %s", got, tc.want)
			}
		})
	}
}

// Measured: any RECV failure kills the sync session — on fresh channels, for "open failed:
// No such file or directory", "open failed: Permission denied" and "read failed: Is a
// directory". So the store must rebuild the transport, once, and carry on.
func TestFetchRecvFailureReconnectsOnce(t *testing.T) {
	st, tr := newTestStore()
	vol := pinVolume(t, st)

	const (
		bad  = testRoot + "/Camera/locked.jpg"
		good = testRoot + "/Camera/IMG_0001.jpg"
		body = "hello adb\n"
	)

	tr.fs.lstat[bad] = regularStat(10, devMedia)
	tr.fs.recvErr[bad] = adbwire.FailError{Service: "RECV", Message: "open failed: Permission denied"}

	tr.fs.lstat[good] = regularStat(int64(len(body)), devMedia)
	tr.fs.files[good] = []byte(body)

	dialsBefore := tr.dials

	_, err := st.Fetch(t.Context(), devicepath.MustParseAuthorizedPath(bad), vol, io.Discard, nil)
	if got := codeOf(t, err); got != errcode.CodeTransferFailed {
		t.Fatalf("code = %s, want %s", got, errcode.CodeTransferFailed)
	}

	switch {
	case st.reconnects != 1:
		t.Errorf("reconnects = %d, want exactly 1", st.reconnects)
	case tr.dials != dialsBefore+1:
		t.Errorf("dials = %d, want %d: the transport is rebuilt once", tr.dials, dialsBefore+1)
	}

	// The whole point of the rebuild: the next operation works.
	var buf bytes.Buffer

	res, err := st.Fetch(t.Context(), devicepath.MustParseAuthorizedPath(good), vol, &buf, nil)
	if err != nil {
		t.Fatalf("Fetch after reconnect: %v", err)
	}

	switch {
	case res.Bytes != int64(len(body)):
		t.Errorf("Bytes = %d, want %d", res.Bytes, len(body))
	case st.reconnects != 1:
		t.Errorf("reconnects = %d, want still 1", st.reconnects)
	}
}

// The digest covers the bytes forwarded, so a destination that fails mid-transfer is a
// failure and not a short success.
func TestFetchDestinationFailure(t *testing.T) {
	st, tr := newTestStore()
	vol := pinVolume(t, st)

	const path = testRoot + "/Camera/IMG_0001.jpg"

	tr.fs.lstat[path] = regularStat(4, devMedia)
	tr.fs.files[path] = []byte("body")

	_, err := st.Fetch(t.Context(), devicepath.MustParseAuthorizedPath(path), vol, failWriter{}, nil)
	if got := codeOf(t, err); got != errcode.CodeTransferFailed {
		t.Errorf("code = %s, want %s", got, errcode.CodeTransferFailed)
	}
}

type failWriter struct{}

func (failWriter) Write([]byte) (int, error) { return 0, errors.New("destination is full") }

func TestFetchRequiresAPinnedVolume(t *testing.T) {
	st, _ := newTestStore()

	_, err := st.Fetch(t.Context(), devicepath.MustParseAuthorizedPath(testRoot+"/a.jpg"), devicepath.Volume{}, io.Discard, nil)
	if got := codeOf(t, err); got != errcode.CodeVolumeUnresolved {
		t.Errorf("code = %s, want %s", got, errcode.CodeVolumeUnresolved)
	}
}

func TestFetchRefusesTheZeroPath(t *testing.T) {
	st, _ := newTestStore()
	vol := pinVolume(t, st)

	_, err := st.Fetch(t.Context(), devicepath.AuthorizedPath{}, vol, io.Discard, nil)
	if got := codeOf(t, err); got != errcode.CodePathDenied {
		t.Errorf("code = %s, want %s", got, errcode.CodePathDenied)
	}
}

// =============================================================================
// The outbound vocabulary.

// A full run — probe, pin, walk, fetch — may put nothing on the wire beyond the closed set
// below. adbwire compiles that set in; this asserts the store never asks for anything else,
// which is the property that keeps "the broker cannot exec a shell on the phone" a fact
// about the program rather than a claim about its author's intentions.
func TestOutboundVocabularyIsClosed(t *testing.T) {
	st, tr := newTestStore()
	vol := pinVolume(t, st)

	if _, err := st.Probe(t.Context(), serial.Serial{}); err != nil {
		t.Fatalf("Probe: %v", err)
	}

	tr.fs.lstat[testRoot] = dirStat(devMedia)
	tr.fs.list[testRoot] = []adbwire.Dirent{
		dirent("Camera", dirStat(devMedia)),
		dirent("link", statWith(modeSymlink, devMedia)),
		dirent("elsewhere", regularStat(1, devData)),
	}
	tr.fs.lstat[testRoot+"/Camera"] = dirStat(devMedia)
	tr.fs.list[testRoot+"/Camera"] = []adbwire.Dirent{dirent("IMG_0001.jpg", regularStat(4, devMedia))}
	tr.fs.lstat[testRoot+"/Camera/IMG_0001.jpg"] = regularStat(4, devMedia)
	tr.fs.files[testRoot+"/Camera/IMG_0001.jpg"] = []byte("body")

	var recs []devicebus.FileRecord
	if _, err := st.List(t.Context(), devicebus.ListInput{Root: devicepath.MustParseAuthorizedPath(testRoot)}, vol, collect(&recs)); err != nil {
		t.Fatalf("List: %v", err)
	}

	if _, err := st.Fetch(t.Context(), devicepath.MustParseAuthorizedPath(testRoot+"/Camera/IMG_0001.jpg"), vol, io.Discard, nil); err != nil {
		t.Fatalf("Fetch: %v", err)
	}

	allowed := []string{
		"host:version",
		"host:devices",
		"host-serial:",
		"host:transport:",
		"sync:",
		"LST2 ",
		"STA2 ",
		"LIS2 ",
		"RECV ",
	}

	forbidden := []string{
		"shell:", "exec:", "SEND", "reverse:", "root:", "tcpip:", "remount:",
		"host:host-features", "host:features", "host:devices-l", "host:transport-any",
		"host:kill", "QUIT",
	}

	for _, op := range tr.ops {
		if !slices.ContainsFunc(allowed, func(p string) bool { return strings.HasPrefix(op, p) }) {
			t.Errorf("op %q is outside the permitted vocabulary", op)
		}

		for _, bad := range forbidden {
			if strings.Contains(op, bad) {
				t.Errorf("op %q contains the forbidden token %q", op, bad)
			}
		}
	}

	if len(tr.ops) == 0 {
		t.Fatal("no ops recorded; the fake was never asked for anything")
	}
}
