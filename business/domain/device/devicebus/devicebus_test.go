package devicebus_test

import (
	"context"
	"errors"
	"io"
	"reflect"
	"slices"
	"testing"

	"github.com/jroedel/adb-broker/business/domain/device/devicebus"
	"github.com/jroedel/adb-broker/business/types/devicepath"
	"github.com/jroedel/adb-broker/business/types/errcode"
	"github.com/jroedel/adb-broker/business/types/serial"
)

// fakeStorer is a devicebus.Storer test double. Each method records what it was called
// with and defers to an optional hook function, falling back to a zero-value success.
type fakeStorer struct {
	probeFn         func(ctx context.Context, s serial.Serial) (devicebus.Device, error)
	resolveVolumeFn func(ctx context.Context) (devicepath.Volume, error)
	listFn          func(ctx context.Context, in devicebus.ListInput, vol devicepath.Volume, fn func(devicebus.FileRecord) error) (devicebus.ListSummary, error)
	fetchFn         func(ctx context.Context, p devicepath.AuthorizedPath, vol devicepath.Volume, w io.Writer) (devicebus.FetchResult, error)

	resolveVolumeCalls int
	listCalledWithVol  devicepath.Volume
	fetchCalledWithVol devicepath.Volume
}

func (f *fakeStorer) Probe(ctx context.Context, s serial.Serial) (devicebus.Device, error) {
	if f.probeFn != nil {
		return f.probeFn(ctx, s)
	}
	return devicebus.Device{Serial: s}, nil
}

func (f *fakeStorer) ResolveVolume(ctx context.Context) (devicepath.Volume, error) {
	f.resolveVolumeCalls++
	if f.resolveVolumeFn != nil {
		return f.resolveVolumeFn(ctx)
	}
	return devicepath.Volume{}, nil
}

func (f *fakeStorer) List(ctx context.Context, in devicebus.ListInput, vol devicepath.Volume, fn func(devicebus.FileRecord) error) (devicebus.ListSummary, error) {
	f.listCalledWithVol = vol
	if f.listFn != nil {
		return f.listFn(ctx, in, vol, fn)
	}
	return devicebus.ListSummary{}, nil
}

func (f *fakeStorer) Fetch(ctx context.Context, p devicepath.AuthorizedPath, vol devicepath.Volume, w io.Writer, before func(devicebus.FetchInfo) error) (devicebus.FetchResult, error) {
	f.fetchCalledWithVol = vol
	if f.fetchFn != nil {
		return f.fetchFn(ctx, p, vol, w)
	}
	return devicebus.FetchResult{}, nil
}

// mustVolume pins a devicepath.Volume for test fixtures, via the same ResolveVolume
// constructor the real package uses — there is no other way to build a non-zero Volume.
func mustVolume(t *testing.T, dev, ino int64) devicepath.Volume {
	t.Helper()

	vol, err := devicepath.ResolveVolume(func(string) (int64, int64, uint32, error) {
		return dev, ino, 0o040000, nil // S_IFDIR
	})
	if err != nil {
		t.Fatalf("mustVolume: %v", err)
	}

	return vol
}

func mustSerial(t *testing.T, s string) serial.Serial {
	t.Helper()

	ser, err := serial.ParseSerial(s)
	if err != nil {
		t.Fatalf("mustSerial: %v", err)
	}

	return ser
}

func mustPath(t *testing.T, s string) devicepath.AuthorizedPath {
	t.Helper()

	p, err := devicepath.ParseAuthorizedPath(s)
	if err != nil {
		t.Fatalf("mustPath: %v", err)
	}

	return p
}

// orderExt is a bare-bones Extension that records its name in a shared slice before
// delegating, so tests can observe wrap order across all three ExtBusiness methods.
type orderExt struct {
	name  string
	bus   devicebus.ExtBusiness
	order *[]string
}

func (e *orderExt) Probe(ctx context.Context, s serial.Serial) (devicebus.Device, error) {
	*e.order = append(*e.order, e.name)
	return e.bus.Probe(ctx, s)
}

func (e *orderExt) List(ctx context.Context, in devicebus.ListInput, fn func(devicebus.FileRecord) error) (devicebus.ListSummary, error) {
	*e.order = append(*e.order, e.name)
	return e.bus.List(ctx, in, fn)
}

func (e *orderExt) Fetch(ctx context.Context, p devicepath.AuthorizedPath, w io.Writer, before func(devicebus.FetchInfo) error) (devicebus.FetchResult, error) {
	*e.order = append(*e.order, e.name)
	return e.bus.Fetch(ctx, p, w, before)
}

func newOrderExt(name string, order *[]string) devicebus.Extension {
	return func(bus devicebus.ExtBusiness) devicebus.ExtBusiness {
		return &orderExt{name: name, bus: bus, order: order}
	}
}

// 1. Probe returns the Device from the Storer with Volume populated from ResolveVolume.
func TestProbe_PopulatesVolume(t *testing.T) {
	vol := mustVolume(t, 190, 4812)
	ser := mustSerial(t, "emulator-5554")

	store := &fakeStorer{
		probeFn: func(_ context.Context, s serial.Serial) (devicebus.Device, error) {
			return devicebus.Device{Serial: s, State: "unauthorized"}, nil
		},
		resolveVolumeFn: func(context.Context) (devicepath.Volume, error) {
			return vol, nil
		},
	}

	biz := devicebus.NewBusiness(store)

	dev, err := biz.Probe(t.Context(), ser)
	if err != nil {
		t.Fatalf("Probe: unexpected error: %v", err)
	}
	if dev.State != "unauthorized" {
		t.Errorf("State = %q, want %q", dev.State, "unauthorized")
	}
	if dev.Volume != vol {
		t.Errorf("Volume = %+v, want %+v", dev.Volume, vol)
	}
}

// 2. Probe fails when ResolveVolume fails, and the returned Device is the zero value.
func TestProbe_FailsWhenResolveVolumeFails(t *testing.T) {
	errBoom := errors.New("resolve boom")
	ser := mustSerial(t, "emulator-5554")

	store := &fakeStorer{
		probeFn: func(_ context.Context, s serial.Serial) (devicebus.Device, error) {
			return devicebus.Device{Serial: s, State: "unauthorized"}, nil
		},
		resolveVolumeFn: func(context.Context) (devicepath.Volume, error) {
			return devicepath.Volume{}, errBoom
		},
	}

	biz := devicebus.NewBusiness(store)

	dev, err := biz.Probe(t.Context(), ser)
	if !errors.Is(err, errBoom) {
		t.Fatalf("Probe: err = %v, want wrapping %v", err, errBoom)
	}
	if !reflect.DeepEqual(dev, devicebus.Device{}) {
		t.Errorf("Device = %+v, want zero value", dev)
	}
}

// 3. List calls store.List with the volume from ResolveVolume, and the summary carries it.
func TestList_ThreadsVolume(t *testing.T) {
	vol := mustVolume(t, 190, 999)

	store := &fakeStorer{
		resolveVolumeFn: func(context.Context) (devicepath.Volume, error) {
			return vol, nil
		},
		listFn: func(_ context.Context, _ devicebus.ListInput, _ devicepath.Volume, _ func(devicebus.FileRecord) error) (devicebus.ListSummary, error) {
			return devicebus.ListSummary{Files: 3}, nil
		},
	}

	biz := devicebus.NewBusiness(store)

	summary, err := biz.List(t.Context(), devicebus.ListInput{}, func(devicebus.FileRecord) error { return nil })
	if err != nil {
		t.Fatalf("List: unexpected error: %v", err)
	}
	if store.listCalledWithVol != vol {
		t.Errorf("store.List called with vol = %+v, want %+v", store.listCalledWithVol, vol)
	}
	if summary.Volume != vol {
		t.Errorf("summary.Volume = %+v, want %+v", summary.Volume, vol)
	}
	if summary.Files != 3 {
		t.Errorf("summary.Files = %d, want 3", summary.Files)
	}
}

// 4. Fetch calls store.Fetch with the volume, and the result carries it.
func TestFetch_ThreadsVolume(t *testing.T) {
	vol := mustVolume(t, 190, 42)
	path := mustPath(t, "/sdcard/DCIM/a.jpg")

	store := &fakeStorer{
		resolveVolumeFn: func(context.Context) (devicepath.Volume, error) {
			return vol, nil
		},
		fetchFn: func(_ context.Context, _ devicepath.AuthorizedPath, _ devicepath.Volume, _ io.Writer) (devicebus.FetchResult, error) {
			return devicebus.FetchResult{Bytes: 128, SHA256: "deadbeef"}, nil
		},
	}

	biz := devicebus.NewBusiness(store)

	result, err := biz.Fetch(t.Context(), path, io.Discard, nil)
	if err != nil {
		t.Fatalf("Fetch: unexpected error: %v", err)
	}
	if store.fetchCalledWithVol != vol {
		t.Errorf("store.Fetch called with vol = %+v, want %+v", store.fetchCalledWithVol, vol)
	}
	if result.Volume != vol {
		t.Errorf("result.Volume = %+v, want %+v", result.Volume, vol)
	}
	if result.Bytes != 128 || result.SHA256 != "deadbeef" {
		t.Errorf("result = %+v, want Bytes=128 SHA256=deadbeef", result)
	}
}

// 5. The volume is resolved exactly once across a Probe + List + Fetch sequence on one
// Business.
func TestResolveVolume_CachedAcrossCalls(t *testing.T) {
	vol := mustVolume(t, 190, 7)
	ser := mustSerial(t, "emulator-5554")
	path := mustPath(t, "/sdcard/DCIM/a.jpg")

	store := &fakeStorer{
		resolveVolumeFn: func(context.Context) (devicepath.Volume, error) {
			return vol, nil
		},
	}

	biz := devicebus.NewBusiness(store)

	if _, err := biz.Probe(t.Context(), ser); err != nil {
		t.Fatalf("Probe: unexpected error: %v", err)
	}
	if _, err := biz.List(t.Context(), devicebus.ListInput{}, func(devicebus.FileRecord) error { return nil }); err != nil {
		t.Fatalf("List: unexpected error: %v", err)
	}
	if _, err := biz.Fetch(t.Context(), path, io.Discard, nil); err != nil {
		t.Fatalf("Fetch: unexpected error: %v", err)
	}

	if store.resolveVolumeCalls != 1 {
		t.Errorf("ResolveVolume called %d times, want 1", store.resolveVolumeCalls)
	}
}

// 6. A failed resolution is not cached as success.
func TestResolveVolume_FailureNotCached(t *testing.T) {
	errBoom := errors.New("resolve boom")
	vol := mustVolume(t, 190, 7)

	attempt := 0
	store := &fakeStorer{
		resolveVolumeFn: func(context.Context) (devicepath.Volume, error) {
			attempt++
			if attempt == 1 {
				return devicepath.Volume{}, errBoom
			}
			return vol, nil
		},
	}

	biz := devicebus.NewBusiness(store)

	if _, err := biz.List(t.Context(), devicebus.ListInput{}, func(devicebus.FileRecord) error { return nil }); !errors.Is(err, errBoom) {
		t.Fatalf("first List: err = %v, want wrapping %v", err, errBoom)
	}

	summary, err := biz.List(t.Context(), devicebus.ListInput{}, func(devicebus.FileRecord) error { return nil })
	if err != nil {
		t.Fatalf("second List: unexpected error: %v", err)
	}
	if summary.Volume != vol {
		t.Errorf("second List: summary.Volume = %+v, want %+v", summary.Volume, vol)
	}
}

// 7. Extensions apply outermost-first, exercised across all three methods.
func TestNewBusiness_ExtensionOrder(t *testing.T) {
	vol := mustVolume(t, 190, 1)
	ser := mustSerial(t, "emulator-5554")
	path := mustPath(t, "/sdcard/DCIM/a.jpg")

	store := &fakeStorer{
		resolveVolumeFn: func(context.Context) (devicepath.Volume, error) {
			return vol, nil
		},
	}

	var order []string
	extA := newOrderExt("A", &order)
	extB := newOrderExt("B", &order)

	biz := devicebus.NewBusiness(store, extA, extB)

	order = nil
	if _, err := biz.Probe(t.Context(), ser); err != nil {
		t.Fatalf("Probe: unexpected error: %v", err)
	}
	if want := []string{"A", "B"}; !slices.Equal(order, want) {
		t.Errorf("Probe order = %v, want %v", order, want)
	}

	order = nil
	if _, err := biz.List(t.Context(), devicebus.ListInput{}, func(devicebus.FileRecord) error { return nil }); err != nil {
		t.Fatalf("List: unexpected error: %v", err)
	}
	if want := []string{"A", "B"}; !slices.Equal(order, want) {
		t.Errorf("List order = %v, want %v", order, want)
	}

	order = nil
	if _, err := biz.Fetch(t.Context(), path, io.Discard, nil); err != nil {
		t.Fatalf("Fetch: unexpected error: %v", err)
	}
	if want := []string{"A", "B"}; !slices.Equal(order, want) {
		t.Errorf("Fetch order = %v, want %v", order, want)
	}
}

// 8. A nil extension in the list is skipped, not a panic.
func TestNewBusiness_SkipsNilExtension(t *testing.T) {
	vol := mustVolume(t, 190, 1)
	ser := mustSerial(t, "emulator-5554")

	store := &fakeStorer{
		resolveVolumeFn: func(context.Context) (devicepath.Volume, error) {
			return vol, nil
		},
	}

	var order []string
	extA := newOrderExt("A", &order)

	biz := devicebus.NewBusiness(store, nil, extA, nil)

	if _, err := biz.Probe(t.Context(), ser); err != nil {
		t.Fatalf("Probe: unexpected error: %v", err)
	}
	if want := []string{"A"}; !slices.Equal(order, want) {
		t.Errorf("order = %v, want %v", order, want)
	}
}

// 9. List propagates a callback error and stops.
func TestList_PropagatesCallbackError(t *testing.T) {
	vol := mustVolume(t, 190, 1)
	callbackErr := errors.New("callback boom")

	reachedAfterErr := false
	store := &fakeStorer{
		resolveVolumeFn: func(context.Context) (devicepath.Volume, error) {
			return vol, nil
		},
		listFn: func(_ context.Context, _ devicebus.ListInput, _ devicepath.Volume, fn func(devicebus.FileRecord) error) (devicebus.ListSummary, error) {
			if err := fn(devicebus.FileRecord{}); err != nil {
				return devicebus.ListSummary{}, err
			}
			reachedAfterErr = true
			return devicebus.ListSummary{Files: 999}, nil
		},
	}

	biz := devicebus.NewBusiness(store)

	_, err := biz.List(t.Context(), devicebus.ListInput{}, func(devicebus.FileRecord) error {
		return callbackErr
	})
	if !errors.Is(err, callbackErr) {
		t.Fatalf("List: err = %v, want wrapping %v", err, callbackErr)
	}
	if reachedAfterErr {
		t.Error("List: walk continued past the callback error")
	}
}

// 10. List does not buffer: the callback is invoked before List returns.
func TestList_DoesNotBuffer(t *testing.T) {
	vol := mustVolume(t, 190, 1)

	var events []string
	store := &fakeStorer{
		resolveVolumeFn: func(context.Context) (devicepath.Volume, error) {
			return vol, nil
		},
		listFn: func(_ context.Context, _ devicebus.ListInput, _ devicepath.Volume, fn func(devicebus.FileRecord) error) (devicebus.ListSummary, error) {
			err := fn(devicebus.FileRecord{})
			events = append(events, "store-list-after-fn")
			return devicebus.ListSummary{}, err
		},
	}

	biz := devicebus.NewBusiness(store)

	_, err := biz.List(t.Context(), devicebus.ListInput{}, func(devicebus.FileRecord) error {
		events = append(events, "callback")
		return nil
	})
	if err != nil {
		t.Fatalf("List: unexpected error: %v", err)
	}

	want := []string{"callback", "store-list-after-fn"}
	if !slices.Equal(events, want) {
		t.Errorf("events = %v, want %v", events, want)
	}
}

// 11. A Storer error from each of the three methods propagates unchanged.
func TestStorerErrors_PropagateUnchanged(t *testing.T) {
	vol := mustVolume(t, 190, 1)
	ser := mustSerial(t, "emulator-5554")
	path := mustPath(t, "/sdcard/DCIM/a.jpg")

	probeErr := errors.New("probe boom")
	listErr := errors.New("list boom")
	fetchErr := errors.New("fetch boom")

	store := &fakeStorer{
		resolveVolumeFn: func(context.Context) (devicepath.Volume, error) {
			return vol, nil
		},
		probeFn: func(context.Context, serial.Serial) (devicebus.Device, error) {
			return devicebus.Device{}, probeErr
		},
		listFn: func(context.Context, devicebus.ListInput, devicepath.Volume, func(devicebus.FileRecord) error) (devicebus.ListSummary, error) {
			return devicebus.ListSummary{}, listErr
		},
		fetchFn: func(context.Context, devicepath.AuthorizedPath, devicepath.Volume, io.Writer) (devicebus.FetchResult, error) {
			return devicebus.FetchResult{}, fetchErr
		},
	}

	biz := devicebus.NewBusiness(store)

	if _, err := biz.Probe(t.Context(), ser); !errors.Is(err, probeErr) {
		t.Errorf("Probe: err = %v, want wrapping %v", err, probeErr)
	}
	if _, err := biz.List(t.Context(), devicebus.ListInput{}, func(devicebus.FileRecord) error { return nil }); !errors.Is(err, listErr) {
		t.Errorf("List: err = %v, want wrapping %v", err, listErr)
	}
	if _, err := biz.Fetch(t.Context(), path, io.Discard, nil); !errors.Is(err, fetchErr) {
		t.Errorf("Fetch: err = %v, want wrapping %v", err, fetchErr)
	}
}

// 12. ListSummary.RefusedEntries and Errors pass through untouched.
func TestList_SummaryPassesThroughUntouched(t *testing.T) {
	vol := mustVolume(t, 190, 1)
	path := mustPath(t, "/sdcard/DCIM/denied.jpg")

	wantErrors := []devicebus.PathError{
		{Path: path, Code: errcode.CodePermissionDenied},
	}

	store := &fakeStorer{
		resolveVolumeFn: func(context.Context) (devicepath.Volume, error) {
			return vol, nil
		},
		listFn: func(context.Context, devicebus.ListInput, devicepath.Volume, func(devicebus.FileRecord) error) (devicebus.ListSummary, error) {
			return devicebus.ListSummary{
				Files:          5,
				RefusedEntries: 2,
				Errors:         wantErrors,
			}, nil
		},
	}

	biz := devicebus.NewBusiness(store)

	summary, err := biz.List(t.Context(), devicebus.ListInput{}, func(devicebus.FileRecord) error { return nil })
	if err != nil {
		t.Fatalf("List: unexpected error: %v", err)
	}
	if summary.RefusedEntries != 2 {
		t.Errorf("RefusedEntries = %d, want 2", summary.RefusedEntries)
	}
	if !reflect.DeepEqual(summary.Errors, wantErrors) {
		t.Errorf("Errors = %+v, want %+v", summary.Errors, wantErrors)
	}
}
