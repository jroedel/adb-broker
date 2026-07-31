// Package devicebus is the Business layer for reading a phone: the domain model, the
// Storer port a transport implements, and the Business core that pins a storage volume
// before any path is served.
//
// The one guarantee this package exists to provide is that a path is never read before
// the device's storage volume has been resolved. Storer, the transport port, takes a
// devicepath.Volume on every method that touches a path — a caller holding a Storer
// cannot fetch or list without one. ExtBusiness, the seam a caller and every extension
// actually see, takes no Volume at all: Business resolves it internally and threads it
// to the Storer, so "fetch before the volume was pinned" is not a bug review has to
// catch, it is a call that cannot be written. The pinned Volume still reaches the
// caller — outward, on Device, ListSummary and FetchResult — so an extension such as an
// audit log can record which volume this run trusted.
package devicebus

import (
	"context"
	"io"
	"sync"

	"github.com/jroedel/adb-broker/business/types/devicepath"
	"github.com/jroedel/adb-broker/business/types/serial"
)

// Storer is the transport port. Every method that touches a path requires BOTH an
// AuthorizedPath and a pinned Volume, so a caller holding only one cannot express an
// operation.
//
// The Volume parameter exists here, on the port, because the Storer is what actually
// walks or reads the device filesystem — it is the thing an unpinned read would harm.
// ExtBusiness, one layer up, drops the parameter entirely: Business is the sole holder
// of the pin, resolving it once via ResolveVolume and supplying it to every Storer call,
// which is what makes an unpinned path operation unexpressible above this port.
type Storer interface {
	Probe(ctx context.Context, s serial.Serial) (Device, error)
	ResolveVolume(ctx context.Context) (devicepath.Volume, error)
	List(ctx context.Context, in ListInput, vol devicepath.Volume, fn func(FileRecord) error) (ListSummary, error)
	Fetch(ctx context.Context, p devicepath.AuthorizedPath, vol devicepath.Volume, w io.Writer) (FetchResult, error)
}

// ExtBusiness lists every public method an extension can wrap.
//
// Unlike Storer, no method here takes a devicepath.Volume. The volume is not a caller
// concern at this layer — it is resolved once, internally, by Business, and travels only
// OUTWARD on the returned Device, ListSummary and FetchResult. That asymmetry is the
// confinement guarantee: a caller or extension holding only an ExtBusiness has no way to
// supply a volume of its own, correct or otherwise, so it cannot express a path operation
// against an unpinned or forged volume. Do not "simplify" this by adding a Volume
// parameter here — that would hand every caller exactly the capability this seam exists
// to withhold.
type ExtBusiness interface {
	Probe(ctx context.Context, s serial.Serial) (Device, error)
	List(ctx context.Context, in ListInput, fn func(FileRecord) error) (ListSummary, error)
	Fetch(ctx context.Context, p devicepath.AuthorizedPath, w io.Writer) (FetchResult, error)
}

// Extension wraps a new layer of business logic around the existing logic.
type Extension func(ExtBusiness) ExtBusiness

// Business is the core devicebus implementation. It resolves the device's storage
// volume lazily, caches it for the process lifetime once resolution succeeds, and
// threads it to every Storer call so a path is never read before it is pinned.
type Business struct {
	store Storer

	mu       sync.Mutex
	volume   devicepath.Volume
	resolved bool
}

// NewBusiness constructs the devicebus Business and wraps it with extensions.
//
// Extensions apply in reverse: the first-listed extension becomes the OUTERMOST
// wrapper, so it runs first on the way in and last on the way out. A nil extension is
// skipped rather than applied.
func NewBusiness(store Storer, extensions ...Extension) ExtBusiness {
	b := ExtBusiness(&Business{store: store})

	for i := len(extensions) - 1; i >= 0; i-- {
		ext := extensions[i]
		if ext == nil {
			continue
		}
		b = ext(b)
	}

	return b
}

// resolveVolume resolves the device's storage volume on first need and caches it for
// the lifetime of b. A resolution error is never cached: the broker is one-shot, so a
// transient failure must not poison every later call in the same process with a false
// "resolved" state, and it must never fall back to an unpinned zero Volume, which would
// be an unauthorised read.
func (b *Business) resolveVolume(ctx context.Context) (devicepath.Volume, error) {
	b.mu.Lock()
	defer b.mu.Unlock()

	if b.resolved {
		return b.volume, nil
	}

	vol, err := b.store.ResolveVolume(ctx)
	if err != nil {
		return devicepath.Volume{}, err
	}

	b.volume = vol
	b.resolved = true

	return vol, nil
}

// Probe reads the device's identity and pins its storage volume in the same call, so a
// device whose storage is not in the expected shape is discovered once, up front, rather
// than during listing. If volume resolution fails, Probe returns the zero Device and the
// error — the store's Probe result is discarded rather than returned half-populated.
func (b *Business) Probe(ctx context.Context, s serial.Serial) (Device, error) {
	dev, err := b.store.Probe(ctx, s)
	if err != nil {
		return Device{}, err
	}

	vol, err := b.resolveVolume(ctx)
	if err != nil {
		return Device{}, err
	}

	dev.Volume = vol

	return dev, nil
}

// List resolves the pinned volume and streams the walk through fn without buffering:
// fn is passed straight to the Storer, so a large listing is consumable incrementally,
// and an error fn returns propagates and stops the walk.
func (b *Business) List(ctx context.Context, in ListInput, fn func(FileRecord) error) (ListSummary, error) {
	vol, err := b.resolveVolume(ctx)
	if err != nil {
		return ListSummary{}, err
	}

	summary, err := b.store.List(ctx, in, vol, fn)
	if err != nil {
		return summary, err
	}

	summary.Volume = vol

	return summary, nil
}

// Fetch resolves the pinned volume and streams p's contents to w via the Storer.
func (b *Business) Fetch(ctx context.Context, p devicepath.AuthorizedPath, w io.Writer) (FetchResult, error) {
	vol, err := b.resolveVolume(ctx)
	if err != nil {
		return FetchResult{}, err
	}

	result, err := b.store.Fetch(ctx, p, vol, w)
	if err != nil {
		return result, err
	}

	result.Volume = vol

	return result, nil
}
