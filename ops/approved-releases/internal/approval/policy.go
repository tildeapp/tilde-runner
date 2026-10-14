package approval

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"errors"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"sync"
	"time"
)

const (
	// RefreshInterval is how long a fetched list is used before the next call fetches again; a
	// revocation therefore takes effect within one interval of the app's next request.
	RefreshInterval = 10 * time.Minute
	// RetryInterval bounds fetch attempts while the source is unreachable.
	RetryInterval = 60 * time.Second
	// MaxAge marks a list stale. A stale list is still used: staleness warns, it does not refuse.
	MaxAge       = 7 * 24 * time.Hour
	FetchTimeout = 10 * time.Second
	cacheName    = "approved-releases.v1"
)

var (
	// ErrUnavailable: no verified list, neither fetched nor cached, so nothing is approved; or,
	// from CheckFresh, a fetch for a release the list does not name did not finish in time.
	ErrUnavailable = errors.New("approval list unavailable")
	// ErrRevoked: the verified release is on the list's revoked set.
	ErrRevoked = errors.New("release revoked")
	// ErrNotApproved: the verified release is on neither set.
	ErrNotApproved = errors.New("release not approved")

	errRollback    = errors.New("approval list version below the cached version")
	errEquivocates = errors.New("approval list differs from the cached list at the same version")
	errRetiredKey  = errors.New("approval list not signed by the cached list's key or its successor")
)

// Source returns the signed list bytes. The transport is untrusted; only the signature matters.
type Source func(ctx context.Context) ([]byte, error)

type Status int

const (
	StatusUnavailable Status = iota
	StatusFresh
	StatusStale
)

// Policy holds the newest verified list and decides which releases are approved.
type Policy struct {
	anchor   ed25519.PublicKey
	source   Source
	fallback string
	now      func() time.Time

	mu          sync.Mutex
	cacheDir    string
	loaded      bool
	current     *Verified
	raw         []byte
	lastSuccess time.Time
	lastAttempt time.Time
	inflight    chan struct{}
}

// NewPolicy trusts anchor (the compiled approval key). fallback is a digest approved only while
// no verified list exists; it is empty in every release build.
func NewPolicy(anchor ed25519.PublicKey, source Source, fallback string, now func() time.Time) *Policy {
	if now == nil {
		now = time.Now
	}
	return &Policy{anchor: anchor, source: source, fallback: fallback, now: now}
}

// SetCacheDir sets where the newest verified bytes persist. Without one the list lives in memory.
func (p *Policy) SetCacheDir(dir string) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.cacheDir = dir
	p.loaded = false
	if p.current == nil {
		return
	}
	// A list accepted before the directory was known is persisted now, after the on-disk copy has
	// had its chance to move the list forward, so a newer cached list is never written over.
	p.loadCache()
	p.writeCache(p.raw)
	p.loaded = false
}

// Refresh starts from the cached copy, fetches when the list is due, and reports ErrUnavailable
// only when no verified list exists afterwards. A failed or refused fetch keeps the current list.
func (p *Policy) Refresh(ctx context.Context) error {
	return p.refresh(ctx, false)
}

// CheckFresh is Check, except that a release the current list does not name sends one fetch ahead
// of RefreshInterval (still at most one attempt per RetryInterval) and is checked again, so a
// release approved by a newly published list is admitted at once instead of after the interval.
func (p *Policy) CheckFresh(ctx context.Context, digest string) error {
	err := p.Check(digest)
	if !errors.Is(err, ErrNotApproved) {
		return err
	}
	cut := p.refresh(ctx, true)
	err = p.Check(digest)
	if errors.Is(err, ErrNotApproved) && cut != nil {
		// The fetch did not finish in time, so the release is unconfirmed rather than refused.
		return ErrUnavailable
	}
	return err
}

// errCut: an early refresh's fetch, or its wait for one in flight, ended with its context.
var errCut = errors.New("approval list fetch did not finish")

// refresh fetches when the list is due, or with early regardless of RefreshInterval; early also
// waits for a fetch already in flight, so its caller sees that fetch's list, and reports errCut
// when that fetch or wait ended with a context. A fetch that was skipped or completed is not cut.
func (p *Policy) refresh(ctx context.Context, early bool) error {
	p.mu.Lock()
	p.loadCache()
	now := p.now()
	due := early || p.current == nil || now.Sub(p.lastSuccess) >= RefreshInterval
	retry := p.lastAttempt.IsZero() || now.Sub(p.lastAttempt) >= RetryInterval
	cut := false
	if due && retry && p.inflight == nil && p.source != nil {
		done := make(chan struct{})
		p.inflight, p.lastAttempt = done, now
		p.mu.Unlock()
		raw, err := p.fetch(ctx)
		p.mu.Lock()
		if err == nil && p.accept(raw) == nil {
			p.lastSuccess = p.now()
		}
		cut = errors.Is(err, context.DeadlineExceeded) || errors.Is(err, context.Canceled)
		p.inflight = nil
		close(done)
	}
	waiting := p.inflight
	available := p.current != nil || p.fallback != ""
	p.mu.Unlock()
	if (early || !available) && waiting != nil {
		select {
		case <-waiting:
		case <-ctx.Done():
			if early {
				return errCut
			}
			return ErrUnavailable
		}
		p.mu.Lock()
		available = p.current != nil
		p.mu.Unlock()
	}
	if !available {
		return ErrUnavailable
	}
	if early && cut {
		return errCut
	}
	return nil
}

func (p *Policy) fetch(ctx context.Context) ([]byte, error) {
	ctx, cancel := context.WithTimeout(ctx, FetchTimeout)
	defer cancel()
	return p.source(ctx)
}

// Check decides a verified release digest against the current list, without network access.
func (p *Policy) Check(digest string) error {
	p.mu.Lock()
	current := p.current
	p.mu.Unlock()
	switch {
	case current == nil && p.fallback != "" && digest == p.fallback:
		return nil
	case current == nil:
		return ErrUnavailable
	case current.Revokes(digest):
		return ErrRevoked
	case current.Approves(digest):
		return nil
	default:
		return ErrNotApproved
	}
}

// Status reports whether a verified list exists and whether it is older than MaxAge.
func (p *Policy) Status() (Status, *Verified) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.current == nil {
		return StatusUnavailable, nil
	}
	if p.now().Sub(p.current.IssuedAt) > MaxAge {
		return StatusStale, p.current
	}
	return StatusFresh, p.current
}

// Accept installs raw if it verifies and moves forward from the current list.
func (p *Policy) Accept(raw []byte) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.loadCache()
	return p.accept(raw)
}

func (p *Policy) accept(raw []byte) error {
	verified, err := Verify(raw, p.anchor)
	if err != nil {
		return err
	}
	if current := p.current; current != nil {
		switch {
		case verified.Document.Version < current.Document.Version:
			return errRollback
		case verified.Document.Version == current.Document.Version && bytes.Equal(raw, p.raw):
			return nil
		case verified.Document.Version == current.Document.Version:
			return errEquivocates
		case !verified.trusts(current.Signer):
			// Once a successor has signed a list this device accepted, the earlier key is retired.
			return errRetiredKey
		}
	}
	p.current, p.raw = verified, bytes.Clone(raw)
	p.writeCache(raw)
	return nil
}

func (p *Policy) loadCache() {
	if p.loaded {
		return
	}
	p.loaded = true
	if p.cacheDir == "" {
		return
	}
	raw, err := os.ReadFile(filepath.Join(p.cacheDir, cacheName))
	if err != nil {
		return
	}
	// A cached copy is subject to the same rules as a fetched one; an unverifiable cache is ignored.
	_ = p.accept(raw)
}

func (p *Policy) writeCache(raw []byte) {
	if p.cacheDir == "" || os.MkdirAll(p.cacheDir, 0o700) != nil {
		return
	}
	temporary, err := os.CreateTemp(p.cacheDir, cacheName+".*")
	if err != nil {
		return
	}
	defer os.Remove(temporary.Name())
	if _, err := temporary.Write(raw); err != nil || temporary.Sync() != nil || temporary.Close() != nil {
		temporary.Close()
		return
	}
	_ = os.Rename(temporary.Name(), filepath.Join(p.cacheDir, cacheName))
}

// HTTPSource fetches url over HTTPS without redirects, bounded in size.
func HTTPSource(url string) Source {
	client := &http.Client{
		Timeout:       FetchTimeout,
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}
	return func(ctx context.Context) ([]byte, error) {
		request, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
		if err != nil {
			return nil, err
		}
		request.Header.Set("Accept", "application/json")
		response, err := client.Do(request)
		if err != nil {
			return nil, err
		}
		defer response.Body.Close()
		if response.StatusCode != http.StatusOK {
			return nil, errors.New("approval list fetch failed")
		}
		raw, err := io.ReadAll(io.LimitReader(response.Body, MaxListBytes+1))
		if err != nil || len(raw) > MaxListBytes {
			return nil, ErrMalformed
		}
		return raw, nil
	}
}

// FileSource reads a local file; used by tests and operator tooling.
func FileSource(path string) Source {
	return func(context.Context) ([]byte, error) {
		raw, err := os.ReadFile(path)
		if err != nil {
			return nil, err
		}
		if len(raw) > MaxListBytes {
			return nil, ErrMalformed
		}
		return raw, nil
	}
}
