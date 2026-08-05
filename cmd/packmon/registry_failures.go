package main

import (
	"context"
	"sync/atomic"
	"time"
)

const (
	// registryBreakerThreshold is the number of consecutive failed registry
	// requests after which the lookup phase stops issuing new requests. A dead
	// network fails every request; a rate-limited or flaky registry does not
	// fail 20 in a row without a single success in between.
	registryBreakerThreshold = 20
	// defaultPerRequestLookupTimeout bounds a single registry request when no
	// phase (and therefore no --timeout value) is attached to the context.
	defaultPerRequestLookupTimeout = 30 * time.Second
)

// registryLookupPhase carries the state of one latest-version lookup phase:
// failure accounting for honest warnings, the consecutive-failure breaker, and
// the per-request timeout. The phase itself has no deadline; its duration is
// bounded by the request rate limiter and, on dead networks, by the breaker.
//
// Counters count HTTP requests, not packages: a cached lookup issues no
// request and cannot be refused, and a 404 is a definitive answer -- the
// package does not exist on that registry -- rather than a failure to reach it.
type registryLookupPhase struct {
	refused        atomic.Int64
	skipped        atomic.Int64
	consecutive    atomic.Int64
	breakerTripped atomic.Bool
	requestTimeout time.Duration
}

func (p *registryLookupPhase) recordRefusal() {
	if p == nil {
		return
	}
	p.refused.Add(1)
	if p.consecutive.Add(1) >= registryBreakerThreshold {
		p.breakerTripped.Store(true)
	}
}

func (p *registryLookupPhase) recordSuccess() {
	if p == nil {
		return
	}
	p.consecutive.Store(0)
}

func (p *registryLookupPhase) recordSkipped() {
	if p == nil {
		return
	}
	p.skipped.Add(1)
}

func (p *registryLookupPhase) breakerOpen() bool {
	if p == nil {
		return false
	}
	return p.breakerTripped.Load()
}

func (p *registryLookupPhase) refusedCount() int {
	if p == nil {
		return 0
	}
	return int(p.refused.Load())
}

func (p *registryLookupPhase) skippedCount() int {
	if p == nil {
		return 0
	}
	return int(p.skipped.Load())
}

func (p *registryLookupPhase) perRequestTimeout() time.Duration {
	if p == nil || p.requestTimeout <= 0 {
		return defaultPerRequestLookupTimeout
	}
	return p.requestTimeout
}

type registryLookupPhaseKey struct{}

// withRegistryLookupPhase scopes lookup-phase state to the context. It sets no
// deadline: parent cancellation still propagates, and each request bounds
// itself with perRequestTimeout.
func withRegistryLookupPhase(parent context.Context, timeoutSeconds int) (context.Context, *registryLookupPhase) {
	if parent == nil {
		parent = context.Background()
	}
	phase := &registryLookupPhase{}
	if timeoutSeconds > 0 {
		phase.requestTimeout = time.Duration(timeoutSeconds) * time.Second
	}
	return context.WithValue(parent, registryLookupPhaseKey{}, phase), phase
}

func registryLookupPhaseFrom(ctx context.Context) *registryLookupPhase {
	if ctx == nil {
		return nil
	}
	phase, _ := ctx.Value(registryLookupPhaseKey{}).(*registryLookupPhase)
	return phase
}
