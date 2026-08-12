package main

import (
	"fmt"
	"io"
	"sync"
	"sync/atomic"
	"time"
)

// lookupProgressInterval spaces the periodic progress lines emitted while the
// latest-version lookup phase runs.
const lookupProgressInterval = 10 * time.Second

// lookupProgress periodically reports how many latest-version lookups have
// completed. A nil reporter is a no-op so quiet runs can skip the goroutine
// while call sites stay unconditional.
type lookupProgress struct {
	w        io.Writer
	total    int
	interval time.Duration
	done     atomic.Int64
	stopCh   chan struct{}
	stopOnce sync.Once
	wg       sync.WaitGroup
}

// startLookupProgress launches the progress reporter. It returns nil (a valid
// no-op reporter) in quiet mode, for empty workloads, or without a writer.
func startLookupProgress(w io.Writer, total int, quiet bool, interval time.Duration) *lookupProgress {
	if quiet || total == 0 || interval <= 0 || w == nil {
		return nil
	}
	p := &lookupProgress{
		w:        w,
		total:    total,
		interval: interval,
		stopCh:   make(chan struct{}),
	}
	p.wg.Add(1)
	go p.loop()
	return p
}

func (p *lookupProgress) loop() {
	defer p.wg.Done()
	ticker := time.NewTicker(p.interval)
	defer ticker.Stop()
	for {
		select {
		case <-p.stopCh:
			return
		case <-ticker.C:
			_, _ = fmt.Fprintf(p.w, "  %d/%d packages checked\n", p.done.Load(), p.total)
		}
	}
}

// increment records one completed lookup.
func (p *lookupProgress) increment() {
	if p == nil {
		return
	}
	p.done.Add(1)
}

// stop ends the reporter and waits for its goroutine so no progress line is
// written after stop returns.
func (p *lookupProgress) stop() {
	if p == nil {
		return
	}
	p.stopOnce.Do(func() { close(p.stopCh) })
	p.wg.Wait()
}
