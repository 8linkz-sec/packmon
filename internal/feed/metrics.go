package feed

const (
	// QueueJobResultSuccess and QueueJobResultError are the bounded queue-job
	// result labels emitted through the MetricsRecorder port.
	QueueJobResultSuccess = "success"
	QueueJobResultError   = "error"
)

// MetricsRecorder is the feed-owned metrics port used by feed sync loops and
// async queue workers. Server composition injects the concrete telemetry
// adapter; tests and non-server callers default to a no-op recorder.
type MetricsRecorder interface {
	AddQueueStuckRecovered(count int)
	IncFeedSyncTimeout(feed string)
	IncQueueError(source string)
	IncQueueJobCompleted(source, result string)
}

type noopMetricsRecorder struct{}

// NoopMetricsRecorder returns a recorder that intentionally drops all metrics.
func NoopMetricsRecorder() MetricsRecorder {
	return noopMetricsRecorder{}
}

// MetricsRecorderOrNoop returns recorder when non-nil, otherwise a no-op
// recorder.
func MetricsRecorderOrNoop(recorder MetricsRecorder) MetricsRecorder {
	if recorder == nil {
		return NoopMetricsRecorder()
	}
	return recorder
}

func (noopMetricsRecorder) AddQueueStuckRecovered(int) {}
func (noopMetricsRecorder) IncFeedSyncTimeout(string)  {}
func (noopMetricsRecorder) IncQueueError(string)       {}
func (noopMetricsRecorder) IncQueueJobCompleted(string, string) {
}

type metricsRecorderOption struct {
	recorder MetricsRecorder
}

// WithMetricsRecorder injects a feed metrics recorder into components that
// accept feed options.
func WithMetricsRecorder(recorder MetricsRecorder) metricsRecorderOption {
	return metricsRecorderOption{recorder: recorder}
}

func (o metricsRecorderOption) applyManagerOption(m *Manager) {
	m.metrics = MetricsRecorderOrNoop(o.recorder)
}

func (o metricsRecorderOption) applyQueueOption(q *QueueProcessor) {
	q.metrics = MetricsRecorderOrNoop(o.recorder)
}
