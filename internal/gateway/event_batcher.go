package gateway

import (
	"context"
	"errors"
	"log/slog"
	"sync"
	"time"

	"captcha/internal/types"
)

type eventBatcherOptions struct {
	MaxSize       int
	FlushInterval time.Duration
	QueueSize     int
	ReportTimeout time.Duration
	Logger        *slog.Logger
}

type eventBatcher struct {
	client        EventClient
	maxSize       int
	flushInterval time.Duration
	reportTimeout time.Duration
	logger        *slog.Logger
	queue         chan types.AuditEvent
	stop          chan struct{}
	done          chan struct{}
	once          sync.Once
}

var errEventQueueFull = errors.New("gateway event queue full")
var errEventBatcherClosed = errors.New("gateway event batcher closed")

func newEventBatcher(client EventClient, options eventBatcherOptions) *eventBatcher {
	maxSize := options.MaxSize
	if maxSize <= 1 {
		maxSize = 10
	}
	flushInterval := options.FlushInterval
	if flushInterval <= 0 {
		flushInterval = time.Second
	}
	queueSize := options.QueueSize
	if queueSize <= 0 {
		queueSize = maxSize * 4
	}
	if queueSize < maxSize {
		queueSize = maxSize
	}
	reportTimeout := options.ReportTimeout
	if reportTimeout <= 0 {
		reportTimeout = 1500 * time.Millisecond
	}
	logger := options.Logger
	if logger == nil {
		logger = slog.Default()
	}
	batcher := &eventBatcher{
		client:        client,
		maxSize:       maxSize,
		flushInterval: flushInterval,
		reportTimeout: reportTimeout,
		logger:        logger,
		queue:         make(chan types.AuditEvent, queueSize),
		stop:          make(chan struct{}),
		done:          make(chan struct{}),
	}
	go batcher.run()
	return batcher
}

func (b *eventBatcher) Report(ctx context.Context, events []types.AuditEvent) (types.ReportResult, error) {
	accepted := 0
	for _, event := range events {
		select {
		case <-b.stop:
			return types.ReportResult{Accepted: accepted}, errEventBatcherClosed
		default:
		}
		select {
		case b.queue <- event:
			accepted++
		case <-b.stop:
			return types.ReportResult{Accepted: accepted}, errEventBatcherClosed
		case <-ctx.Done():
			return types.ReportResult{Accepted: accepted}, ctx.Err()
		default:
			return types.ReportResult{Accepted: accepted}, errEventQueueFull
		}
	}
	return types.ReportResult{Accepted: accepted}, nil
}

func (b *eventBatcher) Close() {
	b.once.Do(func() {
		close(b.stop)
		<-b.done
	})
}

func (b *eventBatcher) run() {
	defer close(b.done)
	ticker := time.NewTicker(b.flushInterval)
	defer ticker.Stop()

	batch := make([]types.AuditEvent, 0, b.maxSize)
	flush := func() {
		if len(batch) == 0 {
			return
		}
		events := append([]types.AuditEvent(nil), batch...)
		batch = batch[:0]
		b.send(events)
	}

	for {
		select {
		case event := <-b.queue:
			batch = append(batch, event)
			if len(batch) >= b.maxSize {
				flush()
			}
		case <-ticker.C:
			flush()
		case <-b.stop:
			for {
				select {
				case event := <-b.queue:
					batch = append(batch, event)
					if len(batch) >= b.maxSize {
						flush()
					}
				default:
					flush()
					return
				}
			}
		}
	}
}

func (b *eventBatcher) send(events []types.AuditEvent) {
	ctx, cancel := context.WithTimeout(context.Background(), b.reportTimeout)
	defer cancel()
	if _, err := b.client.Report(ctx, events); err != nil {
		b.logger.Warn("gateway batched event report failed", "error", err, "events", len(events))
	}
}
