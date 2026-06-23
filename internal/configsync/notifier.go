package configsync

import "sync"

type Notifier struct {
	mu          sync.Mutex
	version     int64
	subscribers map[chan int64]struct{}
}

func NewNotifier() *Notifier {
	return &Notifier{
		version:     1,
		subscribers: make(map[chan int64]struct{}),
	}
}

func (n *Notifier) Version() int64 {
	if n == nil {
		return 0
	}
	n.mu.Lock()
	defer n.mu.Unlock()
	return n.version
}

func (n *Notifier) Notify() int64 {
	if n == nil {
		return 0
	}
	n.mu.Lock()
	defer n.mu.Unlock()
	n.version++
	for subscriber := range n.subscribers {
		select {
		case subscriber <- n.version:
		default:
			select {
			case <-subscriber:
			default:
			}
			select {
			case subscriber <- n.version:
			default:
			}
		}
	}
	return n.version
}

func (n *Notifier) Subscribe() (<-chan int64, func()) {
	ch := make(chan int64, 1)
	if n == nil {
		close(ch)
		return ch, func() {}
	}
	n.mu.Lock()
	n.subscribers[ch] = struct{}{}
	n.mu.Unlock()
	return ch, func() {
		n.mu.Lock()
		if _, ok := n.subscribers[ch]; ok {
			delete(n.subscribers, ch)
			close(ch)
		}
		n.mu.Unlock()
	}
}
