package ratelimit

import (
	"sync"
	"time"
)

type bucket struct {
	count   int
	resetAt time.Time
}

type Limiter struct {
	mu          sync.Mutex
	limit       int
	window      time.Duration
	now         func() time.Time
	buckets     map[string]bucket
	lastCleanup time.Time
}

func New(limit int, window time.Duration) *Limiter {
	return NewWithClock(limit, window, time.Now)
}

func NewWithClock(limit int, window time.Duration, now func() time.Time) *Limiter {
	if now == nil {
		now = time.Now
	}
	return &Limiter{
		limit:   limit,
		window:  window,
		now:     now,
		buckets: make(map[string]bucket),
	}
}

func (l *Limiter) Allow(key string) (bool, time.Duration) {
	if l.limit <= 0 || l.window <= 0 {
		return true, 0
	}

	l.mu.Lock()
	defer l.mu.Unlock()

	now := l.now()
	l.cleanup(now)

	current, exists := l.buckets[key]
	if !exists || !now.Before(current.resetAt) {
		current = bucket{resetAt: now.Add(l.window)}
	}
	if current.count >= l.limit {
		return false, current.resetAt.Sub(now)
	}

	current.count++
	l.buckets[key] = current
	return true, 0
}

func (l *Limiter) cleanup(now time.Time) {
	if !l.lastCleanup.IsZero() && now.Sub(l.lastCleanup) < l.window {
		return
	}
	for key, current := range l.buckets {
		if !now.Before(current.resetAt) {
			delete(l.buckets, key)
		}
	}
	l.lastCleanup = now
}
