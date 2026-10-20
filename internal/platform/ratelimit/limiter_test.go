package ratelimit_test

import (
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/JonatanGarbuyo/lds-user-service/internal/platform/ratelimit"
)

func TestLimiterAllowsUpToLimitThenDeniesWithRetryAfter(t *testing.T) {
	now := time.Date(2026, time.October, 19, 12, 0, 0, 0, time.UTC)
	limiter := ratelimit.NewWithClock(2, time.Minute, func() time.Time { return now })

	if allowed, _ := limiter.Allow("ip:203.0.113.1"); !allowed {
		t.Fatal("first request was denied")
	}
	if allowed, _ := limiter.Allow("ip:203.0.113.1"); !allowed {
		t.Fatal("second request was denied")
	}

	allowed, retryAfter := limiter.Allow("ip:203.0.113.1")
	if allowed {
		t.Fatal("third request was allowed, want denial")
	}
	if retryAfter != time.Minute {
		t.Errorf("retryAfter = %v, want %v", retryAfter, time.Minute)
	}
}

func TestLimiterResetsAfterWindow(t *testing.T) {
	now := time.Date(2026, time.October, 19, 12, 0, 0, 0, time.UTC)
	limiter := ratelimit.NewWithClock(1, time.Minute, func() time.Time { return now })

	if allowed, _ := limiter.Allow("ip"); !allowed {
		t.Fatal("first request was denied")
	}
	if allowed, _ := limiter.Allow("ip"); allowed {
		t.Fatal("second request was allowed before the window elapsed")
	}

	now = now.Add(time.Minute)
	if allowed, _ := limiter.Allow("ip"); !allowed {
		t.Fatal("request after the window was denied")
	}
}

func TestLimiterTracksKeysIndependently(t *testing.T) {
	now := time.Date(2026, time.October, 19, 12, 0, 0, 0, time.UTC)
	limiter := ratelimit.NewWithClock(1, time.Minute, func() time.Time { return now })

	if allowed, _ := limiter.Allow("ip:one"); !allowed {
		t.Fatal("first key was denied")
	}
	if allowed, _ := limiter.Allow("ip:two"); !allowed {
		t.Fatal("second key was denied")
	}
}

func TestLimiterAllowsAllWhenDisabled(t *testing.T) {
	limiter := ratelimit.New(0, 0)

	for range 100 {
		if allowed, _ := limiter.Allow("ip"); !allowed {
			t.Fatal("disabled limiter denied a request")
		}
	}
}

func TestLimiterIsSafeUnderConcurrency(t *testing.T) {
	now := time.Date(2026, time.October, 19, 12, 0, 0, 0, time.UTC)
	limiter := ratelimit.NewWithClock(10, time.Minute, func() time.Time { return now })

	var allowed atomic.Int32
	var wg sync.WaitGroup
	wg.Add(50)

	for range 50 {
		go func() {
			defer wg.Done()
			if ok, _ := limiter.Allow("ip"); ok {
				allowed.Add(1)
			}
		}()
	}

	wg.Wait()
	if allowed.Load() != 10 {
		t.Errorf("allowed requests = %d, want 10", allowed.Load())
	}
}
