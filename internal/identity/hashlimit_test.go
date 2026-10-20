package identity_test

import (
	"sync"
	"sync/atomic"
	"testing"

	"github.com/JonatanGarbuyo/lds-user-service/internal/identity"
)

func TestHashLimiterBoundsConcurrentAcquisitions(t *testing.T) {
	limiter := identity.NewHashLimiter(2)

	var (
		active  atomic.Int32
		maximum atomic.Int32
	)
	var waitGroup sync.WaitGroup
	for range 32 {
		waitGroup.Add(1)
		go func() {
			defer waitGroup.Done()
			if !limiter.TryAcquire() {
				return
			}
			defer limiter.Release()

			current := active.Add(1)
			defer active.Add(-1)
			for {
				observed := maximum.Load()
				if current <= observed || maximum.CompareAndSwap(observed, current) {
					break
				}
			}
		}()
	}
	waitGroup.Wait()

	if got := maximum.Load(); got > 2 {
		t.Errorf("maximum concurrent acquisitions = %d, want at most 2", got)
	}
	if !limiter.TryAcquire() {
		t.Fatal("limiter did not release all slots")
	}
	if !limiter.TryAcquire() {
		t.Fatal("limiter did not release all slots")
	}
	if limiter.TryAcquire() {
		t.Error("limiter allowed more acquisitions than its capacity")
	}
	limiter.Release()
	limiter.Release()
}
