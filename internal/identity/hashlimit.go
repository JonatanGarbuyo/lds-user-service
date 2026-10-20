package identity

type HashLimiter interface {
	TryAcquire() bool
	Release()
}

type channelHashLimiter struct {
	slots chan struct{}
}

func NewHashLimiter(capacity int) HashLimiter {
	if capacity < 1 {
		capacity = 1
	}
	return &channelHashLimiter{slots: make(chan struct{}, capacity)}
}

func (l *channelHashLimiter) TryAcquire() bool {
	select {
	case l.slots <- struct{}{}:
		return true
	default:
		return false
	}
}

func (l *channelHashLimiter) Release() {
	<-l.slots
}
