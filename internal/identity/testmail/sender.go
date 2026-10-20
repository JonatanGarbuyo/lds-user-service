package testmail

import (
	"context"
	"sync"

	"github.com/JonatanGarbuyo/lds-user-service/internal/identity"
)

type Sender struct {
	mu       sync.Mutex
	messages []identity.VerificationEmail
	err      error
}

func New() *Sender {
	return &Sender{}
}

func (s *Sender) SendVerificationCode(_ context.Context, message identity.VerificationEmail) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.err != nil {
		return s.err
	}
	s.messages = append(s.messages, message)
	return nil
}

func (s *Sender) Fail(err error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.err = err
}

func (s *Sender) Messages() []identity.VerificationEmail {
	s.mu.Lock()
	defer s.mu.Unlock()

	return append([]identity.VerificationEmail(nil), s.messages...)
}

func (s *Sender) Last() (identity.VerificationEmail, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if len(s.messages) == 0 {
		return identity.VerificationEmail{}, false
	}
	return s.messages[len(s.messages)-1], true
}

func (s *Sender) Count() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.messages)
}

var _ identity.VerificationEmailSender = (*Sender)(nil)
