package email

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/JonatanGarbuyo/lds-user-service/internal/identity"
)

const devSubject = "Verify your email address"

type DevSender struct {
	mu       sync.Mutex
	filePath string
	now      func() time.Time
}

type devMessage struct {
	To        string    `json:"to"`
	Subject   string    `json:"subject"`
	Code      string    `json:"code"`
	ExpiresAt time.Time `json:"expiresAt"`
	SentAt    time.Time `json:"sentAt"`
}

func NewDevSender(filePath string) (*DevSender, error) {
	if filePath == "" {
		return nil, errors.New("mail outbox file path is required")
	}
	if err := os.MkdirAll(filepath.Dir(filePath), 0o700); err != nil {
		return nil, fmt.Errorf("create mail outbox directory: %w", err)
	}
	return &DevSender{filePath: filePath, now: time.Now}, nil
}

func (s *DevSender) SendVerificationCode(ctx context.Context, message identity.VerificationEmail) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if message.To == "" || message.Code == "" {
		return errors.New("verification email requires a recipient and a code")
	}

	payload, err := json.Marshal(devMessage{
		To:        message.To,
		Subject:   devSubject,
		Code:      message.Code,
		ExpiresAt: message.ExpiresAt.UTC(),
		SentAt:    s.now().UTC(),
	})
	if err != nil {
		return fmt.Errorf("encode development email: %w", err)
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	file, err := os.OpenFile(s.filePath, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o600)
	if err != nil {
		return fmt.Errorf("open development mail outbox: %w", err)
	}
	if err := file.Chmod(0o600); err != nil {
		_ = file.Close()
		return fmt.Errorf("secure development mail outbox: %w", err)
	}

	if _, err := file.Write(append(payload, '\n')); err != nil {
		_ = file.Close()
		return fmt.Errorf("write development mail outbox: %w", err)
	}
	if err := file.Close(); err != nil {
		return fmt.Errorf("close development mail outbox: %w", err)
	}
	return nil
}

var _ identity.VerificationEmailSender = (*DevSender)(nil)
