package email_test

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/JonatanGarbuyo/lds-user-service/internal/identity"
	identityemail "github.com/JonatanGarbuyo/lds-user-service/internal/identity/email"
)

type outboxMessage struct {
	To        string    `json:"to"`
	Subject   string    `json:"subject"`
	Code      string    `json:"code"`
	ExpiresAt time.Time `json:"expiresAt"`
	SentAt    time.Time `json:"sentAt"`
}

func readOutbox(t *testing.T, filePath string) []outboxMessage {
	t.Helper()

	contents, err := os.ReadFile(filePath)
	if err != nil {
		t.Fatalf("read outbox: %v", err)
	}

	var messages []outboxMessage
	for _, line := range strings.Split(strings.TrimSpace(string(contents)), "\n") {
		if line == "" {
			continue
		}
		var message outboxMessage
		if err := json.Unmarshal([]byte(line), &message); err != nil {
			t.Fatalf("decode outbox line %q: %v", line, err)
		}
		messages = append(messages, message)
	}
	return messages
}

func TestDevSenderWritesVerificationEmailToPrivateOutbox(t *testing.T) {
	directory := filepath.Join(t.TempDir(), "outbox")
	filePath := filepath.Join(directory, "mail.jsonl")

	sender, err := identityemail.NewDevSender(filePath)
	if err != nil {
		t.Fatalf("NewDevSender() error = %v", err)
	}

	expiresAt := time.Date(2026, time.October, 19, 12, 10, 0, 0, time.UTC)
	err = sender.SendVerificationCode(context.Background(), identity.VerificationEmail{
		To:        "person@example.com",
		Code:      "012345",
		ExpiresAt: expiresAt,
	})
	if err != nil {
		t.Fatalf("SendVerificationCode() error = %v", err)
	}

	messages := readOutbox(t, filePath)
	if len(messages) != 1 {
		t.Fatalf("messages = %d, want 1", len(messages))
	}
	if messages[0].To != "person@example.com" || messages[0].Code != "012345" {
		t.Errorf("message = %+v, want recipient and code", messages[0])
	}
	if !messages[0].ExpiresAt.Equal(expiresAt) {
		t.Errorf("expiresAt = %v, want %v", messages[0].ExpiresAt, expiresAt)
	}
	if messages[0].SentAt.IsZero() {
		t.Error("sentAt is zero")
	}

	fileInfo, err := os.Stat(filePath)
	if err != nil {
		t.Fatalf("stat outbox file: %v", err)
	}
	if permission := fileInfo.Mode().Perm(); permission != 0o600 {
		t.Errorf("outbox file permissions = %o, want 600", permission)
	}
	directoryInfo, err := os.Stat(directory)
	if err != nil {
		t.Fatalf("stat outbox directory: %v", err)
	}
	if permission := directoryInfo.Mode().Perm(); permission != 0o700 {
		t.Errorf("outbox directory permissions = %o, want 700", permission)
	}
}

func TestDevSenderAppendsMultipleMessages(t *testing.T) {
	filePath := filepath.Join(t.TempDir(), "mail.jsonl")
	sender, err := identityemail.NewDevSender(filePath)
	if err != nil {
		t.Fatalf("NewDevSender() error = %v", err)
	}

	for _, code := range []string{"111111", "222222"} {
		if err := sender.SendVerificationCode(context.Background(), identity.VerificationEmail{
			To:        "person@example.com",
			Code:      code,
			ExpiresAt: time.Now().Add(10 * time.Minute),
		}); err != nil {
			t.Fatalf("SendVerificationCode() error = %v", err)
		}
	}

	messages := readOutbox(t, filePath)
	if len(messages) != 2 {
		t.Fatalf("messages = %d, want 2", len(messages))
	}
	if messages[0].Code != "111111" || messages[1].Code != "222222" {
		t.Errorf("codes = %q/%q, want 111111/222222", messages[0].Code, messages[1].Code)
	}
}

func TestDevSenderRejectsIncompleteMessages(t *testing.T) {
	sender, err := identityemail.NewDevSender(filepath.Join(t.TempDir(), "mail.jsonl"))
	if err != nil {
		t.Fatalf("NewDevSender() error = %v", err)
	}

	tests := []identity.VerificationEmail{
		{Code: "012345"},
		{To: "person@example.com"},
	}
	for _, message := range tests {
		if err := sender.SendVerificationCode(context.Background(), message); err == nil {
			t.Errorf("SendVerificationCode(%+v) error = nil, want error", message)
		}
	}
}

func TestDevSenderHonorsCancelledContext(t *testing.T) {
	sender, err := identityemail.NewDevSender(filepath.Join(t.TempDir(), "mail.jsonl"))
	if err != nil {
		t.Fatalf("NewDevSender() error = %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	err = sender.SendVerificationCode(ctx, identity.VerificationEmail{
		To:        "person@example.com",
		Code:      "012345",
		ExpiresAt: time.Now().Add(10 * time.Minute),
	})
	if err == nil {
		t.Fatal("SendVerificationCode() error = nil, want context error")
	}
}

func TestDevSenderRequiresOutboxPath(t *testing.T) {
	if _, err := identityemail.NewDevSender(""); err == nil {
		t.Fatal("NewDevSender() error = nil, want error")
	}
}
