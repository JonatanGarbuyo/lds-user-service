package identity

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"
)

const (
	defaultVerificationCodeTTL        = 10 * time.Minute
	defaultVerificationMaxAttempts    = 5
	defaultVerificationResendCoolDown = 60 * time.Second
)

type EmailVerificationPolicy struct {
	CodeTTL        time.Duration
	MaxAttempts    int
	ResendCooldown time.Duration
}

func DefaultEmailVerificationPolicy() EmailVerificationPolicy {
	return EmailVerificationPolicy{
		CodeTTL:        defaultVerificationCodeTTL,
		MaxAttempts:    defaultVerificationMaxAttempts,
		ResendCooldown: defaultVerificationResendCoolDown,
	}
}

type EmailVerificationIssuer interface {
	IssueForUser(ctx context.Context, user User) error
}

type EmailVerificationDependencies struct {
	Users          UserRepository
	Challenges     EmailVerificationRepository
	Hasher         SecretHasher
	Sender         VerificationEmailSender
	RequestLimiter AbuseLimiter
	ConfirmLimiter AbuseLimiter
	Policy         EmailVerificationPolicy
	Now            func() time.Time
	CodeGenerator  VerificationCodeGenerator
}

type EmailVerificationService struct {
	users          UserRepository
	challenges     EmailVerificationRepository
	hasher         SecretHasher
	sender         VerificationEmailSender
	requestLimiter AbuseLimiter
	confirmLimiter AbuseLimiter
	policy         EmailVerificationPolicy
	now            func() time.Time
	codeGenerator  VerificationCodeGenerator
}

func NewEmailVerificationService(dependencies EmailVerificationDependencies) *EmailVerificationService {
	if dependencies.Policy == (EmailVerificationPolicy{}) {
		dependencies.Policy = DefaultEmailVerificationPolicy()
	}
	if dependencies.Now == nil {
		dependencies.Now = time.Now
	}
	if dependencies.CodeGenerator == nil {
		dependencies.CodeGenerator = NewVerificationCodeGenerator()
	}

	return &EmailVerificationService{
		users:          dependencies.Users,
		challenges:     dependencies.Challenges,
		hasher:         dependencies.Hasher,
		sender:         dependencies.Sender,
		requestLimiter: dependencies.RequestLimiter,
		confirmLimiter: dependencies.ConfirmLimiter,
		policy:         dependencies.Policy,
		now:            dependencies.Now,
		codeGenerator:  dependencies.CodeGenerator,
	}
}

type RequestEmailVerificationInput struct {
	Email    string
	ClientIP string
}

type ConfirmEmailVerificationInput struct {
	Email    string
	Code     string
	ClientIP string
}

func (s *EmailVerificationService) IssueForUser(ctx context.Context, user User) error {
	if user.EmailVerified {
		return nil
	}

	code, err := s.codeGenerator.Generate()
	if err != nil {
		return err
	}

	codeHash, err := s.hasher.Hash(code)
	if err != nil {
		return fmt.Errorf("hash verification code: %w", err)
	}

	now := s.now()
	expiresAt := now.Add(s.policy.CodeTTL)
	challenge, err := s.challenges.CreateChallenge(ctx, user.ID, codeHash, now, expiresAt, s.policy.ResendCooldown)
	if err != nil {
		return fmt.Errorf("create verification challenge: %w", err)
	}

	message := VerificationEmail{
		To:        user.Email,
		Code:      code,
		ExpiresAt: expiresAt,
	}
	if err := s.sender.SendVerificationCode(ctx, message); err != nil {
		deliveryErr := &VerificationDeliveryError{Err: err}
		if discardErr := s.challenges.DeleteChallenge(ctx, challenge.ID); discardErr != nil {
			return errors.Join(deliveryErr, fmt.Errorf("discard undelivered verification challenge: %w", discardErr))
		}
		return deliveryErr
	}
	return nil
}

func (s *EmailVerificationService) Request(ctx context.Context, input RequestEmailVerificationInput) error {
	email := NormalizeEmail(input.Email)
	if err := validateEmailOnly(email); err != nil {
		return err
	}
	if err := allow(s.requestLimiter, "email-verification-request:"+input.ClientIP); err != nil {
		return err
	}

	user, err := s.users.FindByEmail(ctx, email)
	if errors.Is(err, ErrUserNotFound) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("find user: %w", err)
	}
	if user.EmailVerified {
		return nil
	}

	err = s.IssueForUser(ctx, user)
	if errors.Is(err, ErrResendTooSoon) || errors.Is(err, ErrEmailAlreadyVerified) {
		return nil
	}
	return err
}

func (s *EmailVerificationService) Confirm(ctx context.Context, input ConfirmEmailVerificationInput) (User, error) {
	email := NormalizeEmail(input.Email)
	if err := validateEmailOnly(email); err != nil {
		return User{}, err
	}

	code := strings.TrimSpace(input.Code)
	if err := validateVerificationCode(code); err != nil {
		return User{}, err
	}
	if err := allow(s.confirmLimiter, "email-verification-confirm:"+input.ClientIP); err != nil {
		return User{}, err
	}

	now := s.now()
	challenge, err := s.challenges.FindActiveChallengeByEmail(ctx, email, now, s.policy.MaxAttempts)
	if errors.Is(err, ErrChallengeNotFound) {
		return User{}, ErrInvalidVerificationCode
	}
	if err != nil {
		return User{}, fmt.Errorf("find verification challenge: %w", err)
	}

	matches, err := s.hasher.Verify(code, challenge.CodeHash)
	if err != nil {
		return User{}, fmt.Errorf("verify verification code: %w", err)
	}
	if !matches {
		err := s.challenges.RecordFailedAttempt(ctx, challenge.ID, now, s.policy.MaxAttempts)
		if errors.Is(err, ErrChallengeNotFound) || errors.Is(err, ErrChallengeInactive) {
			return User{}, ErrInvalidVerificationCode
		}
		if err != nil {
			return User{}, fmt.Errorf("record failed verification attempt: %w", err)
		}
		return User{}, ErrInvalidVerificationCode
	}

	user, err := s.challenges.ConsumeAndVerify(ctx, challenge.ID, now, s.policy.MaxAttempts)
	if errors.Is(err, ErrChallengeNotFound) || errors.Is(err, ErrChallengeInactive) {
		return User{}, ErrInvalidVerificationCode
	}
	if err != nil {
		return User{}, fmt.Errorf("consume verification challenge: %w", err)
	}
	return user, nil
}

func allow(limiter AbuseLimiter, key string) error {
	if limiter == nil {
		return nil
	}
	allowed, retryAfter := limiter.Allow(key)
	if allowed {
		return nil
	}
	if retryAfter < time.Second {
		retryAfter = time.Second
	}
	return &RateLimitError{RetryAfter: retryAfter}
}
