//go:build integration

package postgres_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/JonatanGarbuyo/lds-user-service/internal/identity"
	identitypostgres "github.com/JonatanGarbuyo/lds-user-service/internal/identity/postgres"
	"github.com/JonatanGarbuyo/lds-user-service/internal/identity/testpg"
)

const verificationTestCooldown = 60 * time.Second

func createVerificationUser(t *testing.T, repository *identitypostgres.Repository, email string) identity.User {
	t.Helper()

	user, err := repository.Create(context.Background(), identity.NewUser{
		Email:        email,
		PasswordHash: "$argon2id$test-hash",
	})
	if err != nil {
		t.Fatalf("create user: %v", err)
	}
	return user
}

func TestVerificationRepositoryCreatesAndFindsActiveChallenge(t *testing.T) {
	db := testpg.OpenDatabase(t)
	users := identitypostgres.NewRepository(db.Pool)
	repository := identitypostgres.NewVerificationRepository(db.Pool)
	user := createVerificationUser(t, users, uniqueEmail(t))

	now := time.Now().UTC().Truncate(time.Microsecond)
	expiresAt := now.Add(10 * time.Minute)
	challenge, err := repository.CreateChallenge(context.Background(), user.ID, "hash:012345", now, expiresAt, verificationTestCooldown)
	if err != nil {
		t.Fatalf("CreateChallenge() error = %v", err)
	}
	if challenge.ID == "" {
		t.Fatal("challenge.ID is empty")
	}
	if challenge.UserID != user.ID {
		t.Errorf("challenge.UserID = %q, want %q", challenge.UserID, user.ID)
	}
	if !challenge.CreatedAt.Equal(now) || !challenge.ExpiresAt.Equal(expiresAt) {
		t.Errorf("challenge times = %v/%v, want %v/%v", challenge.CreatedAt, challenge.ExpiresAt, now, expiresAt)
	}

	found, err := repository.FindActiveChallengeByEmail(context.Background(), user.Email, now.Add(time.Second), 5)
	if err != nil {
		t.Fatalf("FindActiveChallengeByEmail() error = %v", err)
	}
	if found.ID != challenge.ID {
		t.Errorf("found.ID = %q, want %q", found.ID, challenge.ID)
	}
	if found.Email != user.Email {
		t.Errorf("found.Email = %q, want %q", found.Email, user.Email)
	}
	if found.CodeHash != "hash:012345" {
		t.Errorf("found.CodeHash = %q, want hash:012345", found.CodeHash)
	}
	if found.Attempts != 0 {
		t.Errorf("found.Attempts = %d, want 0", found.Attempts)
	}
}

func TestVerificationRepositoryEnforcesResendCooldownAndInvalidatesPrevious(t *testing.T) {
	db := testpg.OpenDatabase(t)
	users := identitypostgres.NewRepository(db.Pool)
	repository := identitypostgres.NewVerificationRepository(db.Pool)
	user := createVerificationUser(t, users, uniqueEmail(t))

	now := time.Now().UTC().Truncate(time.Microsecond)
	first, err := repository.CreateChallenge(context.Background(), user.ID, "hash:111111", now, now.Add(10*time.Minute), verificationTestCooldown)
	if err != nil {
		t.Fatalf("first CreateChallenge() error = %v", err)
	}

	_, err = repository.CreateChallenge(context.Background(), user.ID, "hash:222222", now.Add(59*time.Second), now.Add(10*time.Minute), verificationTestCooldown)
	if !errors.Is(err, identity.ErrResendTooSoon) {
		t.Fatalf("CreateChallenge() during cooldown error = %v, want ErrResendTooSoon", err)
	}

	second, err := repository.CreateChallenge(context.Background(), user.ID, "hash:222222", now.Add(60*time.Second), now.Add(10*time.Minute), verificationTestCooldown)
	if err != nil {
		t.Fatalf("second CreateChallenge() error = %v", err)
	}
	if second.ID == first.ID {
		t.Error("second challenge reused the first challenge ID")
	}

	found, err := repository.FindActiveChallengeByEmail(context.Background(), user.Email, now.Add(61*time.Second), 5)
	if err != nil {
		t.Fatalf("FindActiveChallengeByEmail() error = %v", err)
	}
	if found.ID != second.ID {
		t.Errorf("active challenge = %q, want the new challenge %q", found.ID, second.ID)
	}

	var invalidated bool
	if err := db.Pool.QueryRow(
		context.Background(),
		`SELECT invalidated_at IS NOT NULL FROM email_verification_challenges WHERE id = $1`,
		first.ID,
	).Scan(&invalidated); err != nil {
		t.Fatalf("query previous challenge: %v", err)
	}
	if !invalidated {
		t.Error("previous challenge was not invalidated")
	}
}

func TestVerificationRepositoryConcurrentChallengeCreationLeavesOneActive(t *testing.T) {
	db := testpg.OpenDatabase(t)
	users := identitypostgres.NewRepository(db.Pool)
	repository := identitypostgres.NewVerificationRepository(db.Pool)
	user := createVerificationUser(t, users, uniqueEmail(t))

	const workers = 8
	now := time.Now().UTC().Truncate(time.Microsecond)
	results := make(chan error, workers)
	start := make(chan struct{})

	for range workers {
		go func() {
			<-start
			_, err := repository.CreateChallenge(context.Background(), user.ID, "hash:012345", now, now.Add(10*time.Minute), verificationTestCooldown)
			results <- err
		}()
	}
	close(start)

	var created, throttled int
	for range workers {
		err := <-results
		switch {
		case err == nil:
			created++
		case errors.Is(err, identity.ErrResendTooSoon):
			throttled++
		default:
			t.Errorf("CreateChallenge() unexpected error = %v", err)
		}
	}

	if created != 1 || throttled != workers-1 {
		t.Errorf("created = %d, throttled = %d, want 1 and %d", created, throttled, workers-1)
	}

	var total, active int
	if err := db.Pool.QueryRow(
		context.Background(),
		`SELECT count(*), count(*) FILTER (WHERE consumed_at IS NULL AND invalidated_at IS NULL)
		 FROM email_verification_challenges WHERE user_id = $1`,
		user.ID,
	).Scan(&total, &active); err != nil {
		t.Fatalf("count challenges: %v", err)
	}
	if total != 1 || active != 1 {
		t.Errorf("total/active challenges = %d/%d, want 1/1", total, active)
	}
}

func TestVerificationRepositoryLocksChallengeAfterMaximumAttempts(t *testing.T) {
	db := testpg.OpenDatabase(t)
	users := identitypostgres.NewRepository(db.Pool)
	repository := identitypostgres.NewVerificationRepository(db.Pool)
	user := createVerificationUser(t, users, uniqueEmail(t))

	now := time.Now().UTC().Truncate(time.Microsecond)
	challenge, err := repository.CreateChallenge(context.Background(), user.ID, "hash:012345", now, now.Add(10*time.Minute), verificationTestCooldown)
	if err != nil {
		t.Fatalf("CreateChallenge() error = %v", err)
	}

	for attempt := 1; attempt <= 5; attempt++ {
		if err := repository.RecordFailedAttempt(context.Background(), challenge.ID, now.Add(time.Second), 5); err != nil {
			t.Fatalf("attempt %d RecordFailedAttempt() error = %v", attempt, err)
		}
	}

	if err := repository.RecordFailedAttempt(context.Background(), challenge.ID, now.Add(time.Second), 5); !errors.Is(err, identity.ErrChallengeInactive) {
		t.Fatalf("sixth RecordFailedAttempt() error = %v, want ErrChallengeInactive", err)
	}

	var attempts int
	var invalidated bool
	if err := db.Pool.QueryRow(
		context.Background(),
		`SELECT attempts, invalidated_at IS NOT NULL FROM email_verification_challenges WHERE id = $1`,
		challenge.ID,
	).Scan(&attempts, &invalidated); err != nil {
		t.Fatalf("query challenge: %v", err)
	}
	if attempts != 5 {
		t.Errorf("attempts = %d, want 5", attempts)
	}
	if !invalidated {
		t.Error("challenge was not invalidated after maximum attempts")
	}

	if _, err := repository.ConsumeAndVerify(context.Background(), challenge.ID, now.Add(time.Second), 5); !errors.Is(err, identity.ErrChallengeInactive) {
		t.Fatalf("ConsumeAndVerify() after maximum attempts error = %v, want ErrChallengeInactive", err)
	}
}

func TestVerificationRepositoryConsumeAndVerifyIsSingleUse(t *testing.T) {
	db := testpg.OpenDatabase(t)
	users := identitypostgres.NewRepository(db.Pool)
	repository := identitypostgres.NewVerificationRepository(db.Pool)
	user := createVerificationUser(t, users, uniqueEmail(t))

	now := time.Now().UTC().Truncate(time.Microsecond)
	challenge, err := repository.CreateChallenge(context.Background(), user.ID, "hash:012345", now, now.Add(10*time.Minute), verificationTestCooldown)
	if err != nil {
		t.Fatalf("CreateChallenge() error = %v", err)
	}

	verifiedAt := now.Add(time.Minute)
	verified, err := repository.ConsumeAndVerify(context.Background(), challenge.ID, verifiedAt, 5)
	if err != nil {
		t.Fatalf("ConsumeAndVerify() error = %v", err)
	}
	if !verified.EmailVerified {
		t.Error("verified.EmailVerified = false, want true")
	}
	if verified.Status != identity.StatusActive {
		t.Errorf("verified.Status = %q, want active", verified.Status)
	}
	if !verified.UpdatedAt.Equal(verifiedAt) {
		t.Errorf("verified.UpdatedAt = %v, want %v", verified.UpdatedAt, verifiedAt)
	}

	if _, err := repository.ConsumeAndVerify(context.Background(), challenge.ID, verifiedAt, 5); !errors.Is(err, identity.ErrChallengeInactive) {
		t.Fatalf("second ConsumeAndVerify() error = %v, want ErrChallengeInactive", err)
	}

	var consumed bool
	if err := db.Pool.QueryRow(
		context.Background(),
		`SELECT consumed_at IS NOT NULL FROM email_verification_challenges WHERE id = $1`,
		challenge.ID,
	).Scan(&consumed); err != nil {
		t.Fatalf("query challenge: %v", err)
	}
	if !consumed {
		t.Error("challenge was not marked as consumed")
	}
}

func TestVerificationRepositoryConcurrentConfirmationSucceedsOnce(t *testing.T) {
	db := testpg.OpenDatabase(t)
	users := identitypostgres.NewRepository(db.Pool)
	repository := identitypostgres.NewVerificationRepository(db.Pool)
	user := createVerificationUser(t, users, uniqueEmail(t))

	now := time.Now().UTC().Truncate(time.Microsecond)
	challenge, err := repository.CreateChallenge(context.Background(), user.ID, "hash:012345", now, now.Add(10*time.Minute), verificationTestCooldown)
	if err != nil {
		t.Fatalf("CreateChallenge() error = %v", err)
	}

	const workers = 8
	results := make(chan error, workers)
	start := make(chan struct{})

	for range workers {
		go func() {
			<-start
			_, err := repository.ConsumeAndVerify(context.Background(), challenge.ID, now.Add(time.Second), 5)
			results <- err
		}()
	}
	close(start)

	var confirmed, inactive int
	for range workers {
		err := <-results
		switch {
		case err == nil:
			confirmed++
		case errors.Is(err, identity.ErrChallengeInactive):
			inactive++
		default:
			t.Errorf("ConsumeAndVerify() unexpected error = %v", err)
		}
	}
	if confirmed != 1 || inactive != workers-1 {
		t.Errorf("confirmed = %d, inactive = %d, want 1 and %d", confirmed, inactive, workers-1)
	}

	stored, err := users.FindByEmail(context.Background(), user.Email)
	if err != nil {
		t.Fatalf("FindByEmail() error = %v", err)
	}
	if !stored.EmailVerified {
		t.Error("user email was not verified")
	}
}

func TestVerificationRepositoryRejectsExpiredChallenge(t *testing.T) {
	db := testpg.OpenDatabase(t)
	users := identitypostgres.NewRepository(db.Pool)
	repository := identitypostgres.NewVerificationRepository(db.Pool)
	user := createVerificationUser(t, users, uniqueEmail(t))

	now := time.Now().UTC().Truncate(time.Microsecond)
	challenge, err := repository.CreateChallenge(context.Background(), user.ID, "hash:012345", now, now.Add(time.Second), verificationTestCooldown)
	if err != nil {
		t.Fatalf("CreateChallenge() error = %v", err)
	}

	if _, err := repository.FindActiveChallengeByEmail(context.Background(), user.Email, now.Add(2*time.Second), 5); !errors.Is(err, identity.ErrChallengeNotFound) {
		t.Fatalf("FindActiveChallengeByEmail() error = %v, want ErrChallengeNotFound", err)
	}
	if _, err := repository.ConsumeAndVerify(context.Background(), challenge.ID, now.Add(2*time.Second), 5); !errors.Is(err, identity.ErrChallengeInactive) {
		t.Fatalf("ConsumeAndVerify() error = %v, want ErrChallengeInactive", err)
	}

	stored, err := users.FindByEmail(context.Background(), user.Email)
	if err != nil {
		t.Fatalf("FindByEmail() error = %v", err)
	}
	if stored.EmailVerified {
		t.Error("expired challenge verified the email")
	}
}

func TestVerificationRepositoryNewChallengeInvalidatesPreviousUnderConcurrency(t *testing.T) {
	db := testpg.OpenDatabase(t)
	users := identitypostgres.NewRepository(db.Pool)
	repository := identitypostgres.NewVerificationRepository(db.Pool)
	user := createVerificationUser(t, users, uniqueEmail(t))

	now := time.Now().UTC().Truncate(time.Microsecond)
	previous, err := repository.CreateChallenge(context.Background(), user.ID, "hash:111111", now, now.Add(10*time.Minute), verificationTestCooldown)
	if err != nil {
		t.Fatalf("first CreateChallenge() error = %v", err)
	}
	if _, err := repository.CreateChallenge(context.Background(), user.ID, "hash:222222", now.Add(time.Minute), now.Add(10*time.Minute), verificationTestCooldown); err != nil {
		t.Fatalf("second CreateChallenge() error = %v", err)
	}

	const workers = 8
	results := make(chan error, workers)
	start := make(chan struct{})
	for range workers {
		go func() {
			<-start
			_, err := repository.ConsumeAndVerify(context.Background(), previous.ID, now.Add(time.Minute), 5)
			results <- err
		}()
	}
	close(start)

	for range workers {
		err := <-results
		if !errors.Is(err, identity.ErrChallengeInactive) {
			t.Errorf("ConsumeAndVerify(previous) error = %v, want ErrChallengeInactive", err)
		}
	}
}

func TestVerificationRepositoryDeletesUndeliveredChallenge(t *testing.T) {
	db := testpg.OpenDatabase(t)
	users := identitypostgres.NewRepository(db.Pool)
	repository := identitypostgres.NewVerificationRepository(db.Pool)
	user := createVerificationUser(t, users, uniqueEmail(t))

	now := time.Now().UTC().Truncate(time.Microsecond)
	challenge, err := repository.CreateChallenge(context.Background(), user.ID, "hash:012345", now, now.Add(10*time.Minute), verificationTestCooldown)
	if err != nil {
		t.Fatalf("CreateChallenge() error = %v", err)
	}
	if err := repository.DeleteChallenge(context.Background(), challenge.ID); err != nil {
		t.Fatalf("DeleteChallenge() error = %v", err)
	}
	if _, err := repository.FindActiveChallengeByEmail(context.Background(), user.Email, now.Add(time.Second), 5); !errors.Is(err, identity.ErrChallengeNotFound) {
		t.Fatalf("FindActiveChallengeByEmail() error = %v, want ErrChallengeNotFound", err)
	}
}

func TestVerificationRepositoryPersistsAcrossPoolReopen(t *testing.T) {
	db := testpg.OpenDatabase(t)
	users := identitypostgres.NewRepository(db.Pool)
	repository := identitypostgres.NewVerificationRepository(db.Pool)
	user := createVerificationUser(t, users, uniqueEmail(t))

	now := time.Now().UTC().Truncate(time.Microsecond)
	challenge, err := repository.CreateChallenge(context.Background(), user.ID, "hash:012345", now, now.Add(10*time.Minute), verificationTestCooldown)
	if err != nil {
		t.Fatalf("CreateChallenge() error = %v", err)
	}

	db.Close()

	reopened := testpg.OpenDatabase(t)
	found, err := identitypostgres.NewVerificationRepository(reopened.Pool).FindActiveChallengeByEmail(context.Background(), user.Email, now.Add(time.Second), 5)
	if err != nil {
		t.Fatalf("FindActiveChallengeByEmail() after reopen error = %v", err)
	}
	if found.ID != challenge.ID {
		t.Errorf("found.ID = %q, want %q", found.ID, challenge.ID)
	}
}

func TestVerificationRepositoryRejectsUnknownUser(t *testing.T) {
	db := testpg.OpenDatabase(t)
	repository := identitypostgres.NewVerificationRepository(db.Pool)

	now := time.Now().UTC().Truncate(time.Microsecond)
	_, err := repository.CreateChallenge(context.Background(), "00000000-0000-0000-0000-000000000000", "hash:012345", now, now.Add(10*time.Minute), verificationTestCooldown)
	if !errors.Is(err, identity.ErrUserNotFound) {
		t.Fatalf("CreateChallenge() error = %v, want ErrUserNotFound", err)
	}
}

func TestVerificationRepositoryRejectsChallengeForVerifiedUser(t *testing.T) {
	db := testpg.OpenDatabase(t)
	users := identitypostgres.NewRepository(db.Pool)
	repository := identitypostgres.NewVerificationRepository(db.Pool)
	user := createVerificationUser(t, users, uniqueEmail(t))

	now := time.Now().UTC().Truncate(time.Microsecond)
	challenge, err := repository.CreateChallenge(context.Background(), user.ID, "hash:012345", now, now.Add(10*time.Minute), verificationTestCooldown)
	if err != nil {
		t.Fatalf("CreateChallenge() error = %v", err)
	}
	if _, err := repository.ConsumeAndVerify(context.Background(), challenge.ID, now.Add(time.Second), 5); err != nil {
		t.Fatalf("ConsumeAndVerify() error = %v", err)
	}

	_, err = repository.CreateChallenge(context.Background(), user.ID, "hash:222222", now.Add(verificationTestCooldown), now.Add(11*time.Minute), verificationTestCooldown)
	if !errors.Is(err, identity.ErrEmailAlreadyVerified) {
		t.Fatalf("CreateChallenge() for verified user error = %v, want ErrEmailAlreadyVerified", err)
	}
}
