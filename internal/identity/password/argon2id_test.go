package password_test

import (
	"encoding/base64"
	"strings"
	"testing"

	"github.com/JonatanGarbuyo/lds-user-service/internal/identity/password"
)

func TestHashProducesArgon2idPHCString(t *testing.T) {
	hasher := password.New()
	const plaintext = "correct horse battery"

	encoded, err := hasher.Hash(plaintext)
	if err != nil {
		t.Fatalf("Hash() error = %v", err)
	}
	if encoded == plaintext {
		t.Fatal("Hash() returned the plaintext password")
	}

	parts := strings.Split(encoded, "$")
	if len(parts) != 6 {
		t.Fatalf("encoded hash = %q, want 6 PHC fields", encoded)
	}
	if parts[0] != "" || parts[1] != "argon2id" {
		t.Errorf("algorithm fields = %q/%q, want empty/argon2id", parts[0], parts[1])
	}
	if parts[2] != "v=19" {
		t.Errorf("version field = %q, want v=19", parts[2])
	}
	if parts[3] != "m=65536,t=3,p=2" {
		t.Errorf("parameters field = %q, want m=65536,t=3,p=2", parts[3])
	}

	salt, err := base64.RawStdEncoding.DecodeString(parts[4])
	if err != nil {
		t.Fatalf("salt is not base64: %v", err)
	}
	if len(salt) != 16 {
		t.Errorf("salt length = %d, want 16", len(salt))
	}

	hash, err := base64.RawStdEncoding.DecodeString(parts[5])
	if err != nil {
		t.Fatalf("hash is not base64: %v", err)
	}
	if len(hash) != 32 {
		t.Errorf("hash length = %d, want 32", len(hash))
	}
}

func TestHashUsesRandomSalt(t *testing.T) {
	hasher := password.New()

	first, err := hasher.Hash("correct horse battery")
	if err != nil {
		t.Fatalf("first Hash() error = %v", err)
	}
	second, err := hasher.Hash("correct horse battery")
	if err != nil {
		t.Fatalf("second Hash() error = %v", err)
	}
	if first == second {
		t.Error("two hashes of the same password are equal, want random salts")
	}
}

func TestVerifyAcceptsMatchingPassword(t *testing.T) {
	hasher := password.New()
	const plaintext = "correct horse battery"

	encoded, err := hasher.Hash(plaintext)
	if err != nil {
		t.Fatalf("Hash() error = %v", err)
	}

	ok, err := hasher.Verify(plaintext, encoded)
	if err != nil {
		t.Fatalf("Verify() error = %v", err)
	}
	if !ok {
		t.Error("Verify() = false, want true")
	}
}

func TestVerifyRejectsWrongPassword(t *testing.T) {
	hasher := password.New()

	encoded, err := hasher.Hash("correct horse battery")
	if err != nil {
		t.Fatalf("Hash() error = %v", err)
	}

	ok, err := hasher.Verify("incorrect horse battery", encoded)
	if err != nil {
		t.Fatalf("Verify() error = %v", err)
	}
	if ok {
		t.Error("Verify() = true, want false")
	}
}

func TestVerifyRejectsMalformedEncodings(t *testing.T) {
	tests := []struct {
		name    string
		encoded string
	}{
		{name: "empty", encoded: ""},
		{name: "not PHC", encoded: "plaintext"},
		{name: "missing fields", encoded: "$argon2id$v=19$m=65536,t=3,p=2$c2FsdA"},
		{name: "unknown algorithm", encoded: "$argon2i$v=19$m=65536,t=3,p=2$c2FsdA$aGFzaA"},
		{name: "unknown version", encoded: "$argon2id$v=18$m=65536,t=3,p=2$c2FsdA$aGFzaA"},
		{name: "invalid parameters", encoded: "$argon2id$v=19$m=bad,t=3,p=2$c2FsdA$aGFzaA"},
		{name: "memory out of range", encoded: "$argon2id$v=19$m=10000000,t=3,p=2$c2FsdA$aGFzaA"},
		{name: "parallelism out of range", encoded: "$argon2id$v=19$m=65536,t=3,p=999$c2FsdA$aGFzaA"},
		{name: "invalid salt", encoded: "$argon2id$v=19$m=65536,t=3,p=2$***$aGFzaA"},
		{name: "invalid hash", encoded: "$argon2id$v=19$m=65536,t=3,p=2$c2FsdA$***"},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			_, err := password.New().Verify("correct horse battery", test.encoded)
			if err == nil {
				t.Fatal("Verify() error = nil, want error")
			}
		})
	}
}
