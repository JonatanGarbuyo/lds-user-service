package readerstate_test

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"math/big"
	"strings"
	"testing"
	"time"

	"github.com/JonatanGarbuyo/lds-user-service/internal/readerstate"
)

func newKey(t *testing.T) *ecdsa.PrivateKey {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	return key
}

func newSigner(t *testing.T, key *ecdsa.PrivateKey, now time.Time) *readerstate.Signer {
	t.Helper()
	signer, err := readerstate.NewSigner(key, nil, readerstate.Options{
		Issuer:   "https://users.example.com",
		Audience: "https://site.example.com",
		TTL:      30 * time.Minute,
		Now:      func() time.Time { return now },
	})
	if err != nil {
		t.Fatalf("NewSigner() error = %v", err)
	}
	return signer
}

func TestIssueProducesSignedSnapshotVerifiableWithPublishedJWKS(t *testing.T) {
	key := newKey(t)
	now := time.Date(2026, 10, 19, 12, 0, 0, 0, time.UTC)
	signer := newSigner(t, key, now)

	snapshot, err := signer.Issue("user-1", true, "active")
	if err != nil {
		t.Fatalf("Issue() error = %v", err)
	}
	if strings.Count(snapshot.SignedSnapshot, ".") != 2 {
		t.Fatalf("signedSnapshot is not a compact JWT: %q", snapshot.SignedSnapshot)
	}
	if !snapshot.ExpiresAt.Equal(now.Add(30 * time.Minute)) {
		t.Errorf("ExpiresAt = %s, want %s", snapshot.ExpiresAt, now.Add(30*time.Minute))
	}

	claims, err := signer.Verify(snapshot.SignedSnapshot)
	if err != nil {
		t.Fatalf("Verify() error = %v", err)
	}
	if claims.Subject != "user-1" {
		t.Errorf("subject = %q, want user-1", claims.Subject)
	}
	if !claims.EmailVerified {
		t.Error("emailVerified = false, want true")
	}
	if claims.Status != "active" {
		t.Errorf("status = %q, want active", claims.Status)
	}
	if claims.Issuer != "https://users.example.com" {
		t.Errorf("issuer = %q", claims.Issuer)
	}
	if claims.Audience != "https://site.example.com" {
		t.Errorf("audience = %q", claims.Audience)
	}

	jwks := signer.JWKS()
	if len(jwks.Keys) != 1 {
		t.Fatalf("JWKS keys = %d, want 1", len(jwks.Keys))
	}
	jwk := jwks.Keys[0]
	if jwk.KID == "" || jwk.Alg != "ES256" || jwk.Use != "sig" || jwk.Crv != "P-256" {
		t.Fatalf("unexpected JWK metadata: %+v", jwk)
	}

	publicKey := publicKeyFromJWK(t, jwk)
	verifyCompactJWT(t, snapshot.SignedSnapshot, publicKey)
}

func TestVerifyRejectsTamperedExpiredWrongAudienceAndUnknownKeys(t *testing.T) {
	key := newKey(t)
	now := time.Date(2026, 10, 19, 12, 0, 0, 0, time.UTC)
	signer := newSigner(t, key, now)
	snapshot, err := signer.Issue("user-1", false, "active")
	if err != nil {
		t.Fatalf("Issue() error = %v", err)
	}

	parts := strings.Split(snapshot.SignedSnapshot, ".")
	tampered := parts[0] + "." + base64.RawURLEncoding.EncodeToString([]byte(`{"sub":"admin","iss":"https://users.example.com","aud":"https://site.example.com","exp":9999999999}`)) + "." + parts[2]
	if _, err := signer.Verify(tampered); err == nil {
		t.Error("Verify() accepted a tampered payload")
	}

	otherSigner, err := readerstate.NewSigner(newKey(t), nil, readerstate.Options{
		Issuer:   "https://users.example.com",
		Audience: "https://site.example.com",
		TTL:      30 * time.Minute,
		Now:      func() time.Time { return now },
	})
	if err != nil {
		t.Fatalf("NewSigner() error = %v", err)
	}
	if _, err := otherSigner.Verify(snapshot.SignedSnapshot); err == nil {
		t.Error("Verify() accepted a token signed by an unknown key")
	}

	wrongAudience, err := readerstate.NewSigner(key, nil, readerstate.Options{
		Issuer:   "https://users.example.com",
		Audience: "https://other.example.com",
		TTL:      30 * time.Minute,
		Now:      func() time.Time { return now },
	})
	if err != nil {
		t.Fatalf("NewSigner() error = %v", err)
	}
	if _, err := wrongAudience.Verify(snapshot.SignedSnapshot); err == nil {
		t.Error("Verify() accepted the wrong audience")
	}

	expiredAt := now.Add(31 * time.Minute)
	expiredSigner := newSigner(t, key, expiredAt)
	if _, err := expiredSigner.Verify(snapshot.SignedSnapshot); err == nil {
		t.Error("Verify() accepted an expired snapshot")
	}
}

func TestKeyRotationKeepsPreviousVerificationKeysPublic(t *testing.T) {
	previous := newKey(t)
	now := time.Date(2026, 10, 19, 12, 0, 0, 0, time.UTC)
	previousSigner := newSigner(t, previous, now)
	oldSnapshot, err := previousSigner.Issue("user-1", true, "active")
	if err != nil {
		t.Fatalf("Issue() error = %v", err)
	}

	rotated, err := readerstate.NewSigner(newKey(t), []*ecdsa.PublicKey{&previous.PublicKey}, readerstate.Options{
		Issuer:   "https://users.example.com",
		Audience: "https://site.example.com",
		TTL:      30 * time.Minute,
		Now:      func() time.Time { return now },
	})
	if err != nil {
		t.Fatalf("NewSigner() error = %v", err)
	}
	if _, err := rotated.Verify(oldSnapshot.SignedSnapshot); err != nil {
		t.Errorf("Verify() rejected a snapshot signed by a previous key: %v", err)
	}
	if len(rotated.JWKS().Keys) != 2 {
		t.Errorf("JWKS keys = %d, want 2", len(rotated.JWKS().Keys))
	}
}

func TestSnapshotContainsOnlyPresentationClaims(t *testing.T) {
	signer := newSigner(t, newKey(t), time.Now().UTC())
	snapshot, err := signer.Issue("user-1", true, "active")
	if err != nil {
		t.Fatalf("Issue() error = %v", err)
	}

	payload := strings.Split(snapshot.SignedSnapshot, ".")[1]
	decoded, err := base64.RawURLEncoding.DecodeString(payload)
	if err != nil {
		t.Fatalf("decode payload: %v", err)
	}
	var values map[string]any
	if err := json.Unmarshal(decoded, &values); err != nil {
		t.Fatalf("unmarshal payload: %v", err)
	}
	if _, exists := values["email"]; exists {
		t.Error("snapshot contains the email address")
	}
	if _, exists := values["password"]; exists {
		t.Error("snapshot contains a password claim")
	}
}

func publicKeyFromJWK(t *testing.T, jwk readerstate.JWK) *ecdsa.PublicKey {
	t.Helper()
	x, err := base64.RawURLEncoding.DecodeString(jwk.X)
	if err != nil {
		t.Fatalf("decode x: %v", err)
	}
	y, err := base64.RawURLEncoding.DecodeString(jwk.Y)
	if err != nil {
		t.Fatalf("decode y: %v", err)
	}
	point := make([]byte, 0, 65)
	point = append(point, 0x04)
	point = append(point, x...)
	point = append(point, y...)
	publicKey, err := ecdsa.ParseUncompressedPublicKey(elliptic.P256(), point)
	if err != nil {
		t.Fatalf("parse public key: %v", err)
	}
	return publicKey
}

func verifyCompactJWT(t *testing.T, token string, publicKey *ecdsa.PublicKey) {
	t.Helper()
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		t.Fatalf("token parts = %d, want 3", len(parts))
	}
	signature, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil {
		t.Fatalf("decode signature: %v", err)
	}
	if len(signature) != 64 {
		t.Fatalf("signature length = %d, want 64", len(signature))
	}
	digest := sha256.Sum256([]byte(parts[0] + "." + parts[1]))
	r := new(big.Int).SetBytes(signature[:32])
	s := new(big.Int).SetBytes(signature[32:])
	if !ecdsa.Verify(publicKey, digest[:], r, s) {
		t.Error("signature does not verify with the published JWKS key")
	}
}
