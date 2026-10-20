package readerstate_test

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"testing"
	"time"

	"github.com/JonatanGarbuyo/lds-user-service/internal/readerstate"
)

func privateKeyPEM(t *testing.T, key *ecdsa.PrivateKey) []byte {
	t.Helper()
	der, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatalf("marshal private key: %v", err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der})
}

func publicKeyPEM(t *testing.T, key *ecdsa.PublicKey) []byte {
	t.Helper()
	der, err := x509.MarshalPKIXPublicKey(key)
	if err != nil {
		t.Fatalf("marshal public key: %v", err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der})
}

func TestLoadSignerParsesConfiguredKeys(t *testing.T) {
	active, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate active key: %v", err)
	}
	previous, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate previous key: %v", err)
	}

	signer, generated, err := readerstate.LoadSigner(readerstate.SignerConfig{
		Issuer:                "lds-user-service",
		Audience:              "lds-web",
		TTL:                   time.Minute,
		PrivateKeyPEM:         privateKeyPEM(t, active),
		PreviousPublicKeysPEM: publicKeyPEM(t, &previous.PublicKey),
	})
	if err != nil {
		t.Fatalf("LoadSigner() error = %v", err)
	}
	if generated {
		t.Error("generated = true, want false for configured keys")
	}
	if len(signer.JWKS().Keys) != 2 {
		t.Errorf("JWKS keys = %d, want 2", len(signer.JWKS().Keys))
	}
}

func TestLoadSignerGeneratesEphemeralDevelopmentKey(t *testing.T) {
	signer, generated, err := readerstate.LoadSigner(readerstate.SignerConfig{
		Issuer:            "lds-user-service",
		Audience:          "lds-web",
		TTL:               time.Minute,
		GenerateIfMissing: true,
	})
	if err != nil {
		t.Fatalf("LoadSigner() error = %v", err)
	}
	if !generated {
		t.Error("generated = false, want true")
	}
	if len(signer.JWKS().Keys) != 1 {
		t.Errorf("JWKS keys = %d, want 1", len(signer.JWKS().Keys))
	}
}

func TestLoadSignerRequiresAKeyWhenGenerationIsDisabled(t *testing.T) {
	if _, _, err := readerstate.LoadSigner(readerstate.SignerConfig{
		Issuer:   "lds-user-service",
		Audience: "lds-web",
		TTL:      time.Minute,
	}); err == nil {
		t.Fatal("LoadSigner() error = nil, want error")
	}
}
