package readerstate

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"os"
	"strings"
	"time"
)

type SignerConfig struct {
	Issuer                 string
	Audience               string
	TTL                    time.Duration
	PrivateKeyPEM          []byte
	PrivateKeyFile         string
	PreviousPublicKeysPEM  []byte
	PreviousPublicKeysFile string
	GenerateIfMissing      bool
	Now                    func() time.Time
}

func LoadSigner(config SignerConfig) (*Signer, bool, error) {
	privateKeyPEM := normalizePEM(config.PrivateKeyPEM)
	if len(privateKeyPEM) == 0 && config.PrivateKeyFile != "" {
		value, err := os.ReadFile(config.PrivateKeyFile)
		if err != nil {
			return nil, false, fmt.Errorf("read reader state private key: %w", err)
		}
		privateKeyPEM = value
	}

	generated := false
	var active *ecdsa.PrivateKey
	if len(privateKeyPEM) == 0 {
		if !config.GenerateIfMissing {
			return nil, false, errors.New("reader state private key is required")
		}
		key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			return nil, false, fmt.Errorf("generate reader state key: %w", err)
		}
		active = key
		generated = true
	} else {
		key, err := ParsePrivateKeyPEM(privateKeyPEM)
		if err != nil {
			return nil, false, err
		}
		active = key
	}

	previousPEM := normalizePEM(config.PreviousPublicKeysPEM)
	if len(previousPEM) == 0 && config.PreviousPublicKeysFile != "" {
		value, err := os.ReadFile(config.PreviousPublicKeysFile)
		if err != nil {
			return nil, false, fmt.Errorf("read reader state previous public keys: %w", err)
		}
		previousPEM = value
	}
	var previous []*ecdsa.PublicKey
	if len(previousPEM) > 0 {
		keys, err := ParsePublicKeysPEM(previousPEM)
		if err != nil {
			return nil, false, err
		}
		previous = keys
	}

	signer, err := NewSigner(active, previous, Options{
		Issuer:   config.Issuer,
		Audience: config.Audience,
		TTL:      config.TTL,
		Now:      config.Now,
	})
	if err != nil {
		return nil, false, err
	}
	return signer, generated, nil
}

func normalizePEM(value []byte) []byte {
	if len(value) == 0 {
		return nil
	}
	normalized := strings.ReplaceAll(string(value), `\n`, "\n")
	return []byte(normalized)
}

func ParsePublicKeysPEM(value []byte) ([]*ecdsa.PublicKey, error) {
	keys := make([]*ecdsa.PublicKey, 0)
	remaining := value
	for {
		block, rest := pem.Decode(remaining)
		if block == nil {
			break
		}
		remaining = rest
		key, err := parsePublicKeyDER(block.Bytes)
		if err != nil {
			return nil, err
		}
		keys = append(keys, key)
	}
	if len(keys) == 0 {
		return nil, fmt.Errorf("%w: no public key PEM blocks found", ErrUnsupportedKey)
	}
	return keys, nil
}

func parsePublicKeyDER(der []byte) (*ecdsa.PublicKey, error) {
	if parsed, err := x509.ParsePKIXPublicKey(der); err == nil {
		publicKey, ok := parsed.(*ecdsa.PublicKey)
		if !ok {
			return nil, fmt.Errorf("%w: public key is not ECDSA", ErrUnsupportedKey)
		}
		return publicKey, nil
	}
	if certificate, err := x509.ParseCertificate(der); err == nil {
		publicKey, ok := certificate.PublicKey.(*ecdsa.PublicKey)
		if !ok {
			return nil, fmt.Errorf("%w: certificate key is not ECDSA", ErrUnsupportedKey)
		}
		return publicKey, nil
	}
	if key, err := x509.ParseECPrivateKey(der); err == nil {
		return &key.PublicKey, nil
	}
	return nil, fmt.Errorf("%w: public key must be PKIX, a certificate or SEC1 ECDSA", ErrUnsupportedKey)
}
