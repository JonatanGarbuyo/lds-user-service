package readerstate

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/big"
	"strings"
	"time"
)

const (
	algorithm = "ES256"
	keyUse    = "sig"
	curveName = "P-256"
)

var (
	ErrInvalidSnapshot = errors.New("invalid reader state snapshot")
	ErrUnsupportedKey  = errors.New("unsupported reader state key")
)

type Options struct {
	Issuer   string
	Audience string
	TTL      time.Duration
	Now      func() time.Time
	Random   io.Reader
}

type Snapshot struct {
	SignedSnapshot string
	ExpiresAt      time.Time
}

type Claims struct {
	Issuer        string
	Audience      string
	Subject       string
	IssuedAt      time.Time
	ExpiresAt     time.Time
	TokenID       string
	EmailVerified bool
	Status        string
}

type JWKS struct {
	Keys []JWK `json:"keys"`
}

type JWK struct {
	Kty string `json:"kty"`
	Crv string `json:"crv"`
	X   string `json:"x"`
	Y   string `json:"y"`
	Alg string `json:"alg"`
	Use string `json:"use"`
	KID string `json:"kid"`
}

type Signer struct {
	active       *ecdsa.PrivateKey
	activeKeyID  string
	verification map[string]*ecdsa.PublicKey
	order        []string
	issuer       string
	audience     string
	ttl          time.Duration
	now          func() time.Time
	random       io.Reader
}

func NewSigner(active *ecdsa.PrivateKey, previous []*ecdsa.PublicKey, options Options) (*Signer, error) {
	if active == nil {
		return nil, fmt.Errorf("%w: active private key is required", ErrUnsupportedKey)
	}
	if active.Curve != elliptic.P256() {
		return nil, fmt.Errorf("%w: active key must use P-256", ErrUnsupportedKey)
	}
	if options.Issuer == "" || options.Audience == "" {
		return nil, errors.New("reader state issuer and audience are required")
	}
	if options.TTL <= 0 {
		return nil, errors.New("reader state TTL must be greater than zero")
	}
	if options.Now == nil {
		options.Now = time.Now
	}
	if options.Random == nil {
		options.Random = rand.Reader
	}

	signer := &Signer{
		active:       active,
		activeKeyID:  keyID(&active.PublicKey),
		verification: make(map[string]*ecdsa.PublicKey),
		issuer:       options.Issuer,
		audience:     options.Audience,
		ttl:          options.TTL,
		now:          options.Now,
		random:       options.Random,
	}
	signer.addVerificationKey(signer.activeKeyID, &active.PublicKey)
	for _, publicKey := range previous {
		if publicKey == nil {
			continue
		}
		if publicKey.Curve != elliptic.P256() {
			return nil, fmt.Errorf("%w: previous key must use P-256", ErrUnsupportedKey)
		}
		signer.addVerificationKey(keyID(publicKey), publicKey)
	}
	return signer, nil
}

func (s *Signer) ActiveKeyID() string {
	return s.activeKeyID
}

func (s *Signer) Issue(userID string, emailVerified bool, status string) (Snapshot, error) {
	now := s.now().UTC()
	expiresAt := now.Add(s.ttl)
	tokenID, err := randomTokenID(s.random)
	if err != nil {
		return Snapshot{}, err
	}

	header, err := json.Marshal(jwtHeader{Algorithm: algorithm, KeyID: s.activeKeyID, Type: "JWT"})
	if err != nil {
		return Snapshot{}, fmt.Errorf("encode reader state header: %w", err)
	}
	payload, err := json.Marshal(jwtPayload{
		Issuer:        s.issuer,
		Audience:      s.audience,
		Subject:       userID,
		IssuedAt:      now.Unix(),
		ExpiresAt:     expiresAt.Unix(),
		TokenID:       tokenID,
		EmailVerified: emailVerified,
		Status:        status,
	})
	if err != nil {
		return Snapshot{}, fmt.Errorf("encode reader state payload: %w", err)
	}

	signingInput := encodeSegment(header) + "." + encodeSegment(payload)
	digest := sha256.Sum256([]byte(signingInput))
	r, signature, err := ecdsa.Sign(s.random, s.active, digest[:])
	if err != nil {
		return Snapshot{}, fmt.Errorf("sign reader state: %w", err)
	}
	encodedSignature := encodeSignature(r, signature)

	return Snapshot{
		SignedSnapshot: signingInput + "." + encodedSignature,
		ExpiresAt:      expiresAt,
	}, nil
}

func (s *Signer) Verify(token string) (Claims, error) {
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return Claims{}, ErrInvalidSnapshot
	}

	headerBytes, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		return Claims{}, ErrInvalidSnapshot
	}
	var header jwtHeader
	if err := json.Unmarshal(headerBytes, &header); err != nil {
		return Claims{}, ErrInvalidSnapshot
	}
	if header.Algorithm != algorithm {
		return Claims{}, fmt.Errorf("%w: algorithm must be %s", ErrInvalidSnapshot, algorithm)
	}
	publicKey, exists := s.verification[header.KeyID]
	if !exists {
		return Claims{}, fmt.Errorf("%w: unknown key id", ErrInvalidSnapshot)
	}

	signatureBytes, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil || len(signatureBytes) != 64 {
		return Claims{}, ErrInvalidSnapshot
	}
	digest := sha256.Sum256([]byte(parts[0] + "." + parts[1]))
	r := new(big.Int).SetBytes(signatureBytes[:32])
	signature := new(big.Int).SetBytes(signatureBytes[32:])
	if !ecdsa.Verify(publicKey, digest[:], r, signature) {
		return Claims{}, ErrInvalidSnapshot
	}

	payloadBytes, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return Claims{}, ErrInvalidSnapshot
	}
	var payload jwtPayload
	if err := json.Unmarshal(payloadBytes, &payload); err != nil {
		return Claims{}, ErrInvalidSnapshot
	}
	if payload.Issuer != s.issuer || payload.Audience != s.audience {
		return Claims{}, fmt.Errorf("%w: issuer or audience mismatch", ErrInvalidSnapshot)
	}
	if payload.Subject == "" {
		return Claims{}, fmt.Errorf("%w: subject is required", ErrInvalidSnapshot)
	}

	now := s.now().UTC()
	issuedAt := time.Unix(payload.IssuedAt, 0).UTC()
	expiresAt := time.Unix(payload.ExpiresAt, 0).UTC()
	if !now.Before(expiresAt) {
		return Claims{}, fmt.Errorf("%w: snapshot expired", ErrInvalidSnapshot)
	}
	if issuedAt.After(now.Add(time.Minute)) {
		return Claims{}, fmt.Errorf("%w: issued-at is in the future", ErrInvalidSnapshot)
	}

	return Claims{
		Issuer:        payload.Issuer,
		Audience:      payload.Audience,
		Subject:       payload.Subject,
		IssuedAt:      issuedAt,
		ExpiresAt:     expiresAt,
		TokenID:       payload.TokenID,
		EmailVerified: payload.EmailVerified,
		Status:        payload.Status,
	}, nil
}

func (s *Signer) JWKS() JWKS {
	keys := make([]JWK, 0, len(s.order))
	for _, kid := range s.order {
		keys = append(keys, publicJWK(kid, s.verification[kid]))
	}
	return JWKS{Keys: keys}
}

func (s *Signer) addVerificationKey(kid string, publicKey *ecdsa.PublicKey) {
	if _, exists := s.verification[kid]; exists {
		return
	}
	s.verification[kid] = publicKey
	s.order = append(s.order, kid)
}

type jwtHeader struct {
	Algorithm string `json:"alg"`
	KeyID     string `json:"kid"`
	Type      string `json:"typ"`
}

type jwtPayload struct {
	Issuer        string `json:"iss"`
	Audience      string `json:"aud"`
	Subject       string `json:"sub"`
	IssuedAt      int64  `json:"iat"`
	ExpiresAt     int64  `json:"exp"`
	TokenID       string `json:"jti"`
	EmailVerified bool   `json:"emailVerified"`
	Status        string `json:"status"`
}

func encodeSegment(value []byte) string {
	return base64.RawURLEncoding.EncodeToString(value)
}

func encodeSignature(r, signature *big.Int) string {
	buffer := make([]byte, 64)
	r.FillBytes(buffer[:32])
	signature.FillBytes(buffer[32:])
	return base64.RawURLEncoding.EncodeToString(buffer)
}

func randomTokenID(random io.Reader) (string, error) {
	var buffer [16]byte
	if _, err := io.ReadFull(random, buffer[:]); err != nil {
		return "", fmt.Errorf("generate reader state token id: %w", err)
	}
	return base64.RawURLEncoding.EncodeToString(buffer[:]), nil
}
