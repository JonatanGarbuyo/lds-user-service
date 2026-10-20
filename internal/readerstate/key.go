package readerstate

import (
	"crypto/ecdsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
)

func keyID(publicKey *ecdsa.PublicKey) string {
	x, y := publicKeyCoordinates(publicKey)
	canonical, _ := json.Marshal(struct {
		Crv string `json:"crv"`
		Kty string `json:"kty"`
		X   string `json:"x"`
		Y   string `json:"y"`
	}{
		Crv: curveName,
		Kty: "EC",
		X:   x,
		Y:   y,
	})
	digest := sha256.Sum256(canonical)
	return base64.RawURLEncoding.EncodeToString(digest[:])
}

func publicJWK(kid string, publicKey *ecdsa.PublicKey) JWK {
	x, y := publicKeyCoordinates(publicKey)
	return JWK{
		Kty: "EC",
		Crv: curveName,
		X:   x,
		Y:   y,
		Alg: algorithm,
		Use: keyUse,
		KID: kid,
	}
}

func publicKeyCoordinates(publicKey *ecdsa.PublicKey) (string, string) {
	point, err := publicKey.Bytes()
	if err != nil || len(point) != 65 {
		return "", ""
	}
	return base64.RawURLEncoding.EncodeToString(point[1:33]),
		base64.RawURLEncoding.EncodeToString(point[33:65])
}

func ParsePrivateKeyPEM(value []byte) (*ecdsa.PrivateKey, error) {
	block, _ := pem.Decode(value)
	if block == nil {
		return nil, fmt.Errorf("%w: private key PEM block not found", ErrUnsupportedKey)
	}

	if key, err := x509.ParsePKCS8PrivateKey(block.Bytes); err == nil {
		ecdsaKey, ok := key.(*ecdsa.PrivateKey)
		if !ok {
			return nil, fmt.Errorf("%w: private key is not ECDSA", ErrUnsupportedKey)
		}
		return ecdsaKey, nil
	}
	if key, err := x509.ParseECPrivateKey(block.Bytes); err == nil {
		return key, nil
	}
	return nil, fmt.Errorf("%w: private key must be PKCS#8 or SEC1 ECDSA", ErrUnsupportedKey)
}

func ParsePublicKeyPEM(value []byte) (*ecdsa.PublicKey, error) {
	block, _ := pem.Decode(value)
	if block == nil {
		return nil, fmt.Errorf("%w: public key PEM block not found", ErrUnsupportedKey)
	}
	return parsePublicKeyDER(block.Bytes)
}
