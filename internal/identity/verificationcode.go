package identity

import (
	"crypto/rand"
	"fmt"
	"io"
	"math/big"
)

const verificationCodeDigits = 6

var verificationCodeUpperBound = big.NewInt(1_000_000)

type VerificationCodeGenerator interface {
	Generate() (string, error)
}

type CryptoVerificationCodeGenerator struct {
	random io.Reader
}

func NewVerificationCodeGenerator() *CryptoVerificationCodeGenerator {
	return NewVerificationCodeGeneratorWithReader(rand.Reader)
}

func NewVerificationCodeGeneratorWithReader(random io.Reader) *CryptoVerificationCodeGenerator {
	return &CryptoVerificationCodeGenerator{random: random}
}

func (g *CryptoVerificationCodeGenerator) Generate() (string, error) {
	value, err := rand.Int(g.random, verificationCodeUpperBound)
	if err != nil {
		return "", fmt.Errorf("generate verification code: %w", err)
	}
	return fmt.Sprintf("%0*d", verificationCodeDigits, value.Int64()), nil
}
