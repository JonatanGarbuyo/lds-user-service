package password

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"strings"

	"golang.org/x/crypto/argon2"

	"github.com/JonatanGarbuyo/lds-user-service/internal/identity"
)

const (
	argon2idAlgorithm = "argon2id"
	argon2Version     = argon2.Version

	maxMemory      = 256 * 1024
	maxIterations  = 10
	maxParallelism = 32
	maxSaltLength  = 64
	maxHashLength  = 128
)

type Params struct {
	Memory      uint32
	Iterations  uint32
	Parallelism uint8
	SaltLength  uint32
	KeyLength   uint32
}

func DefaultParams() Params {
	return Params{
		Memory:      64 * 1024,
		Iterations:  3,
		Parallelism: 2,
		SaltLength:  16,
		KeyLength:   32,
	}
}

type Hasher struct {
	params Params
	random io.Reader
}

func New() *Hasher {
	return &Hasher{params: DefaultParams(), random: rand.Reader}
}

func (h *Hasher) Hash(password string) (string, error) {
	salt := make([]byte, h.params.SaltLength)
	if _, err := io.ReadFull(h.random, salt); err != nil {
		return "", fmt.Errorf("generate password salt: %w", err)
	}

	hash := argon2.IDKey([]byte(password), salt, h.params.Iterations, h.params.Memory, h.params.Parallelism, h.params.KeyLength)
	encoded := fmt.Sprintf(
		"$%s$v=%d$m=%d,t=%d,p=%d$%s$%s",
		argon2idAlgorithm,
		argon2Version,
		h.params.Memory,
		h.params.Iterations,
		h.params.Parallelism,
		base64.RawStdEncoding.EncodeToString(salt),
		base64.RawStdEncoding.EncodeToString(hash),
	)
	return encoded, nil
}

func (h *Hasher) Verify(password, encoded string) (bool, error) {
	params, salt, expected, err := decode(encoded)
	if err != nil {
		return false, err
	}

	actual := argon2.IDKey([]byte(password), salt, params.Iterations, params.Memory, params.Parallelism, uint32(len(expected)))
	return subtle.ConstantTimeCompare(actual, expected) == 1, nil
}

func decode(encoded string) (Params, []byte, []byte, error) {
	parts := strings.Split(encoded, "$")
	if len(parts) != 6 || parts[0] != "" {
		return Params{}, nil, nil, errors.New("invalid password hash encoding")
	}
	if parts[1] != argon2idAlgorithm {
		return Params{}, nil, nil, errors.New("unsupported password hash algorithm")
	}

	var version int
	if _, err := fmt.Sscanf(parts[2], "v=%d", &version); err != nil || version != argon2Version {
		return Params{}, nil, nil, errors.New("unsupported password hash version")
	}

	var params Params
	if _, err := fmt.Sscanf(parts[3], "m=%d,t=%d,p=%d", &params.Memory, &params.Iterations, &params.Parallelism); err != nil {
		return Params{}, nil, nil, errors.New("invalid password hash parameters")
	}
	if params.Memory == 0 || params.Memory > maxMemory ||
		params.Iterations == 0 || params.Iterations > maxIterations ||
		params.Parallelism == 0 || params.Parallelism > maxParallelism {
		return Params{}, nil, nil, errors.New("password hash parameters out of range")
	}

	salt, err := base64.RawStdEncoding.DecodeString(parts[4])
	if err != nil || len(salt) == 0 || len(salt) > maxSaltLength {
		return Params{}, nil, nil, errors.New("invalid password hash salt")
	}

	hash, err := base64.RawStdEncoding.DecodeString(parts[5])
	if err != nil || len(hash) == 0 || len(hash) > maxHashLength {
		return Params{}, nil, nil, errors.New("invalid password hash value")
	}

	return params, salt, hash, nil
}

var _ identity.PasswordHasher = (*Hasher)(nil)
