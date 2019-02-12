package jwtee

import "github.com/pkg/errors"

var (
	// ErrInvalidSignature indicates that signature invalid.
	ErrInvalidSignature = errors.New("invalid signature")

	// ErrRequestedHashUnavailable indicates that hash func is not registered.
	ErrRequestedHashUnavailable = errors.New("requested hash function is unavailable")
)

// Key stores signing key data.
type Key struct {
	secret []byte
}

// NewSharedSecretKey returns Key with secret inside.
func NewSharedSecretKey(secret []byte) Key {
	return Key{
		secret: secret,
	}
}

// Secret returns key's secret.
func (k Key) Secret() []byte {
	return k.secret
}

// Signer used to sign and verify token signature.
type Signer interface {
	GetAlgorithmID() Algorithm
	Sign(payload []byte, key Key) ([]byte, error)
	Verify(expected, payload []byte, key Key) error
}
