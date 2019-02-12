package signer

import (
	"crypto"
	"crypto/hmac"
	_ "crypto/sha256" // link binary
	_ "crypto/sha512" // link binary

	"github.com/furdarius/jwtee"
)

// HMAC implements Signer with HMAC.
type HMAC struct {
	alg  jwtee.Algorithm
	hash crypto.Hash
}

// NewHS256 returns new HMAC Signer using SHA256.
func NewHS256() *HMAC {
	return &HMAC{jwtee.HS256, crypto.SHA256}
}

// NewHS384 returns new HMAC Signer using SHA384.
func NewHS384() *HMAC {
	return &HMAC{jwtee.HS384, crypto.SHA384}
}

// NewHS512 returns new HMAC Signer using HS512.
func NewHS512() *HMAC {
	return &HMAC{jwtee.HS512, crypto.SHA512}
}

// GetAlgorithmID inherited from Signer.
func (h *HMAC) GetAlgorithmID() jwtee.Algorithm {
	return h.alg
}

// Sign inherited from Signer.
func (h *HMAC) Sign(payload []byte, key jwtee.Key) ([]byte, error) {
	if !h.hash.Available() {
		return nil, jwtee.ErrRequestedHashUnavailable
	}

	digest := hmac.New(h.hash.New, key.Secret())

	_, err := digest.Write(payload)
	if err != nil {
		return nil, err
	}

	signed := digest.Sum(nil)

	return signed, nil
}

// Verify inherited from Signer.
func (h *HMAC) Verify(expected, payload []byte, key jwtee.Key) error {
	signed, err := h.Sign(payload, key)
	if err != nil {
		return err
	}

	if !hmac.Equal(expected, signed) {
		return jwtee.ErrInvalidSignature
	}

	return nil
}
