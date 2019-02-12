package jwtee

import (
	"encoding/json"
)

// DecodedParts stores ready to use parts of the JWT token.
type DecodedParts struct {
	raw       []byte
	header    Header
	claims    json.RawMessage
	payload   []byte
	signature []byte
}

// Header returns token's Header.
func (t *DecodedParts) Header() Header {
	return t.header
}

// RawClaims returns bytes with decoded claims string.
func (t *DecodedParts) RawClaims() []byte {
	return t.claims
}

// Payload returns bytes used as JWS Signing Input to compute the JWS Signature.
// JWS Signing Input formatted as:
// ASCII(BASE64URL(UTF8(JWS Protected Header)) || '.' || BASE64URL(JWS Payload))
func (t *DecodedParts) Payload() []byte {
	return t.payload
}

// Signature returns token's signature.
func (t *DecodedParts) Signature() []byte {
	return t.signature
}

// MarshalBinary inherited from encoding.BinaryMarshaler.
func (t *DecodedParts) MarshalBinary() (data []byte, err error) {
	return t.raw, nil
}

// MarshalText inherited from encoding.TextMarshaler.
func (t *DecodedParts) MarshalText() (text []byte, err error) {
	return t.MarshalBinary()
}

// PartsVerifier used to verify signature of JWT.
type PartsVerifier struct {
	signer Signer
	key    Key
}

// NewPartsVerifier returns new instance of PartsVerifier.
func NewPartsVerifier(signer Signer, key Key) *PartsVerifier {
	return &PartsVerifier{signer, key}
}

// Verify used to check consistency of token signature.
func (v *PartsVerifier) Verify(parts *DecodedParts) error {
	return v.signer.Verify(parts.Signature(), parts.Payload(), v.key)
}
