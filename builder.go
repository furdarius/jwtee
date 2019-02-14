package jwtee

import (
	"encoding"
	"encoding/base64"
	"github.com/pkg/errors"
)

// Builder used to build encoded and signed token.
type Builder interface {
	Build(claims encoding.BinaryMarshaler, signer Signer, key Key) (*DecodedParts, error)
}

// TokenBuilder implements Builder.
type TokenBuilder struct {
	h Header
}

// NewTokenBuilder returns new instance of TokenBuilder.
func NewTokenBuilder() *TokenBuilder {
	return &TokenBuilder{
		h: Header{
			Typ: "JWT",
		},
	}
}

// WithKID used to setup the kid (key ID) Header Parameter.
func (b *TokenBuilder) WithKID(kid string) *TokenBuilder {
	b.h.Kid = kid

	return b
}

// Build used to construct and encode JWT.
func (b *TokenBuilder) Build(claims encoding.BinaryMarshaler, signer Signer, key Key) (*DecodedParts, error) {
	// TODO: Possible to reduce allocation if encode parts in same buffer
	encodedHeader := b.encodeHeader(signer)

	rawClaims, encodedClaims, err := b.encodeClaims(claims)
	if err != nil {
		return nil, errors.Wrap(err, "failed to encode claims")
	}

	payload := b.buildPayload(encodedHeader, encodedClaims)

	signed, signature, err := b.signPayload(payload, signer, key)
	if err != nil {
		return nil, errors.Wrap(err, "failed to sign payload")
	}

	parts := &DecodedParts{
		raw: signed,
		header: Header{
			Typ: "JWT",
			Alg: signer.GetAlgorithmID(),
		},
		claims:    rawClaims,
		payload:   payload,
		signature: signature,
	}

	return parts, nil
}

func (b *TokenBuilder) concatParts(p1, p2, sep []byte) []byte {
	buf := make([]byte, len(p1)+len(p2)+1)
	copy(buf[:len(p1)], p1)
	copy(buf[len(p1):len(p1)+1], sep)
	copy(buf[len(p1)+1:], p2)

	return buf
}

func (b *TokenBuilder) buildPayload(headers, claims []byte) []byte {
	return b.concatParts(headers, claims, []byte{sep})
}

func (b *TokenBuilder) signPayload(payload []byte, signer Signer, key Key) (signed, signature []byte, err error) {
	signature, err = signer.Sign(payload, key)
	if err != nil {
		return nil, nil, err
	}

	encodedSignature := make([]byte, base64.RawURLEncoding.EncodedLen(len(signature)))
	base64.RawURLEncoding.Encode(encodedSignature, signature)

	signed = b.concatParts(payload, encodedSignature, []byte{sep})

	return signed, signature, nil
}

func (b *TokenBuilder) encodeClaims(claims encoding.BinaryMarshaler) (raw, encoded []byte, err error) {
	raw, err = claims.MarshalBinary()
	if err != nil {
		return nil, nil, err
	}

	encoded = make([]byte, base64.RawURLEncoding.EncodedLen(len(raw)))
	base64.RawURLEncoding.Encode(encoded, raw)

	return raw, encoded, nil
}

// nolint: gocyclo
func (b *TokenBuilder) encodeHeader(signer Signer) []byte {
	if b.h.Kid != "" && b.h.Typ == "JWT" {
		algID := signer.GetAlgorithmID()
		algIDLen := len(algID)
		kid := b.h.Kid
		kidLen := len(kid)
		buf := make([]byte, 20+algIDLen+9+kidLen+2)
		copy(buf[:20], `{"typ":"JWT","alg":"`)
		copy(buf[20:20+algIDLen], algID)
		copy(buf[20+algIDLen:20+algIDLen+9], `","kid":"`)
		copy(buf[20+algIDLen+9:], kid)
		copy(buf[20+algIDLen+9+kidLen:], `"}`)

		encoded := make([]byte, base64.RawURLEncoding.EncodedLen(len(buf)))
		base64.RawURLEncoding.Encode(encoded, buf)

		return encoded
	}

	switch signer.GetAlgorithmID() {
	case HS256:
		return []byte("eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9")
	case HS384:
		return []byte("eyJhbGciOiJIUzM4NCIsInR5cCI6IkpXVCJ9")
	case HS512:
		return []byte("eyJhbGciOiJIUzUxMiIsInR5cCI6IkpXVCJ9")
	case RS256:
		return []byte("eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9")
	case RS384:
		return []byte("eyJhbGciOiJSUzM4NCIsInR5cCI6IkpXVCJ9")
	case RS512:
		return []byte("eyJhbGciOiJSUzUxMiIsInR5cCI6IkpXVCJ9")
	case ES256:
		return []byte("eyJhbGciOiJFUzI1NiIsInR5cCI6IkpXVCJ9")
	case ES384:
		return []byte("eyJhbGciOiJFUzM4NCIsInR5cCI6IkpXVCJ9")
	case ES512:
		return []byte("eyJhbGciOiJFUzUxMiIsInR5cCI6IkpXVCJ9")
	case PS256:
		return []byte("eyJhbGciOiJQUzI1NiIsInR5cCI6IkpXVCJ9")
	case PS384:
		return []byte("eyJhbGciOiJQUzM4NCIsInR5cCI6IkpXVCJ9")
	default:
		algID := signer.GetAlgorithmID()
		algIDLen := len(algID)
		buf := make([]byte, 20+algIDLen+2)
		copy(buf[:20], `{"typ":"JWT","alg":"`)
		copy(buf[20:20+algIDLen], algID)
		copy(buf[20+algIDLen:], `"}`)

		encoded := make([]byte, base64.RawURLEncoding.EncodedLen(len(buf)))
		base64.RawURLEncoding.Encode(encoded, buf)

		return encoded
	}
}
