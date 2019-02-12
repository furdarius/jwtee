package signer_test

import (
	"encoding/base64"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/furdarius/jwtee"
	"github.com/furdarius/jwtee/signer"
)

func TestHMAC_Sign(t *testing.T) {
	tests := []struct {
		desc    string
		payload []byte
		key     jwtee.Key
		signer  *signer.HMAC
		checker func(t *testing.T, signature []byte, err error)
	}{
		{
			desc:    "successful signing HS256",
			payload: []byte(`eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRHdvZSIsImlhdCI6MTUxNjIzOTAyMn0`),
			key:     jwtee.NewSharedSecretKey([]byte(`1234`)),
			signer:  signer.NewHS256(),
			checker: func(t *testing.T, signature []byte, err error) {
				assert.NoError(t, err)

				expectedSignature := []byte(`JzaK6yp8NxAj8gQ1gPP6xu8wpxQ1q4Pno9Co8_XJjk0`)

				encoded := make([]byte, base64.RawURLEncoding.EncodedLen(len(signature)))
				base64.RawURLEncoding.Encode(encoded, signature)

				assert.Equal(t, expectedSignature, encoded)
			},
		},
		{
			desc:    "successful signing HS384",
			payload: []byte(`eyJhbGciOiJIUzM4NCIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRHdvZSIsImlhdCI6MTUxNjIzOTAyMn0`),
			key:     jwtee.NewSharedSecretKey([]byte(`12345`)),
			signer:  signer.NewHS384(),
			checker: func(t *testing.T, signature []byte, err error) {
				assert.NoError(t, err)

				expectedSignature := []byte(`5hmK_dVXFK6WSaR5c3oAe7WSQlhR20JPU_NKSMuZdU5Pq1gu729zPEVw6JkPURhR`)

				encoded := make([]byte, base64.RawURLEncoding.EncodedLen(len(signature)))
				base64.RawURLEncoding.Encode(encoded, signature)

				assert.Equal(t, expectedSignature, encoded)
			},
		},
		{
			desc:    "successful signing HS512",
			payload: []byte(`eyJhbGciOiJIUzUxMiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRHdvZSIsImlhdCI6MTUxNjIzOTAyMn0`),
			key:     jwtee.NewSharedSecretKey([]byte(`123456`)),
			signer:  signer.NewHS512(),
			checker: func(t *testing.T, signature []byte, err error) {
				assert.NoError(t, err)

				expectedSignature := []byte(`sbmDH-Gex_haT58-wa9tLoFI1X0-7krrfUYb-kgP05Lix-fdA2SwAvm-jupzkaABF-9OKOLESXnpblmH8njLuQ`)

				encoded := make([]byte, base64.RawURLEncoding.EncodedLen(len(signature)))
				base64.RawURLEncoding.Encode(encoded, signature)

				assert.Equal(t, expectedSignature, encoded)
			},
		},
	}

	for _, test := range tests {
		t.Run(test.desc, func(t *testing.T) {
			signature, err := test.signer.Sign(test.payload, test.key)
			test.checker(t, signature, err)
		})
	}
}

func TestHMAC_Verify(t *testing.T) {
	tests := []struct {
		desc      string
		payload   []byte
		signature []byte
		key       jwtee.Key
		signer    *signer.HMAC
		checker   func(t *testing.T, err error)
	}{
		{
			desc:      "successful verifying HS256",
			payload:   []byte(`eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRHdvZSIsImlhdCI6MTUxNjIzOTAyMn0`),
			signature: []byte(`JzaK6yp8NxAj8gQ1gPP6xu8wpxQ1q4Pno9Co8_XJjk0`),
			key:       jwtee.NewSharedSecretKey([]byte(`1234`)),
			signer:    signer.NewHS256(),
			checker: func(t *testing.T, err error) {
				assert.NoError(t, err)
			},
		},
		{
			desc:      "successful verifying HS384",
			payload:   []byte(`eyJhbGciOiJIUzM4NCIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRHdvZSIsImlhdCI6MTUxNjIzOTAyMn0`),
			signature: []byte(`5hmK_dVXFK6WSaR5c3oAe7WSQlhR20JPU_NKSMuZdU5Pq1gu729zPEVw6JkPURhR`),
			key:       jwtee.NewSharedSecretKey([]byte(`12345`)),
			signer:    signer.NewHS384(),
			checker: func(t *testing.T, err error) {
				assert.NoError(t, err)
			},
		},
		{
			desc:      "successful verifying HS512",
			payload:   []byte(`eyJhbGciOiJIUzUxMiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRHdvZSIsImlhdCI6MTUxNjIzOTAyMn0`),
			signature: []byte(`sbmDH-Gex_haT58-wa9tLoFI1X0-7krrfUYb-kgP05Lix-fdA2SwAvm-jupzkaABF-9OKOLESXnpblmH8njLuQ`),
			key:       jwtee.NewSharedSecretKey([]byte(`123456`)),
			signer:    signer.NewHS512(),
			checker: func(t *testing.T, err error) {
				assert.NoError(t, err)
			},
		},
	}

	for _, test := range tests {
		t.Run(test.desc, func(t *testing.T) {
			decoded := make([]byte, base64.RawURLEncoding.DecodedLen(len(test.signature)))
			_, err := base64.RawURLEncoding.Decode(decoded, test.signature)
			if err != nil {
				panic("failed to decode signature from base64")
			}

			err = test.signer.Verify(decoded, test.payload, test.key)
			test.checker(t, err)
		})
	}
}
