package jwtee_test

import (
	"encoding"
	"encoding/json"
	"github.com/furdarius/jwtee"
	"github.com/furdarius/jwtee/signer"
	"github.com/stretchr/testify/assert"
	"testing"
)

type testclaims struct {
	jwtee.RegisteredClaims

	Name  string `json:"name"`
	Admin bool   `json:"admin"`
}

// MarshalBinary implements encoding.BinaryMarshaler.
func (c testclaims) MarshalBinary() (data []byte, err error) {
	return json.Marshal(c)
}

func TestBuilder_Build(t *testing.T) {
	tests := []struct {
		desc    string
		key     jwtee.Key
		signer  jwtee.Signer
		builder jwtee.Builder
		claims  encoding.BinaryMarshaler
		checker func(t *testing.T, parts *jwtee.DecodedParts, err error)
	}{
		{
			desc:    "successful building with HS256",
			key:     jwtee.NewSharedSecretKey([]byte(`12345`)),
			signer:  signer.NewHS256(),
			builder: jwtee.NewTokenBuilder(),
			claims: testclaims{
				RegisteredClaims: jwtee.RegisteredClaims{
					Sub: "1234567890",
					Iat: 1516239022,
				},
				Name:  "John Doe",
				Admin: true,
			},
			checker: func(t *testing.T, parts *jwtee.DecodedParts, err error) {
				assert.NoError(t, err)

				expected := []byte(`eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpYXQiOjE1MTYyMzkwMjIsInN1YiI6IjEyMzQ1Njc4OTAiLCJuYW1lIjoiSm9obiBEb2UiLCJhZG1pbiI6dHJ1ZX0.VlbSuOtuL9PoPW1xdBwKsf-Z4kLHI0wKWwi9FQphF-c`)

				actual, err := parts.MarshalText()
				assert.NoError(t, err)

				assert.Equal(t, expected, actual)
			},
		},
	}

	for _, test := range tests {
		t.Run(test.desc, func(t *testing.T) {
			parts, err := test.builder.Build(test.claims, test.signer, test.key)
			test.checker(t, parts, err)
		})
	}
}
