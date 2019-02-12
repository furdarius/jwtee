package jwtee_test

import (
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/furdarius/jwtee"
)

func TestJSONParser_Parse(t *testing.T) {
	tests := []struct {
		desc    string
		jwt     []byte
		checker func(t *testing.T, parts *jwtee.DecodedParts, err error)
	}{
		{
			desc: "success parsing",
			jwt:  []byte(`eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c`),
			checker: func(t *testing.T, parts *jwtee.DecodedParts, err error) {
				assert.NoError(t, err, "Parse finished with error")

				raw, err := parts.MarshalBinary()
				assert.NoError(t, err, "failed to marshal binary")

				assert.Equal(t,
					[]byte(`eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c`),
					raw)

				assert.Equal(t,
					[]byte(`eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ`),
					parts.Payload())

				expectedHeader := jwtee.Header{
					Typ: "JWT",
					Alg: jwtee.HS256,
				}
				assert.Equal(t, expectedHeader, parts.Header())

				type testclaims struct {
					jwtee.RegisteredClaims

					Name string `json:"name"`
				}

				var claims testclaims
				err = json.Unmarshal(parts.RawClaims(), &claims)
				assert.NoError(t, err, "failed to unmarshal testclaims from raw claims")
				assert.Equal(t, "John Doe", claims.Name)
				assert.Equal(t, jwtee.Timestamp(1516239022), claims.Iat)
				assert.Equal(t, "1234567890", claims.Sub)
			},
		},
	}

	for _, test := range tests {
		t.Run(test.desc, func(t *testing.T) {
			token, err := jwtee.NewJSONParser().Parse(test.jwt)
			test.checker(t, token, err)
		})
	}
}
