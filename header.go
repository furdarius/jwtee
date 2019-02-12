package jwtee

// Algorithm describes algorithms supported for signing/verifying.
type Algorithm string

// Algorithm constants represents available algorithms values.
const (
	HS256 Algorithm = "HS256"
	HS384 Algorithm = "HS384"
	HS512 Algorithm = "HS512"
	RS256 Algorithm = "RS256"
	RS384 Algorithm = "RS384"
	RS512 Algorithm = "RS512"
	ES256 Algorithm = "ES256"
	ES384 Algorithm = "ES384"
	ES512 Algorithm = "ES512"
	PS256 Algorithm = "PS256"
	PS384 Algorithm = "PS384"
)

// Header stores JWT header data.
type Header struct {
	// The type of JWS: it can only be "JWT" here
	// @see https://tools.ietf.org/html/rfc7515#section-4.1.9
	Typ string `json:"typ,omitempty"`

	// The algorithm used
	// @see https://tools.ietf.org/html/rfc7515#section-4.1.1
	Alg Algorithm `json:"alg"`

	// Content type
	// @see https://tools.ietf.org/html/rfc7519#section-5.2
	Cty string `json:"cty,omitempty"`

	// JSON Key URL
	// @see https://tools.ietf.org/html/rfc7515#section-4.1.2
	Jku string `json:"jku,omitempty"`

	// Key ID
	// @see https://tools.ietf.org/html/rfc7515#section-4.1.4
	Kid string `json:"kid,omitempty"`

	// X.509 URL
	// @see https://tools.ietf.org/html/rfc7515#section-4.1.5
	X5u string `json:"x5u,omitempty"`

	// X.509 certificate thumbprint
	// @see https://tools.ietf.org/html/rfc7515#section-4.1.7
	X5t string `json:"x5t,omitempty"`
}
