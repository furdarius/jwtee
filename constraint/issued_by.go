package constraint

import (
	"errors"

	"github.com/furdarius/jwtee"
)

// Block represents IssuedBy constraint errors.
var (
	ErrTokenInvalidIssuer = errors.New("token was not issued by the given issuers")
)

// IssuedBy checks if audience is valid.
type IssuedBy struct {
	issuers []string
}

// NewIssuedBy returns new instance of IssuedBy.
func NewIssuedBy(issuers []string) *IssuedBy {
	return &IssuedBy{issuers}
}

// Validate implements Constraint.
func (c *IssuedBy) Validate(claims jwtee.RegisteredClaims) (err error) {
	if !claims.HasBeenIssuedBy(c.issuers...) {
		return ErrTokenInvalidIssuer
	}

	return nil
}
