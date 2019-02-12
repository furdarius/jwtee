package constraint

import (
	"errors"

	"github.com/furdarius/jwtee"
)

// Block represents PermittedFor constraint errors.
var (
	ErrTokenNotPermitted = errors.New("token is not allowed to be used by this audience")
)

// PermittedFor checks if audience is valid.
type PermittedFor struct {
	audience string
}

// NewPermittedFor returns new instance of PermittedFor.
func NewPermittedFor(audience string) *PermittedFor {
	return &PermittedFor{audience}
}

// Validate implements Constraint.
func (c *PermittedFor) Validate(claims jwtee.RegisteredClaims) (err error) {
	if !claims.IsPermittedFor(c.audience) {
		return ErrTokenNotPermitted
	}

	return nil
}
