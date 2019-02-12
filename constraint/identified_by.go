package constraint

import (
	"errors"

	"github.com/furdarius/jwtee"
)

// Block represents IdentifiedBy constraint errors.
var (
	ErrTokenInvalidID = errors.New("token is not identified with the expected ID")
)

// IdentifiedBy checks if audience is valid.
type IdentifiedBy struct {
	id string
}

// NewIdentifiedBy returns new instance of IdentifiedBy.
func NewIdentifiedBy(id string) *IdentifiedBy {
	return &IdentifiedBy{id}
}

// Validate implements Constraint.
func (c *IdentifiedBy) Validate(claims jwtee.RegisteredClaims) (err error) {
	if !claims.IsIdentifiedBy(c.id) {
		return ErrTokenInvalidID
	}

	return nil
}
