package constraint

import (
	"errors"

	"github.com/furdarius/jwtee"
)

// Block represents RelatedTo constraint errors.
var (
	ErrTokenInvalidRelation = errors.New("token is not related to the expected subject")
)

// RelatedTo checks if subject is valid.
type RelatedTo struct {
	subject string
}

// NewRelatedTo returns new instance of RelatedTo.
func NewRelatedTo(subject string) *RelatedTo {
	return &RelatedTo{subject}
}

// Validate implements Constraint.
func (c *RelatedTo) Validate(claims jwtee.RegisteredClaims) (err error) {
	if !claims.IsRelatedTo(c.subject) {
		return ErrTokenInvalidRelation
	}

	return nil
}
