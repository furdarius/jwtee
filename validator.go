package jwtee

// Constraint used to validate JWT Claims with Constraint.
type Constraint interface {
	Validate(claims RegisteredClaims) error
}

// Validator used to validate JWT Claims.
type Validator interface {
	Validate(claims RegisteredClaims, constraints ...Constraint) []error
}

// ClaimsValidator used to validate RegisteredClaims with Constraints.
type ClaimsValidator struct{}

// NewClaimsValidator returns new instance of ClaimsValidator.
func NewClaimsValidator() *ClaimsValidator {
	return &ClaimsValidator{}
}

// Validate inherited from Validator.
func (v *ClaimsValidator) Validate(claims RegisteredClaims, constraints ...Constraint) (errs []error) {
	for _, constraint := range constraints {
		err := constraint.Validate(claims)

		if err != nil {
			errs = append(errs, err)
		}
	}

	return errs
}
