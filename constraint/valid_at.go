package constraint

import (
	"errors"
	"time"

	"github.com/furdarius/jwtee"
)

// Block represents ValidAt constraint errors.
var (
	ErrTokenExpired   = errors.New("token is expired")
	ErrTokenNotBefore = errors.New("token cannot be used yet")
	ErrTokenNotIssued = errors.New("token was issued in the future")
)

// ValidAt checks if Claims is valid on current time.
type ValidAt struct {
	// leeway is time gap after now when token will not be expired.
	leeway time.Duration
}

// NewValidAt returns new instance of ValidAt.
func NewValidAt() *ValidAt {
	return &ValidAt{}
}

// WithLeeway setup leeway for ValidAt Constraint
func (c *ValidAt) WithLeeway(leeway time.Duration) *ValidAt {
	c.leeway = leeway

	return c
}

// Validate implements Constraint.
func (c *ValidAt) Validate(claims jwtee.RegisteredClaims) (err error) {
	now := time.Now()

	err = c.checkIssueTime(claims, now.Add(c.leeway))
	if err != nil {
		return err
	}

	err = c.checkMinimumTime(claims, now.Add(c.leeway))
	if err != nil {
		return err
	}

	err = c.checkExpiration(claims, now.Add(-c.leeway))
	if err != nil {
		return err
	}

	return nil
}

func (c *ValidAt) checkExpiration(claims jwtee.RegisteredClaims, now time.Time) error {
	if claims.IsExpired(now) {
		return ErrTokenExpired
	}

	return nil
}

func (c *ValidAt) checkMinimumTime(claims jwtee.RegisteredClaims, now time.Time) error {
	if !claims.HasBeenCrossedNotBefore(now) {
		return ErrTokenNotBefore
	}

	return nil
}

func (c *ValidAt) checkIssueTime(claims jwtee.RegisteredClaims, now time.Time) error {
	if !claims.HasBeenIssuedBefore(now) {
		return ErrTokenNotIssued
	}

	return nil
}
