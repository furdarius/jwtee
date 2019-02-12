package jwtee

import (
	"time"
)

// RegisteredClaims are the IANA registered “JSON Web Token Claims”.
type RegisteredClaims struct {
	//   The "aud" (audience) claim identifies the recipients that the JWT is
	//   intended for.  Each principal intended to process the JWT MUST
	//   identify itself with a value in the audience claim.  If the principal
	//   processing the claim does not identify itself with a value in the
	//   "aud" claim when this claim is present, then the JWT MUST be
	//   rejected.  In the general case, the "aud" value is an array of case-
	//   sensitive strings, each containing a StringOrURI value.  In the
	//   special case when the JWT has one audience, the "aud" value MAY be a
	//   single case-sensitive string containing a StringOrURI value.  The
	//   interpretation of audience values is generally application specific.
	Aud []string `json:"aud,omitempty"`

	//   The "exp" (expiration time) claim identifies the expiration time on
	//   or after which the JWT MUST NOT be accepted for processing.  The
	//   processing of the "exp" claim requires that the current date/time
	//   MUST be before the expiration date/time listed in the "exp" claim.
	//   Implementers MAY provide for some small leeway, usually no more than
	//   a few minutes, to account for clock skew.  Its value MUST be a number
	//   containing a NumericDate value.  Use of this claim is OPTIONAL.
	Exp Timestamp `json:"exp,omitempty"`

	//   The "jti" (JWT ID) claim provides a unique identifier for the JWT.
	//   The identifier value MUST be assigned in a manner that ensures that
	//   there is a negligible probability that the same value will be
	//   accidentally assigned to a different data object; if the application
	//   uses multiple issuers, collisions MUST be prevented among values
	//   produced by different issuers as well.  The "jti" claim can be used
	//   to prevent the JWT from being replayed.  The "jti" value is a case-
	//   sensitive string.  Use of this claim is OPTIONAL.
	Jti string `json:"jti,omitempty"`

	//   The "iat" (issued at) claim identifies the time at which the JWT was
	//   issued.  This claim can be used to determine the age of the JWT.  Its
	//   value MUST be a number containing a NumericDate value.  Use of this
	//   claim is OPTIONAL.
	Iat Timestamp `json:"iat,omitempty"`

	//   The "iss" (issuer) claim identifies the principal that issued the
	//   JWT.  The processing of this claim is generally application specific.
	//   The "iss" value is a case-sensitive string containing a StringOrURI
	//   value.  Use of this claim is OPTIONAL.
	Iss string `json:"iss,omitempty"`

	//   The "nbf" (not before) claim identifies the time before which the JWT
	//   MUST NOT be accepted for processing.  The processing of the "nbf"
	//   claim requires that the current date/time MUST be after or equal to
	//   the not-before date/time listed in the "nbf" claim.  Implementers MAY
	//   provide for some small leeway, usually no more than a few minutes, to
	//   account for clock skew.  Its value MUST be a number containing a
	//   NumericDate value.  Use of this claim is OPTIONAL.
	Nbf Timestamp `json:"nbf,omitempty"`

	//   The "sub" (subject) claim identifies the principal that is the
	//   subject of the JWT.  The claims in a JWT are normally statements
	//   about the subject.  The subject value MUST either be scoped to be
	//   locally unique in the context of the issuer or be globally unique.
	//   The processing of this claim is generally application specific.  The
	//   "sub" value is a case-sensitive string containing a StringOrURI
	//   value.  Use of this claim is OPTIONAL.
	Sub string `json:"sub,omitempty"`
}

// IsPermittedFor returns true if claims is allowed to be used by the audience.
func (c RegisteredClaims) IsPermittedFor(audience string) bool {
	for _, tokenAudience := range c.Aud {
		if tokenAudience == audience {
			return true
		}
	}

	return false
}

// IsIdentifiedBy returns true if claims has the given id.
func (c RegisteredClaims) IsIdentifiedBy(id string) bool {
	return c.Jti == id
}

// IsRelatedTo returns true if claims has the given subject.
func (c RegisteredClaims) IsRelatedTo(subject string) bool {
	return c.Sub == subject
}

// HasBeenIssuedBy returns true if the token was issued by any of given issuers.
func (c RegisteredClaims) HasBeenIssuedBy(issuers ...string) bool {
	for _, issuer := range issuers {
		if c.Iss == issuer {
			return true
		}
	}

	return false
}

// HasBeenIssuedBefore returns true if the token was issued before of given time.
func (c RegisteredClaims) HasBeenIssuedBefore(now time.Time) bool {
	issuedAt := c.Iat.Time()

	if issuedAt.IsZero() {
		return false
	}

	return issuedAt.Before(now)
}

// HasBeenCrossedNotBefore returns true if the token activation (Not Before) time is before than given time.
func (c RegisteredClaims) HasBeenCrossedNotBefore(now time.Time) bool {
	notBefore := c.Nbf.Time()

	if notBefore.IsZero() {
		return true
	}

	return notBefore.Before(now)
}

// IsExpired returns true if the token is expired.
func (c RegisteredClaims) IsExpired(now time.Time) bool {
	expireAt := c.Exp.Time()

	if expireAt.IsZero() {
		return false
	}

	return expireAt.Before(now)
}
