package main

import (
	"encoding/json"
	"fmt"
	"log"
	"os"
	"time"

	"github.com/furdarius/jwtee"
	"github.com/furdarius/jwtee/constraint"
	"github.com/furdarius/jwtee/signer"
)

type myclaims struct {
	jwtee.RegisteredClaims

	Name string `json:"name"`
}

func main() {
	secret := []byte("secret_code")
	token := []byte("eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJteXNlcnZpY2UiLCJuYW1lIjoiSm9obiBEb2UiLCJpYXQiOjE1MTYyMzkwMjJ9.10i7pIGVUVloV6vrixXDhPdeq09KCdBrUzSzKZxIzLA")

	hmacSigner := signer.NewHS256()
	key := jwtee.NewSharedSecretKey(secret)
	verifier := jwtee.NewPartsVerifier(hmacSigner, key)

	jsonParser := jwtee.NewJSONParser()
	verifyingParser := jwtee.NewVerifyingParser(jsonParser, verifier)

	tokenParts, err := verifyingParser.Parse(token)

	if err == jwtee.ErrInvalidSignature {
		log.Fatal("token has invalid signature")
	}

	if err != nil {
		log.Fatalf("failed to parse JWT string: %v", err)
	}

	var claims myclaims
	err = json.Unmarshal(tokenParts.RawClaims(), &claims)
	if err != nil {
		log.Fatalf("failed to unmarshal claims: %v", err)
	}

	claimsValidator := jwtee.NewClaimsValidator()
	errs := claimsValidator.Validate(claims.RegisteredClaims,
		constraint.NewValidAt().WithLeeway(1*time.Minute),
		constraint.NewRelatedTo("myservice"),
	)
	if errs != nil {
		log.Println("claims is not valid:")
		for _, constraintErr := range errs {
			log.Println("  ", constraintErr)
		}
		os.Exit(1)
	}

	fmt.Println("Name from claims:", claims.Name)
}
