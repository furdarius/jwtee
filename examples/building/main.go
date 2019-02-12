package main

import (
	"encoding/json"
	"fmt"
	"github.com/furdarius/jwtee"
	"github.com/furdarius/jwtee/signer"
	"log"
)

type myclaims struct {
	jwtee.RegisteredClaims

	Name  string `json:"name"`
	Admin bool   `json:"admin"`
}

// MarshalBinary implements encoding.BinaryMarshaler.
func (c myclaims) MarshalBinary() (data []byte, err error) {
	return json.Marshal(c)
}

func main() {
	secret := []byte("secret_code")

	hmacSigner := signer.NewHS256()
	key := jwtee.NewSharedSecretKey(secret)
	builder := jwtee.NewBuilder()

	claims := myclaims{
		RegisteredClaims: jwtee.RegisteredClaims{
			Sub: "1234567890",
			Iat: 1516239022,
		},
		Name:  "John Doe",
		Admin: true,
	}

	rawJWT, err := builder.Build(claims, hmacSigner, key)
	if err != nil {
		log.Fatalf("failed to build jwt: %v", err)
	}

	fmt.Println(string(rawJWT))
}
