# JWTee
[![GoDoc](https://godoc.org/github.com/furdarius/jwtee?status.svg)](https://godoc.org/github.com/furdarius/jwtee)
[![Build Status](https://travis-ci.org/furdarius/jwtee.svg?branch=master)](https://travis-ci.org/furdarius/jwtee)
[![Go Report Card](https://goreportcard.com/badge/github.com/furdarius/jwtee)](https://goreportcard.com/report/github.com/furdarius/jwtee)

Fast and flexible library to work with JSON Web Token and JSON Web Signature in Go based on the [RFC 7519](https://tools.ietf.org/html/rfc7519).

The purpose of the library is to use full power of strong typing when working with JWT.

## Installation
```
go get github.com/furdarius/jwtee
```

### Adding as dependency by "go dep"
```
$ dep ensure -add github.com/furdarius/jwtee
```

## Usage

### Parsing and Verifying

Define own claims, embedding RegisteredClaims:
```go
type myclaims struct {
	jwtee.RegisteredClaims

	Name string `json:"name"`
}
```

Parse and verify token and claims:
```go
hmacSigner := signer.NewHS256()
key := jwtee.NewSharedSecretKey(secret)
verifier := jwtee.NewPartsVerifier(hmacSigner, key)
jsonParser := jwtee.NewJSONParser()
verifyingParser := jwtee.NewVerifyingParser(jsonParser, verifier)
claimsValidator := jwtee.NewClaimsValidator()

secret := []byte("secret_code")
token := []byte("eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJteXNlcnZpY2UiLCJuYW1lIjoiSm9obiBEb2UiLCJpYXQiOjE1MTYyMzkwMjJ9.10i7pIGVUVloV6vrixXDhPdeq09KCdBrUzSzKZxIzLA")

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
```

### Token building

Define own claims, embedding RegisteredClaims and implements encoding.BinaryMarshaler:
```go
type myclaims struct {
	jwtee.RegisteredClaims

	Name  string `json:"name"`
	Admin bool   `json:"admin"`
}

// MarshalBinary implements encoding.BinaryMarshaler.
func (c myclaims) MarshalBinary() (data []byte, err error) {
	return json.Marshal(c)
}
```

Build token from claims:
```go
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
```

[More examples](https://github.com/furdarius/jwtee/blob/master/examples)

## Contributing

Pull requests are very much welcomed. Make sure a test or example is included that covers your change and
your commits represent coherent changes that include a reason for the change.

Use `gometalinter` to check code with linters:
```
gometalinter -t --vendor ./...
```
