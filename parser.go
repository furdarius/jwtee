package jwtee

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"github.com/pkg/errors"
)

const sep byte = '.'

var (
	// ErrPartMissed indicates that token has invalid format
	ErrPartMissed = errors.New("one of token parts missed")
)

// Parser used to take JWT apart.
type Parser interface {
	Parse(jwt json.RawMessage) (*DecodedParts, error)
}

// JSONParser used to parse JWT token.
type JSONParser struct{}

// NewJSONParser returns new instance of JSONParser.
func NewJSONParser() *JSONParser {
	return &JSONParser{}
}

// Parse splits, decode and memoize JWT parts.
func (p *JSONParser) Parse(jwt json.RawMessage) (*DecodedParts, error) {
	firstDot := bytes.IndexByte(jwt, sep)
	lastDot := bytes.LastIndexByte(jwt, sep)

	if lastDot <= firstDot {
		return nil, ErrPartMissed
	}

	decoded := make([]byte, len(jwt))

	headerN, err := base64.RawURLEncoding.Decode(decoded, jwt[:firstDot])
	if err != nil {
		return nil, errors.New("failed to decode header from base64url: " + err.Error())
	}

	claimsN, err := base64.RawURLEncoding.Decode(decoded[headerN:], jwt[firstDot+1:lastDot])
	if err != nil {
		return nil, errors.New("failed to decode claims from base64url: " + err.Error())
	}

	signatureN, err := base64.RawURLEncoding.Decode(decoded[headerN+claimsN:], jwt[lastDot+1:])
	if err != nil {
		return nil, errors.New("failed to decode signature from base64url: " + err.Error())
	}

	var h Header
	err = json.Unmarshal(decoded[:headerN], &h)
	if err != nil {
		return nil, errors.New("failed to unmarshal header: " + err.Error())
	}

	t := &DecodedParts{
		raw:       jwt,
		header:    h,
		claims:    decoded[headerN : headerN+claimsN],
		payload:   jwt[:lastDot],
		signature: decoded[headerN+claimsN : headerN+claimsN+signatureN],
	}

	return t, nil
}

// VerifyingParser used to parse and then verify JWT.
type VerifyingParser struct {
	Parser

	verifier *PartsVerifier
}

// NewVerifyingParser returns new instance of VerifyingParser.
func NewVerifyingParser(parser Parser, verifier *PartsVerifier) *VerifyingParser {
	return &VerifyingParser{parser, verifier}
}

// Parse splits, decode, memoize and verify signature of JWT parts.
// If token signature is invalid then ErrInvalidSignature returns.
func (p *VerifyingParser) Parse(jwt json.RawMessage) (*DecodedParts, error) {
	parts, err := p.Parser.Parse(jwt)
	if err != nil {
		return nil, err
	}

	err = p.verifier.Verify(parts)
	if err != nil {
		return nil, err
	}

	return parts, nil
}
