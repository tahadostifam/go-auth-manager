package auth_manager

import "errors"

var (
	ErrInvalidToken            = errors.New("invalid token")
	ErrInvalidTokenType        = errors.New("invalid token type")
	ErrUnexpectedSigningMethod = errors.New("unexpected token signing method")
	ErrNotFound                = errors.New("not found")
	ErrNoExpiration            = errors.New("no expiration set for the token")
	ErrTokenExpired            = errors.New("token expired")
	ErrEncodingPayload         = errors.New("failed to encode payload to json")
	ErrDecodingPayload         = errors.New("failed to decode the payload")
)
