package auth_manager

import (
	"context"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

var TokenEncodingAlgorithm = jwt.SigningMethodHS512

type AccessTokenClaims struct {
	Payload TokenPayload
	jwt.RegisteredClaims
}

// The GenerateAccessToken method is used to generate Stateless JWT Token.
// Notice that access tokens are not store at Redis Store and they are stateless!
func (t *authManager) GenerateAccessToken(ctx context.Context, uuid string, expiresAt time.Duration) (string, error) {
	now := time.Now()

	claims := AccessTokenClaims{
		Payload: TokenPayload{
			UUID:      uuid,
			TokenType: AccessToken,
			CreatedAt: time.Now(),
		},
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(now.Add(expiresAt)),
			Issuer:    "go-auth-manager",
		},
	}
	jwtToken, err := jwt.NewWithClaims(TokenEncodingAlgorithm, claims).SignedString([]byte(t.opts.PrivateKey))
	if err != nil {
		return "", err
	}

	return jwtToken, nil
}

// DecodeAccessToken parses and validates an access token (JWT) and returns its claims.
// It performs the following checks:
// 1. Verifies the token signature using the provided private key.
// 2. Checks the token's expiration time to ensure it is still valid.
// 3. Validates that the token type is specifically an AccessToken.
//
// If any of these checks fail, an appropriate error is returned.
// If the token is valid, the function returns the decoded AccessTokenClaims.
//
// Parameters:
//   - ctx: The context for the operation (typically used for request cancellation).
//   - token: The JWT access token to be decoded and validated.
//
// Returns:
//   - *AccessTokenClaims: The claims embedded in the token, if valid.
//   - error: Any error encountered during decoding or validation (e.g., invalid token, expired token).
func (t *authManager) DecodeAccessToken(ctx context.Context, token string) (*AccessTokenClaims, error) {
	claims := &AccessTokenClaims{}
	jwtToken, err := jwt.ParseWithClaims(token, claims,
		func(token *jwt.Token) (interface{}, error) {
			if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
				return nil, ErrUnexpectedSigningMethod
			}

			return []byte(t.opts.PrivateKey), nil
		},
	)
	if err != nil {
		return nil, ErrInvalidToken
	}

	expr, err := jwtToken.Claims.GetExpirationTime()
	if err != nil || expr == nil {
		return nil, ErrNoExpiration
	}

	now := time.Now()

	if expr.Time.Before(now) {
		return nil, ErrTokenExpired
	}

	if jwtToken.Valid {
		if claims.Payload.TokenType != AccessToken {
			return nil, ErrInvalidTokenType
		}

		return claims, nil
	}

	return nil, ErrInvalidToken
}
