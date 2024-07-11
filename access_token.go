package auth_manager

import (
	"context"
	"time"

	"github.com/golang-jwt/jwt/v4"
)

// The GenerateAccessToken method is used to generate Stateless JWT Token.
// Notice that access tokens are not store at Redis Store and they are stateless!
func (t *authManager) GenerateAccessToken(ctx context.Context, uuid string, expr time.Duration) (string, error) {
	claims := TokenClaims{
		UUID:      uuid,
		TokenType: AccessToken,
		CreatedAt: time.Now(),
	}
	jwtToken, err := jwt.NewWithClaims(TokenEncodingAlgorithm, claims).SignedString([]byte(t.opts.PrivateKey))
	if err != nil {
		return "", nil
	}

	return jwtToken, nil
}

// The GenerateAccessToken method is used to generate Stateless JWT Token.
// Notice that access tokens are not store at Redis Store and they are stateless!
func (t *authManager) DecodeAccessToken(ctx context.Context, token string) (bool, error) {
	claims := &TokenClaims{}
	jwtToken, err := jwt.ParseWithClaims(token, claims,
		func(token *jwt.Token) (interface{}, error) {
			if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
				return nil, ErrUnexpectedSigningMethod
			}

			return []byte(t.opts.PrivateKey), nil
		},
	)
	if err != nil {
		return false, ErrInvalidToken
	}

	if jwtToken.Valid {
		if claims.TokenType != AccessToken {
			return false, ErrInvalidTokenType
		}

		return true, nil
	}

	return false, ErrInvalidToken
}
