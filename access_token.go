package auth_manager

import (
	"context"
	"time"

	"github.com/golang-jwt/jwt/v4"
)

type AccessTokenClaims struct {
	Payload TokenPayload
	jwt.StandardClaims
}

// The GenerateAccessToken method is used to generate Stateless JWT Token.
// Notice that access tokens are not store at Redis Store and they are stateless!
func (t *authManager) GenerateAccessToken(ctx context.Context, uuid string, expr time.Duration) (string, error) {
	claims := AccessTokenClaims{
		Payload: TokenPayload{
			UUID:      uuid,
			TokenType: AccessToken,
			CreatedAt: time.Now(),
		},
	}
	jwtToken, err := jwt.NewWithClaims(TokenEncodingAlgorithm, claims).SignedString([]byte(t.opts.PrivateKey))
	if err != nil {
		return "", nil
	}

	return jwtToken, nil
}

// The GenerateAccessToken method is used to generate Stateless JWT Token.
// Notice that access tokens are not store at Redis Store and they are stateless!
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

	if jwtToken.Valid {
		if claims.Payload.TokenType != AccessToken {
			return nil, ErrInvalidTokenType
		}

		return claims, nil
	}

	return nil, ErrInvalidToken
}
