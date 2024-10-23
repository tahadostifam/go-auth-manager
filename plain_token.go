package auth_manager

import (
	"context"
	"encoding/json"
	"time"
)

// Used for ResetPassword, VerifyEmail, SessionBasedAuthentication, etc.
func (t *authManager) GeneratePlainToken(ctx context.Context, tokenType TokenType, payload *TokenPayload, expiresAt time.Duration) (string, error) {
	token, err := generateRandomString(TokenByteLength)
	if err != nil {
		return "", err
	}

	claimsJson, err := json.Marshal(&payload)
	if err != nil {
		return "", err
	}

	cmd := t.redisClient.Set(ctx, token, claimsJson, expiresAt)
	if cmd.Err() != nil {
		return "", cmd.Err()
	}

	return token, nil
}

func (t *authManager) DecodePlainToken(ctx context.Context, token string, tokenType TokenType) (*TokenPayload, error) {
	claimsString, err := t.redisClient.Get(ctx, token).Result()
	if err != nil {
		return nil, err
	}

	claims := &TokenPayload{}

	err = json.Unmarshal([]byte(claimsString), &claims)
	if err != nil {
		return nil, ErrInvalidToken
	}

	return claims, nil
}

// The Destroy method is simply used to remove a key from Redis Store.
func (t *authManager) DestroyPlainToken(ctx context.Context, key string) error {
	cmd := t.redisClient.Del(ctx, key)
	if cmd.Err() != nil {
		return cmd.Err()
	}

	return nil
}
