package auth_manager

import (
	"context"
	"encoding/json"
	"fmt"
	"time"
)

const refreshTokenByteLength = 32

func generateHashKey(uuid string) string {
	return fmt.Sprintf("refresh_token:%s", uuid)
}

type RefreshTokenPayload struct {
	IPAddress  string        `json:"ipAddress"`
	UserAgent  string        `json:"userAgent"`
	LoggedInAt time.Duration `json:"loggedInAt"`
}

// The GenerateRefreshToken method generates a random string with base64 with a static byte length
// and stores it in the Redis store with provided expiration duration.
func (t *authManager) GenerateRefreshToken(ctx context.Context, uuid string, payload *RefreshTokenPayload, expiresAt time.Duration) (string, error) {
	// Generate random string
	refreshToken, err := generateRandomString(refreshTokenByteLength)
	if err != nil {
		return "", err
	}

	payloadJson, err := json.Marshal(payload)
	if err != nil {
		return "", ErrEncodingPayload
	}

	err = t.redisClient.HSet(ctx, generateHashKey(uuid), []string{
		refreshToken, string(payloadJson),
	}).Err()
	if err != nil {
		return "", err
	}

	return refreshToken, nil
}

func (t *authManager) DecodeRefreshToken(ctx context.Context, uuid string, token string) (*RefreshTokenPayload, error) {
	payloadStr, err := t.redisClient.HGet(ctx, generateHashKey(uuid), token).Result()
	if err != nil {
		return nil, ErrInvalidToken
	}

	var payload *RefreshTokenPayload

	err = json.Unmarshal([]byte(payloadStr), &payload)
	if err != nil {
		return nil, ErrInvalidToken
	}

	return payload, nil
}

func (t *authManager) TerminateRefreshTokens(ctx context.Context, uuid string) error {
	return t.redisClient.Del(ctx, generateHashKey(uuid)).Err()
}

func (t *authManager) RemoveRefreshToken(ctx context.Context, uuid string, token string) error {
	return t.redisClient.HDel(ctx, generateHashKey(uuid), token).Err()
}
