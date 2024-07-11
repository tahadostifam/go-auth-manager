package auth_manager

import (
	"context"
	"encoding/json"
	"fmt"
	"time"
)

const refreshTokenByteLength = 32

type RefreshTokenPayload struct {
	IPAddress  string        `json:"ipAddress"`
	UserAgent  string        `json:"userAgent"`
	LoggedInAt time.Duration `json:"loggedInAt"`
}

type refreshTokenRaw struct {
	RefreshToken string              `json:"refreshToken"`
	Payload      RefreshTokenPayload `json:"payload"`
}

func refreshTokenKey(uuid string) string {
	return fmt.Sprintf("RefreshTokenRaw_%s", uuid)
}

// The GenerateToken method generates a random string with base64 with a static byte length
// and stores it in the Redis store with provided expiration duration.
func (t *authManager) GenerateRefreshToken(ctx context.Context, uuid string, payload *RefreshTokenPayload, expr time.Duration) (string, error) {
	var raw []refreshTokenRaw
	key := refreshTokenKey(uuid)

	cmd := t.redisClient.Get(ctx, key)
	if cmd.Err() != nil {
		// This is first time user logs in and we need to
		// create a raw for user...
		raw = []refreshTokenRaw{}
	}

	err := json.Unmarshal([]byte(cmd.Val()), &raw)
	if err != nil {
		raw = []refreshTokenRaw{}
	}

	// Generate random string
	refreshToken, err := generateRandomString(refreshTokenByteLength)
	if err != nil {
		return "", err
	}

	raw = append(raw, refreshTokenRaw{
		RefreshToken: refreshToken,
		Payload:      *payload,
	})

	jsonRaw, err := json.Marshal(raw)
	if err != nil {
		return "", err
	}

	err = t.redisClient.Set(ctx, key, jsonRaw, expr).Err()
	if err != nil {
		return "", err
	}

	return refreshToken, nil
}

func (t *authManager) DecodeRefreshToken(ctx context.Context, uuid string, payload *RefreshTokenPayload, expr time.Duration) (string, error) {
	return "", nil
}
