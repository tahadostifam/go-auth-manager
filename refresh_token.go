package auth_manager

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
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
	var list []refreshTokenRaw
	key := refreshTokenKey(uuid)

	cmd := t.redisClient.Get(ctx, key)
	if cmd.Err() != nil {
		// This is first time user logs in and we need to
		// create a refresh token list for user...
		list = []refreshTokenRaw{}
	}

	err := json.Unmarshal([]byte(cmd.Val()), &list)
	if err != nil {
		list = []refreshTokenRaw{}
	}

	// Generate random string
	refreshToken, err := generateRandomString(refreshTokenByteLength)
	if err != nil {
		return "", err
	}

	list = append(list, refreshTokenRaw{
		RefreshToken: refreshToken,
		Payload:      *payload,
	})

	jsonRaw, err := json.Marshal(list)
	if err != nil {
		return "", err
	}

	err = t.redisClient.Set(ctx, key, jsonRaw, expr).Err()
	if err != nil {
		return "", err
	}

	return refreshToken, nil
}

func (t *authManager) DecodeRefreshToken(ctx context.Context, uuid string, token string) (*RefreshTokenPayload, error) {
	var list []refreshTokenRaw
	key := refreshTokenKey(uuid)

	cmd := t.redisClient.Get(ctx, key)
	if cmd.Err() != nil {
		// This is first time user logs in and we need to
		// create a list for user...
		list = []refreshTokenRaw{}
	}

	err := json.Unmarshal([]byte(cmd.Val()), &list)
	if err != nil {
		list = []refreshTokenRaw{}
	}

	var raw *refreshTokenRaw

	for _, v := range list {
		if strings.TrimSpace(v.RefreshToken) == strings.TrimSpace(token) {
			raw = &v
		}
	}

	if raw == nil {
		return nil, ErrInvalidToken
	}

	return &raw.Payload, nil
}

func (t *authManager) TerminateRefreshTokens(ctx context.Context, uuid string) error {
	return t.DestroyToken(ctx, refreshTokenKey(uuid))
}

func (t *authManager) RemoveRefreshToken(ctx context.Context, uuid string, token string) error {
	var list []refreshTokenRaw
	key := refreshTokenKey(uuid)

	cmd := t.redisClient.Get(ctx, key)
	if cmd.Err() != nil {
		// This is first time user logs in and we need to
		// create a refresh token list for user...
		list = []refreshTokenRaw{}
	}

	err := json.Unmarshal([]byte(cmd.Val()), &list)
	if err != nil {
		list = []refreshTokenRaw{}
	}

	rawIndex := -1

	for i, v := range list {
		if strings.TrimSpace(v.RefreshToken) == strings.TrimSpace(token) {
			rawIndex = i
		}
	}

	if rawIndex == -1 {
		return ErrInvalidToken
	}

	// Remove raw from list
	list = append(list[:rawIndex], list[rawIndex+1:]...)

	jsonRaw, err := json.Marshal(list)
	if err != nil {
		return err
	}

	err = t.redisClient.GetSet(ctx, key, jsonRaw).Err()
	if err != nil {
		return err
	}

	return nil
}
