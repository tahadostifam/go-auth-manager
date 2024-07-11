package auth_manager

import (
	"context"
	"encoding/json"
	"errors"
	"time"

	"github.com/go-redis/redis/v8"
	"github.com/golang-jwt/jwt/v4"
)

const TokenByteLength = 32

var (
	ErrInvalidToken            = errors.New("invalid token")
	ErrInvalidTokenType        = errors.New("invalid token type")
	ErrUnexpectedSigningMethod = errors.New("unexpected token signing method")
	ErrNotFound                = errors.New("not found")
)

var TokenEncodingAlgorithm = jwt.SigningMethodHS512

type TokenType int

const (
	ResetPassword TokenType = iota
	VerifyEmail
	AccessToken
	RefreshToken
)

type AuthManager interface {
	GenerateAccessToken(ctx context.Context, uuid string, expr time.Duration) (string, error)
	DecodeAccessToken(ctx context.Context, token string) (*AccessTokenClaims, error)
	GenerateRefreshToken(ctx context.Context, uuid string, payload *RefreshTokenPayload, expr time.Duration) (string, error)
	TerminateRefreshTokens(ctx context.Context, uuid string) error
	RemoveRefreshToken(ctx context.Context, uuid string, token string) error
	DecodeRefreshToken(ctx context.Context, uuid string, token string) (*RefreshTokenPayload, error)
	GenerateToken(ctx context.Context, tokenType TokenType, payload *TokenPayload, expr time.Duration) (string, error)
	DecodeToken(ctx context.Context, token string, tokenType TokenType) (*TokenPayload, error)
	DestroyToken(ctx context.Context, key string) error
}

type AuthManagerOpts struct {
	PrivateKey string
}

// Used as jwt claims
type TokenPayload struct {
	UUID      string    `json:"uuid"`
	CreatedAt time.Time `json:"createdAt"`
	TokenType TokenType `json:"tokenType"`
}

type authManager struct {
	redisClient *redis.Client
	opts        AuthManagerOpts
}

func NewAuthManager(redisClient *redis.Client, opts AuthManagerOpts) AuthManager {
	return &authManager{redisClient, opts}
}

// The GenerateToken method generates a JWT based on the
// provided token claims and stores it in Redis Store with a specified expiration duration.
//
// Never use this method generate access or refresh token!
// There are other methods to achieve this goal.
// Use this method for example for [ResetPassword, VerifyEmail] tokens...
func (t *authManager) GenerateToken(ctx context.Context, tokenType TokenType, payload *TokenPayload, expr time.Duration) (string, error) {
	token, err := generateRandomString(TokenByteLength)
	if err != nil {
		return "", err
	}

	claimsJson, err := json.Marshal(&payload)
	if err != nil {
		return "", err
	}

	cmd := t.redisClient.Set(ctx, token, claimsJson, expr)
	if cmd.Err() != nil {
		return "", cmd.Err()
	}

	return token, nil
}

// The DecodeToken method finds the JWT token in Redis Store and then try to decode token and if it as valid then
// returns an instance of *TokenClaims that contains the payload of the token.
//
// Token type is required for validation!
//
// Never use this method for access and refresh token, they have their own decode methods!
func (t *authManager) DecodeToken(ctx context.Context, token string, tokenType TokenType) (*TokenPayload, error) {
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
func (t *authManager) DestroyToken(ctx context.Context, key string) error {
	cmd := t.redisClient.Del(ctx, key)
	if cmd.Err() != nil {
		return cmd.Err()
	}

	return nil
}
