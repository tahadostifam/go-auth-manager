package auth_manager

import (
	"context"
	"time"

	"github.com/go-redis/redis/v8"
)

const TokenByteLength = 32

type TokenType int

const (
	ResetPassword TokenType = iota
	VerifyEmail
	AccessToken
	RefreshToken
)

type AuthManager interface {
	GenerateAccessToken(ctx context.Context, uuid string, expiresAt time.Duration) (string, error)
	DecodeAccessToken(ctx context.Context, token string) (*AccessTokenClaims, error)
	GenerateRefreshToken(ctx context.Context, uuid string, payload *RefreshTokenPayload, expiresAt time.Duration) (string, error)
	TerminateRefreshTokens(ctx context.Context, uuid string) error
	RemoveRefreshToken(ctx context.Context, uuid string, token string) error
	DecodeRefreshToken(ctx context.Context, uuid string, token string) (*RefreshTokenPayload, error)
	GeneratePlainToken(ctx context.Context, tokenType TokenType, payload *TokenPayload, expiresAt time.Duration) (string, error)
	DecodePlainToken(ctx context.Context, token string, tokenType TokenType) (*TokenPayload, error)
	DestroyPlainToken(ctx context.Context, key string) error
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
