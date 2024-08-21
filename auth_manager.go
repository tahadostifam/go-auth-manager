package auth_manager

import (
	"context"
	"encoding/json"
	"errors"
	"strconv"
	"time"

	"github.com/go-redis/redis/v8"
)

const TokenByteLength = 32

var (
	ErrInvalidToken            = errors.New("invalid token")
	ErrInvalidTokenType        = errors.New("invalid token type")
	ErrUnexpectedSigningMethod = errors.New("unexpected token signing method")
	ErrNotFound                = errors.New("not found")
	ErrNoExpiration            = errors.New("no expiration set for the token")
	ErrTokenExpired            = errors.New("token expired")
	ErrCodeIsInValid = errors.New("code is invalid") 
)

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
	GenerateToken(ctx context.Context, tokenType TokenType, payload *TokenPayload, expiresAt time.Duration) (string, error)
	DecodeToken(ctx context.Context, token string, tokenType TokenType) (*TokenPayload, error)
	DestroyToken(ctx context.Context, key string) error
	GenerateVerificationCode(ctx context.Context, key string, codeLengths int, expiresAt time.Duration)( string,error)
	CompareVerificationCode(ctx context.Context, key, code string) (bool, error)
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
func (t *authManager) GenerateToken(ctx context.Context, tokenType TokenType, payload *TokenPayload, expiresAt time.Duration) (string, error) {
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

// The GenerateVerificationCode method stores a verification code with expire time in Redis.
func (t *authManager) GenerateVerificationCode(ctx context.Context, key string, codeLengths int, expiresAt time.Duration)( string,error ){
	code := generateRandomNumber(codeLengths)

	_, err := t.redisClient.Set(ctx, key, code, expiresAt).Result()
	if err != nil {
		return "",err
	}

	return strconv.Itoa(code),nil
}

// The CompareVerificationCode method compare input code with stored code in Redis.
func (t *authManager) CompareVerificationCode(ctx context.Context, key, code string) (bool, error) {
	storedCode , err := t.redisClient.Get(ctx,key).Result()
	if err != nil{
		return false,err
	}

	if storedCode != code {
		return false,ErrCodeIsInValid
	}  

	return true,nil
}

