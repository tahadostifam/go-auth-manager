package auth_manager_test

import (
	"context"
	"fmt"
	auth_manager "go-auth-manager"
	"log"
	"os"
	"testing"
	"time"

	"github.com/go-redis/redis/v8"
	"github.com/google/uuid"
	"github.com/ory/dockertest/v3"
	"github.com/stretchr/testify/require"
	"github.com/stretchr/testify/suite"
)

func getRedisTestInstance(callback func(_redisClient *redis.Client)) {
	dockerContainerEnvVariables := []string{}

	err := os.Setenv("ENV", "test")
	if err != nil {
		log.Fatalf("Could not set the environment variable to test: %s", err)
	}

	pool, err := dockertest.NewPool("")
	if err != nil {
		log.Fatalf("Could not construct pool: %s", err)
	}

	var client *redis.Client

	resource, err := pool.RunWithOptions(&dockertest.RunOptions{
		Repository: "redis",
		Tag:        "latest",
		Env:        dockerContainerEnvVariables,
	})
	if err != nil {
		log.Fatalf("Could not start resource: %s", err)
	}

	// Kill the container
	defer func() {
		if err = pool.Purge(resource); err != nil {
			log.Fatalf("Could not purge resource: %s", err)
		}
	}()

	err = pool.Retry(func() error {
		ipAddr := resource.Container.NetworkSettings.IPAddress + ":6379"

		fmt.Printf("Docker redis container network ip address: %s\n", ipAddr)

		client = redis.NewClient(&redis.Options{
			Addr: ipAddr,
			DB:   0,
		})
		if err != nil {
			return err
		}

		return nil
	})
	if err != nil {
		log.Fatalf("Could not connect to Redis: %s", err)
	}

	callback(client)
}

var redisClient *redis.Client

type AuthManagerTestSuite struct {
	suite.Suite

	authManager auth_manager.AuthManager
}

func TestMain(m *testing.M) {
	getRedisTestInstance(func(_redisClient *redis.Client) {
		redisClient = _redisClient
		m.Run()
	})
}
func (s *AuthManagerTestSuite) SetupSuite() {
	s.authManager = auth_manager.NewAuthManager(redisClient, auth_manager.AuthManagerOpts{
		PrivateKey: "private-key",
	})
}

func (s *AuthManagerTestSuite) Test_GenerateAndDecodeToken() {
	// Generate
	ctx := context.TODO()
	tokenType := auth_manager.VerifyEmail
	expiration := time.Minute * 2
	payload := &auth_manager.TokenPayload{
		UUID:      uuid.NewString(),
		TokenType: tokenType,
		CreatedAt: time.Now(),
	}

	token, err := s.authManager.GenerateToken(ctx, tokenType, payload, expiration)
	require.NoError(s.T(), err)
	require.NotEmpty(s.T(), token)

	// Decode
	decoded, err := s.authManager.DecodeToken(ctx, token, tokenType)
	require.NoError(s.T(), err)
	require.Equal(s.T(), decoded.UUID, payload.UUID)
	require.Equal(s.T(), decoded.TokenType, payload.TokenType)
	require.NotEmpty(s.T(), decoded.CreatedAt)
}

func (s *AuthManagerTestSuite) Test_GenerateAndDecodeAccessToken() {
	// Generate
	ctx := context.TODO()
	uuid := uuid.NewString()
	expiration := time.Minute * 2

	token, err := s.authManager.GenerateAccessToken(ctx, uuid, expiration)
	require.NoError(s.T(), err)
	require.NotEmpty(s.T(), token)

	// Decode
	decoded, err := s.authManager.DecodeAccessToken(ctx, token)
	require.NoError(s.T(), err)
	require.Equal(s.T(), decoded.Payload.UUID, uuid)
	require.Equal(s.T(), decoded.Payload.TokenType, auth_manager.AccessToken)
	require.NotEmpty(s.T(), decoded.Payload.CreatedAt)
}

func (s *AuthManagerTestSuite) Test_RefreshToken() {
	// Generate
	ctx := context.TODO()
	uuid := uuid.NewString()
	expiration := time.Minute * 2
	payload := &auth_manager.RefreshTokenPayload{
		IPAddress:  "ip-address",
		UserAgent:  "user-agent",
		LoggedInAt: time.Duration(time.Now().UnixMilli()),
	}

	token, err := s.authManager.GenerateRefreshToken(ctx, uuid, payload, expiration)
	require.NoError(s.T(), err)
	require.NotEmpty(s.T(), token)

	// Decode
	decoded, err := s.authManager.DecodeRefreshToken(ctx, uuid, token)
	require.NoError(s.T(), err)
	require.Equal(s.T(), decoded.IPAddress, payload.IPAddress)
	require.Equal(s.T(), decoded.UserAgent, payload.UserAgent)
	require.NotEmpty(s.T(), decoded.LoggedInAt)

	// Remove
	err = s.authManager.RemoveRefreshToken(ctx, uuid, token)
	require.NoError(s.T(), err)

	// Terminates
	err = s.authManager.TerminateRefreshTokens(ctx, uuid)
	require.NoError(s.T(), err)
}

func TestAuthManagerTestSuite(t *testing.T) {
	suite.Run(t, new(AuthManagerTestSuite))
}
