package main

import (
	"context"
	"fmt"
	"log"
	"time"

	"github.com/go-redis/redis/v8"
	auth_manager "github.com/tahadostifam/go-auth-manager"
)

func main() {
	// Initialize the Redis client
	redisClient := redis.NewClient(&redis.Options{
		Addr: "localhost:6379", // Adjust Redis address if needed
		DB:   0,                // Default DB
	})

	// Initialize AuthManager with Redis client and options
	authMgr := auth_manager.NewAuthManager(redisClient, auth_manager.AuthManagerOpts{
		PrivateKey: "supersecretkey", // A simple secret for JWT signing
	})

	// --- 1. Generating a Plain Token ---
	// Create a sample payload for a plain token (e.g., email verification)
	plainTokenPayload := &auth_manager.TokenPayload{
		UUID:      "user-1234", // user UUID -> Unique ID of the user from the database or etc
		CreatedAt: time.Now(),
		TokenType: auth_manager.VerifyEmail, // Type of token (Verify Email)
	}

	plainToken, err := authMgr.GeneratePlainToken(context.Background(), auth_manager.VerifyEmail, plainTokenPayload, time.Hour)
	if err != nil {
		log.Fatalf("Error generating plain token: %v", err)
	}
	fmt.Println("Generated Plain Token:", plainToken)

	// Decode the generated plain token
	decodedPlainToken, err := authMgr.DecodePlainToken(context.Background(), plainToken, auth_manager.VerifyEmail)
	if err != nil {
		log.Fatalf("Error decoding plain token: %v", err)
	}
	fmt.Println("Decoded Plain Token Payload:", decodedPlainToken)

	// --- 2. Generating a Refresh Token ---
	refreshTokenPayload := &auth_manager.RefreshTokenPayload{
		IPAddress:  "192.168.1.1",
		UserAgent:  "Mozilla/5.0",
		LoggedInAt: time.Duration(time.Now().Unix()) * time.Second,
	}

	refreshToken, err := authMgr.GenerateRefreshToken(context.Background(), "user-1234", refreshTokenPayload, time.Hour*24)
	if err != nil {
		log.Fatalf("Error generating refresh token: %v", err)
	}
	fmt.Println("Generated Refresh Token:", refreshToken)

	// Decode the generated refresh token
	decodedRefreshToken, err := authMgr.DecodeRefreshToken(context.Background(), "user-1234", refreshToken)
	if err != nil {
		log.Fatalf("Error decoding refresh token: %v", err)
	}
	fmt.Println("Decoded Refresh Token Payload:", decodedRefreshToken)

	// --- 3. Generating an Access Token ---
	accessToken, err := authMgr.GenerateAccessToken(context.Background(), "user-1234", time.Hour)
	if err != nil {
		log.Fatalf("Error generating access token: %v", err)
	}
	fmt.Println("Generated Access Token:", accessToken)

	// Decode the generated access token
	decodedAccessToken, err := authMgr.DecodeAccessToken(context.Background(), accessToken)
	if err != nil {
		log.Fatalf("Error decoding access token: %v", err)
	}
	fmt.Println("Decoded Access Token Claims:", decodedAccessToken)

	// --- 4. Destroying Plain Tokens ---
	err = authMgr.DestroyPlainToken(context.Background(), plainToken)
	if err != nil {
		log.Fatalf("Error destroying plain token: %v", err)
	}
	fmt.Println("Plain token destroyed")

	// --- 5. Terminating All Refresh Tokens for a User ---
	err = authMgr.TerminateRefreshTokens(context.Background(), "user-1234")
	if err != nil {
		log.Fatalf("Error terminating refresh tokens: %v", err)
	}
	fmt.Println("All refresh tokens terminated for user-1234")
}
