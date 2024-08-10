package auth_manager

import (
	"crypto/rand"
	"encoding/base64"
)

var randomBytesPool = make([]byte, 1024)

func generateRandomString(length int) (string, error) {
	if length > len(randomBytesPool) {
		randomBytesPool = make([]byte, length)
	}

	if _, err := rand.Read(randomBytesPool[:length]); err != nil {
		return "", err
	}

	return base64.RawStdEncoding.EncodeToString(randomBytesPool[:length]), nil
}
