package auth_manager

import (
	"crypto/rand"
	"encoding/base64"
	"math"
	"math/big"
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

func generateRandomNumber(length int) int {
	min := int64(math.Pow(10, float64(length)-1))
	max := int64(math.Pow(10, float64(length))) - 1

	randomNumber, err := rand.Int(rand.Reader, big.NewInt(max-min))
	if err != nil {
		panic(err)
	}

	number := int(randomNumber.Int64()) + int(min)

	return number
}
