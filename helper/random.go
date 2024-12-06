package helper

import (
	"math/rand"
	"time"
)

const RandomStringCharset = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
const RandomStringNumCharset = "0123456789"

var seededRand *rand.Rand = rand.New(rand.NewSource(time.Now().UnixNano()))

func generateRandomString(charset string, length int) string {
	b := make([]byte, length)
	for i := range b {
		b[i] = charset[seededRand.Intn(len(charset))]
	}
	return string(b)
}

func RandomString(length int) string {
	return generateRandomString(RandomStringCharset, length)
}

func RandomNumericCode(length int) string {
	return generateRandomString(RandomStringNumCharset, length)
}
