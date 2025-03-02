package aes

import (
	"errors"
	"math/rand"
	"time"
)

func GenerateRandomKey(keySizeBits int) ([]byte, error) {
	if keySizeBits != 128 && keySizeBits != 192 && keySizeBits != 256 {
		return nil, errors.New("invalid key size; must be 128, 192, or 256 bits")
	}
	keySizeBytes := keySizeBits / 8
	key := make([]byte, keySizeBytes)

	// Create a new local random generator with a seed based on the current time.
	r := rand.New(rand.NewSource(time.Now().UnixNano()))

	for i := 0; i < keySizeBytes; i++ {
		key[i] = byte(r.Intn(256))
	}
	return key, nil
}
