package rsa

import (
	"crypto/rand"
	"math/big"
)

func GenerateLargePrime(bits int) (*big.Int, error) {
	// Generate a random number of the specified bit length.
	for {
		num, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), uint(bits)))

		if err != nil {
			return nil, err
		}

		num.Add(num, new(big.Int).Lsh(big.NewInt(1), uint(bits-1)))

		if num.ProbablyPrime(10) {
			return num, nil
		}
	}
}
