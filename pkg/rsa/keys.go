package rsa

import (
	"errors"
	"fmt"
	"math/big"
)

type RSAKeys struct {
	PublicKey  *big.Int
	PrivateKey *big.Int
	N          *big.Int
}

type PrimeNumbers struct {
	p   *big.Int
	q   *big.Int
	n   *big.Int
	phi *big.Int
}

func GeneratePrimes(bitSize int) (PrimeNumbers, error) {
	// Generating big prime numbers.
	p, err := GenerateLargePrime(bitSize)

	if err != nil {
		return PrimeNumbers{}, errors.New(fmt.Sprintf("Failed to generate prime number of %d bit.", bitSize))
	}

	q, err := GenerateLargePrime(bitSize)

	if err != nil {
		return PrimeNumbers{}, errors.New(fmt.Sprintf("Failed to generate prime number of %d bit.", bitSize))
	}

	var n, phi = new(big.Int), new(big.Int)

	// Calculates N (p*q).
	n.Mul(p, q)

	// Calculates phi (p-1)*(q-1).
	phi.Mul(new(big.Int).Sub(p, big.NewInt(1)), new(big.Int).Sub(q, big.NewInt(1)))

	return PrimeNumbers{p, phi, n, phi}, nil
}

func GenerateKeys(bitSize int) (*RSAKeys, error) {
	primes, err := GeneratePrimes(bitSize)

	if err != nil {
		return &RSAKeys{}, err
	}

	encrypt := big.NewInt(65537)

	decrypt, err := inverse(encrypt, primes.phi)

	if err != nil {
		return &RSAKeys{}, err
	}

	return &RSAKeys{PublicKey: encrypt, PrivateKey: decrypt, N: primes.n}, nil
}
