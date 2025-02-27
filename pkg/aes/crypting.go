package aes

import (
	"encoding/hex"
	"errors"
	"fmt"
	"math/big"
)

func Encrypt(message string, publicKey, N *big.Int) (string, error) {
	messageNumber := stringToBigInt(message)

	// If message converted to int is bigger than N, it cannot be encrypted.
	if messageNumber.Cmp(N) >= 0 {
		return "", errors.New(fmt.Sprintf("Message \"%s\" cannot be encrypted with the given bit size.", message))
	}

	// Perform messageNumber ^ publicKey % N (RSA encryption).
	cipherText := new(big.Int).Exp(messageNumber, publicKey, N)

	return hex.EncodeToString(cipherText.Bytes()), nil
}

func Decrypt(cipherText string, privateKey, N *big.Int) (string, error) {
	cipherTextBytes, err := hex.DecodeString(cipherText)

	if err != nil {
		return "", err
	}

	cipherTextNumber := new(big.Int).SetBytes(cipherTextBytes)

	// Perform cipherTextNumber ^ privateKey % N (RSA decryption).
	message := new(big.Int).Exp(cipherTextNumber, privateKey, N)

	return bigIntToString(message), nil
}
