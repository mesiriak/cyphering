package rsa

import (
	"encoding/hex"
	"errors"
	"fmt"
	"math/big"
	"strconv"
)

func Encrypt(message string, publicKey, N *big.Int) (string, error) {
	messageNumber := stringToBigInt(message)

	// If message converted to int is bigger than N, it cannot be encrypted.
	if messageNumber.Cmp(N) >= 0 {
		return "", errors.New(fmt.Sprintf("Message \"%s\" is too large for encryption with the given modulus N", message))
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

func EncryptStruct(json interface{}, publicKey, N *big.Int) (interface{}, error) {
	switch v := json.(type) {
	case string:
		return Encrypt(v, publicKey, N)
	case int:
		return Encrypt(strconv.Itoa(v), publicKey, N)
	case float64:
		return Encrypt(strconv.FormatFloat(v, 'f', -1, 64), publicKey, N)
	case []interface{}:
		// For lists, recursively encrypt each item
		encryptedList := make([]interface{}, len(v))
		for i, item := range v {
			encrypted, err := EncryptStruct(item, publicKey, N)

			if err != nil {
				return nil, err
			}

			encryptedList[i] = encrypted
		}
		return encryptedList, nil
	case map[string]interface{}:
		// For objects, recursively encrypt each key-value pair
		encryptedObject := make(map[string]interface{})
		for key, value := range v {
			encrypted, err := EncryptStruct(value, publicKey, N)

			if err != nil {
				return nil, err
			}

			encryptedObject[key] = encrypted
		}
		return encryptedObject, nil
	default:
		// Return other types unchanged
		return nil, errors.New(fmt.Sprintf("Unsupported json type: %T", json))
	}
}

func DecryptStruct(json interface{}, privateKey, N *big.Int) (interface{}, error) {
	// Recursively decrypt the values in a JSON object (including nested structures).
	switch v := json.(type) {
	case string:
		return Decrypt(v, privateKey, N)
	case int:
		// If it's an int, we need to decrypt it as a string first, then convert it back to an int,
		return Decrypt(strconv.Itoa(v), privateKey, N)
	case float64:
		// Similarly, handle floats by decrypting and converting them back,
		return Decrypt(strconv.FormatFloat(v, 'f', -1, 64), privateKey, N)
	case []interface{}:
		// For lists, recursively decrypt each item
		decryptedList := make([]interface{}, len(v))
		for i, item := range v {
			decrypted, err := DecryptStruct(item, privateKey, N)

			if err != nil {
				return nil, err
			}

			decryptedList[i] = decrypted
		}
		return decryptedList, nil
	case map[string]interface{}:
		// For objects, recursively decrypt each key-value pair,
		decryptedObject := make(map[string]interface{})
		for key, value := range v {
			decrypted, err := DecryptStruct(value, privateKey, N)

			if err != nil {
				return nil, err
			}

			decryptedObject[key] = decrypted
		}
		return decryptedObject, nil
	default:
		// Return other types unchanged.
		return nil, errors.New(fmt.Sprintf("Unsupported json type: %T", json))
	}
}
