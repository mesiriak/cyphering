package aes

import (
	"bytes"
	"errors"
)

// PKCS#7 padding algorithm.

// ApplyPadding Use if the message length is not a multiple of 16 bytes.
func ApplyPadding(data []byte) []byte {
	padding := blockSize - len(data)%blockSize
	return append(data, bytes.Repeat([]byte{byte(padding)}, padding)...)
}

// RemovePadding Use after decryption to restore original message.
func RemovePadding(data []byte) ([]byte, error) {
	if len(data) == 0 {
		return nil, errors.New("blank data provided")
	}

	padding := int(data[len(data)-1])

	// Padding validation.
	if padding > blockSize || padding == 0 {
		return nil, errors.New("incorrect padding provided")
	}

	for i := 0; i < padding; i++ {
		if data[len(data)-1-i] != byte(padding) {
			return nil, errors.New("incorrect padding provided")
		}
	}

	return data[:len(data)-padding], nil
}
