package tests

import (
	"bytes"
	"encoding/hex"
	"github.com/mesiriak/cyphering/pkg/aes"
	"testing"
)

func TestAESKnownVectorHex(t *testing.T) {
	// Test vector:
	keyHex := "2b7e151628aed2a6abf7158809cf4f3c"
	plaintextHex := "3243f6a8885a308d313198a2e0370734"
	expectedCiphertextHex := "3925841d02dc09fbdc118597196a0b32"

	key, err := hex.DecodeString(keyHex)
	if err != nil {
		t.Fatalf("failed to decode key: %v", err)
	}
	plaintext, err := hex.DecodeString(plaintextHex)
	if err != nil {
		t.Fatalf("failed to decode plaintext: %v", err)
	}
	expectedCiphertext, err := hex.DecodeString(expectedCiphertextHex)
	if err != nil {
		t.Fatalf("failed to decode expected ciphertext: %v", err)
	}

	w, Nr, err := aes.KeyExpansion(key, 128)
	if err != nil {
		t.Fatalf("KeyExpansion failed: %v", err)
	}
	ciphertext := aes.EncryptBlock(plaintext, w, Nr)
	if !bytes.Equal(ciphertext, expectedCiphertext) {
		t.Errorf("AES known vector test failed: got %x, expected %x", ciphertext, expectedCiphertext)
	}

	decrypted := aes.DecryptBlock(ciphertext, w, Nr)
	if !bytes.Equal(decrypted, plaintext) {
		t.Errorf("AES known vector decryption failed: got %x, expected %x", decrypted, plaintext)
	}
}

func TestAESRoundTrip(t *testing.T) {
	testCases := []struct {
		name      string
		key       []byte
		plaintext string
		keySize   int
	}{
		{
			name:      "AES-128",
			key:       []byte("thisis16bytekey!"),
			plaintext: "Test message for AES-128!",
			keySize:   128,
		},
		{
			name:      "AES-192",
			key:       []byte("thisis24bytekeyforaes192"),
			plaintext: "Test message for AES-192 encryption.",
			keySize:   192,
		},
		{
			name:      "AES-256",
			key:       []byte("thisis32bytekeyforaes256encrypt!"),
			plaintext: "Test message for AES-256 with a strong key.",
			keySize:   256,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			encrypted, err := aes.Encrypt(tc.plaintext, tc.key, tc.keySize)
			if err != nil {
				t.Fatalf("Encryption failed: %v", err)
			}
			decrypted, err := aes.Decrypt(encrypted, tc.key, tc.keySize)
			if err != nil {
				t.Fatalf("Decryption failed: %v", err)
			}
			if decrypted != tc.plaintext {
				t.Errorf("Round-trip test failed: got %s, expected %s", decrypted, tc.plaintext)
			}
		})
	}
}
