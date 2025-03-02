package tests

import (
	"github.com/mesiriak/cyphering/pkg/rsa"
	"testing"
)

func TestEncryptDecrypt_VariousMessages(t *testing.T) {
	testCases := []struct {
		name       string
		message    string
		expected   string
		shouldFail bool
	}{
		{"Short Message", "Hello", "Hello", false},
		{"Long Message", "A very long message that exceeds normal length", "A very long message that exceeds normal length", false},
		{"Empty Message", "", "", false},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			keys, err := rsa.GenerateKeys(2048)
			if err != nil {
				t.Fatalf("Failed to generate keys: %v", err)
			}

			encrypted, err := rsa.Encrypt(tc.message, keys.PublicKey, keys.N)
			if tc.shouldFail {
				if err == nil {
					t.Fatal("Expected encryption error, but got none")
				}
				return
			} else if err != nil {
				t.Fatalf("Encryption failed: %v", err)
			}

			decrypted, err := rsa.Decrypt(encrypted, keys.PrivateKey, keys.N)
			if err != nil {
				t.Fatalf("Decryption failed: %v", err)
			}

			if decrypted != tc.expected {
				t.Errorf("Expected decrypted message to be %s, got %s", tc.expected, decrypted)
			}
		})
	}
}
