package aes

import "errors"

const blockSize = 16

// EncryptBlock encrypts one block - 16 byte.
func EncryptBlock(input []byte, w []uint32, Nr int) []byte {
	state := make([]byte, 16)
	copy(state, input)

	addRoundKey(state, w, 0)
	for round := 1; round < Nr; round++ {
		subBytes(state)
		shiftRows(state)
		mixColumns(state)
		addRoundKey(state, w, round)
	}
	subBytes(state)
	shiftRows(state)
	addRoundKey(state, w, Nr)

	return state
}

// DecryptBlock decrypts one block - 16 bytes.
func DecryptBlock(input []byte, w []uint32, Nr int) []byte {
	state := make([]byte, 16)
	copy(state, input)

	addRoundKey(state, w, Nr)
	for round := Nr - 1; round > 0; round-- {
		invShiftRows(state)
		invSubBytes(state)
		addRoundKey(state, w, round)
		invMixColumns(state)
	}
	invShiftRows(state)
	invSubBytes(state)
	addRoundKey(state, w, 0)

	return state
}

func Encrypt(message string, key []byte, keySizeBits int) (string, error) {
	data := ApplyPadding([]byte(message))
	w, Nr, err := KeyExpansion(key, keySizeBits)
	if err != nil {
		return "", err
	}
	var ciphertext []byte
	for i := 0; i < len(data); i += blockSize {
		block := data[i : i+blockSize]
		encryptedBlock := EncryptBlock(block, w, Nr)
		ciphertext = append(ciphertext, encryptedBlock...)
	}
	return string(ciphertext), nil
}

func Decrypt(cipherText string, key []byte, keySizeBits int) (string, error) {
	data := []byte(cipherText)
	if len(data)%blockSize != 0 {
		return "", errors.New("incorrect length of ciphertext")
	}
	w, Nr, err := KeyExpansion(key, keySizeBits)
	if err != nil {
		return "", err
	}
	var plaintext []byte
	for i := 0; i < len(data); i += blockSize {
		block := data[i : i+blockSize]
		decryptedBlock := DecryptBlock(block, w, Nr)
		plaintext = append(plaintext, decryptedBlock...)
	}
	plaintext, err = RemovePadding(plaintext)
	if err != nil {
		return "", err
	}
	return string(plaintext), nil
}
