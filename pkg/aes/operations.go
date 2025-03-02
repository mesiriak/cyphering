package aes

import "errors"

// Implementation of multiplication in the Galois field (GF(2^8)).
func gfMul(a, b byte) byte {
	var p byte = 0
	for i := 0; i < 8; i++ {
		if b&1 != 0 {
			p ^= a
		}
		hiBit := a & 0x80
		a <<= 1
		if hiBit != 0 {
			a ^= 0x1b
		}
		b >>= 1
	}
	return p
}

// Returns the word rotated 8 bits to the left.
func rotWord(word uint32) uint32 {
	return (word << 8) | (word >> 24)
}

// Applies S-box to each byte of the word.
func subWord(word uint32) uint32 {
	return uint32(sBox[(word>>24)&0xff])<<24 |
		uint32(sBox[(word>>16)&0xff])<<16 |
		uint32(sBox[(word>>8)&0xff])<<8 |
		uint32(sBox[word&0xff])
}

// Bytes replacement with sBox.
func subBytes(state []byte) {
	for i := 0; i < blockSize; i++ {
		state[i] = sBox[state[i]]
	}
}

// Bytes replacement inversion with invSBox.
func invSubBytes(state []byte) {
	for i := 0; i < blockSize; i++ {
		state[i] = invSBox[state[i]]
	}
}

// Shifting rows by AES rules.
func shiftRows(state []byte) {
	var temp [16]byte
	// Row 0 - zero shift.
	temp[0], temp[4], temp[8], temp[12] = state[0], state[4], state[8], state[12]
	// Row 1 - shift left on 1.
	temp[1], temp[5], temp[9], temp[13] = state[5], state[9], state[13], state[1]
	// Row 2 - shift left on 2.
	temp[2], temp[6], temp[10], temp[14] = state[10], state[14], state[2], state[6]
	// Row 3 - shift left on 3.
	temp[3], temp[7], temp[11], temp[15] = state[15], state[3], state[7], state[11]
	copy(state, temp[:])
}

// Inversion of shifting rows by AES rules.
func invShiftRows(state []byte) {
	var temp [16]byte
	// Row 0 - zero shift.
	temp[0], temp[4], temp[8], temp[12] = state[0], state[4], state[8], state[12]
	// Row 1 - shift right on 1.
	temp[1], temp[5], temp[9], temp[13] = state[13], state[1], state[5], state[9]
	// Row 2 - shift right on 2.
	temp[2], temp[6], temp[10], temp[14] = state[10], state[14], state[2], state[6]
	// Row 3 - shift right on 3.
	temp[3], temp[7], temp[11], temp[15] = state[7], state[11], state[15], state[3]
	copy(state, temp[:])
}

// Rows shuffling.
func mixColumns(state []byte) {
	for i := 0; i < 4; i++ {
		idx := i * 4
		a0, a1, a2, a3 := state[idx], state[idx+1], state[idx+2], state[idx+3]
		state[idx+0] = gfMul(a0, 2) ^ gfMul(a1, 3) ^ a2 ^ a3
		state[idx+1] = a0 ^ gfMul(a1, 2) ^ gfMul(a2, 3) ^ a3
		state[idx+2] = a0 ^ a1 ^ gfMul(a2, 2) ^ gfMul(a3, 3)
		state[idx+3] = gfMul(a0, 3) ^ a1 ^ a2 ^ gfMul(a3, 2)
	}
}

// Inversion on shuffling rows.
func invMixColumns(state []byte) {
	for i := 0; i < 4; i++ {
		idx := i * 4
		a0, a1, a2, a3 := state[idx], state[idx+1], state[idx+2], state[idx+3]
		state[idx+0] = gfMul(a0, 0x0e) ^ gfMul(a1, 0x0b) ^ gfMul(a2, 0x0d) ^ gfMul(a3, 0x09)
		state[idx+1] = gfMul(a0, 0x09) ^ gfMul(a1, 0x0e) ^ gfMul(a2, 0x0b) ^ gfMul(a3, 0x0d)
		state[idx+2] = gfMul(a0, 0x0d) ^ gfMul(a1, 0x09) ^ gfMul(a2, 0x0e) ^ gfMul(a3, 0x0b)
		state[idx+3] = gfMul(a0, 0x0b) ^ gfMul(a1, 0x0d) ^ gfMul(a2, 0x09) ^ gfMul(a3, 0x0e)
	}
}

// Adds a round key to the state (16 bytes). The state is represented as 4 columns of 4 bytes.
func addRoundKey(state []byte, w []uint32, round int) {
	for c := 0; c < 4; c++ {
		word := w[round*4+c]
		state[c*4+0] ^= byte(word >> 24)
		state[c*4+1] ^= byte(word >> 16)
		state[c*4+2] ^= byte(word >> 8)
		state[c*4+3] ^= byte(word)
	}
}

// KeyExpansion generates a key extension for AES. Also validates key size.
func KeyExpansion(key []byte, keySizeBits int) ([]uint32, int, error) {
	// Ensure the provided key length matches keySizeBits.
	if len(key)*8 != keySizeBits {
		return nil, 0, errors.New("key length does not match keySizeBits")
	}

	var Nr int
	switch keySizeBits {
	case 128:
		Nr = 10
	case 192:
		Nr = 12
	case 256:
		Nr = 14
	default:
		return nil, 0, errors.New("invalid key size; must be 128, 192, or 256 bits")
	}

	totalWords := 4 * (Nr + 1)
	w := make([]uint32, totalWords)
	// Number of 32-bit words in the key.
	wordsInKey := keySizeBits / 32

	// Initialize the first wordsInKey words with the key.
	for i := 0; i < wordsInKey; i++ {
		w[i] = uint32(key[4*i])<<24 | uint32(key[4*i+1])<<16 | uint32(key[4*i+2])<<8 | uint32(key[4*i+3])
	}
	// Expand the key.
	for i := wordsInKey; i < totalWords; i++ {
		temp := w[i-1]
		if i%wordsInKey == 0 {
			temp = subWord(rotWord(temp)) ^ (uint32(rCon[i/wordsInKey]) << 24)
		} else if wordsInKey > 6 && i%wordsInKey == 4 {
			temp = subWord(temp)
		}
		w[i] = w[i-wordsInKey] ^ temp
	}
	return w, Nr, nil
}
