package aes

import (
	"math/big"
)

func stringToBigInt(message string) *big.Int {
	return new(big.Int).SetBytes([]byte(message))
}

func bigIntToString(messageInt *big.Int) string {
	return string(messageInt.Bytes())
}
