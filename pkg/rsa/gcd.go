package rsa

import (
	"errors"
	"fmt"
	"math/big"
)

func XGCD(a, b *big.Int) (*big.Int, *big.Int, *big.Int) {
	// Extended Euclidean Algorithm.
	var xPrev, x = big.NewInt(1), big.NewInt(0)
	var yPrev, y = big.NewInt(0), big.NewInt(1)

	for b.Cmp(big.NewInt(0)) != 0 {
		q := new(big.Int).Div(a, b)
		r := new(big.Int).Mod(a, b)

		a, b = b, r

		xPrev, x = x, new(big.Int).Sub(xPrev, q.Mul(q, x))
		yPrev, y = y, new(big.Int).Sub(yPrev, q.Mul(q, y))
	}

	return a, xPrev, yPrev
}

func inverse(a, n *big.Int) (*big.Int, error) {
	// Function to calculate the modular inverse of a mod n.
	g, x, _ := XGCD(a, n)

	if g.Cmp(big.NewInt(1)) != 0 {
		return big.NewInt(0), errors.New(fmt.Sprintf("Inverse does not exist for number %s mod %s.", a, n))
	}

	// Ensure x is positive.
	return new(big.Int).Mod(x, n), nil
}
