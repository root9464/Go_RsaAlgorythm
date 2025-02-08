package main

import (
	"fmt"
	"log"
	"math/big"
)

func EGCD(a, b *big.Int) (*big.Int, *big.Int, *big.Int) {
	x1, x2, y1, y2 := big.NewInt(0), big.NewInt(1), big.NewInt(1), big.NewInt(0)
	for b.Cmp(big.NewInt(0)) != 0 {
		q := new(big.Int).Div(a, b)
		r := new(big.Int).Sub(a, new(big.Int).Mul(q, b))
		x := new(big.Int).Sub(x2, new(big.Int).Mul(q, x1))
		y := new(big.Int).Sub(y2, new(big.Int).Mul(q, y1))
		a, b = b, r
		x2, x1 = x1, x
		y2, y1 = y1, y
	}
	return a, x2, y2
}

func modInverse(e, phi *big.Int) *big.Int {
	gcd, x, _ := EGCD(e, phi)
	if gcd.Cmp(big.NewInt(1)) != 0 {
		return nil
	}
	if x.Cmp(big.NewInt(0)) == -1 {
		x.Add(x, phi)
	}
	return x
}

func generateValidEValues(phi *big.Int) []*big.Int {
	validE := []*big.Int{}
	if len(validE) == 0 {
		for i := big.NewInt(7); i.Cmp(phi) == -1; i.Add(i, big.NewInt(2)) {
			if new(big.Int).GCD(nil, nil, i, phi).Cmp(big.NewInt(1)) == 0 && i.Cmp(new(big.Int).Sub(phi, big.NewInt(1))) != 0 {
				validE = append(validE, new(big.Int).Set(i))
			}
		}
	}
	return validE
}

func encryptRSA(plainText string, e, n *big.Int) ([]*big.Int, error) {
	encrypted := make([]*big.Int, 0, len(plainText))
	for _, ch := range plainText {
		m := big.NewInt(int64(ch))
		if m.Cmp(n) >= 0 {
			return nil, fmt.Errorf("значение символа %d превышает n", m)
		}
		c := new(big.Int).Exp(m, e, n)
		encrypted = append(encrypted, c)
	}
	return encrypted, nil
}

func decryptRSA(ciphertext []*big.Int, d, n *big.Int) (string, error) {
	var plainText []rune
	for _, c := range ciphertext {
		m := new(big.Int).Exp(c, d, n)
		if !m.IsInt64() || m.Int64() > 0x10FFFF {
			return "", fmt.Errorf("недопустимое значение символа %s", m.String())
		}
		plainText = append(plainText, rune(m.Int64()))
	}
	return string(plainText), nil
}

func main() {
	p, q := big.NewInt(65537), big.NewInt(65519)

	n := new(big.Int).Mul(p, q)
	phi := new(big.Int).Mul(new(big.Int).Sub(p, big.NewInt(1)), new(big.Int).Sub(q, big.NewInt(1)))

	validE := generateValidEValues(phi)
	if len(validE) == 0 {
		log.Fatal("Ошибка: не удалось найти допустимые значения e")
	}

	e := validE[0]
	fmt.Printf("Выбрано e: %s\n", e.String())

	d := modInverse(e, phi)
	if d == nil {
		log.Fatal("Ошибка: невозможно найти обратный элемент d")
	}

	if e.Cmp(d) == 0 {
		log.Fatal("Ошибка: e и d совпадают")
	}

	fmt.Printf("Открытый ключ: (e=%s, n=%s)\n", e.String(), n.String())
	fmt.Printf("Закрытый ключ: (d=%s, n=%s)\n", d.String(), n.String())

}
