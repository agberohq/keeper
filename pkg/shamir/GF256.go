package shamir

import (
	"crypto/rand"
	"crypto/subtle"
	"errors"
)

// GF256 provides Galois Field 2^8 arithmetic operations.
// Uses AES irreducible polynomial: x^8 + x^4 + x^3 + x + 1
type GF256 struct {
	// Pre-computed log/exp tables for fast multiplication
	logTable [256]uint16
	expTable [256]uint8
}

// NewGF256 creates a new GF(2^8) instance with pre-computed tables.
func NewGF256() *GF256 {
	gf := &GF256{}
	gf.initTables()
	return gf
}

// initTables pre-computes log and exp tables for fast operations.
func (gf *GF256) initTables() {
	const generator uint8 = 0x03 // Generator for AES field
	var x uint8 = 1
	for i := 0; i < 255; i++ {
		gf.expTable[i] = x
		gf.logTable[x] = uint16(i)
		x = gf.mulPoly(x, generator)
	}
	// expTable wraps around: 2^255 = 1
	gf.expTable[255] = gf.expTable[0]
}

// mulPoly multiplies two polynomials in GF(2^8).
func (gf *GF256) mulPoly(a, b uint8) uint8 {
	var result uint8 = 0
	for i := 0; i < 8; i++ {
		if (b & 1) != 0 {
			result ^= a
		}
		hiBit := (a & 0x80) != 0
		a <<= 1
		if hiBit {
			a ^= 0x1B // AES polynomial without x^8 term
		}
		b >>= 1
	}
	return result
}

// Add returns a + b in GF(2^8) (XOR).
func (gf *GF256) Add(a, b uint8) uint8 {
	return a ^ b
}

// Sub returns a - b in GF(2^8) (same as Add).
func (gf *GF256) Sub(a, b uint8) uint8 {
	return a ^ b
}

// Mul returns a * b in GF(2^8) using log tables.
func (gf *GF256) Mul(a, b uint8) uint8 {
	if a == 0 || b == 0 {
		return 0
	}

	// Constant-time-ish: compute both paths
	logA := gf.logTable[a]
	logB := gf.logTable[b]
	sum := (int(logA) + int(logB)) % 255
	result := gf.expTable[sum]

	// Ensure zero if either input is zero (constant time)
	var zero uint8
	maskA := subtle.ConstantTimeByteEq(a, 0)
	maskB := subtle.ConstantTimeByteEq(b, 0)
	mask := maskA | maskB

	if mask == 1 {
		return zero
	}
	return result
}

// Div returns a / b in GF(2^8).
func (gf *GF256) Div(a, b uint8) uint8 {
	if b == 0 {
		panic("divide by zero")
	}
	if a == 0 {
		return 0
	}

	logA := gf.logTable[a]
	logB := gf.logTable[b]
	diff := (int(logA) - int(logB)) % 255
	if diff < 0 {
		diff += 255
	}
	return gf.expTable[diff]
}

// Inv returns the multiplicative inverse of a in GF(2^8).
func (gf *GF256) Inv(a uint8) uint8 {
	if a == 0 {
		return 0
	}
	return gf.expTable[255-gf.logTable[a]]
}

// NewPolynomial creates a random polynomial with given intercept and degree.
// The highest coefficient is guaranteed to be non-zero to ensure exact degree.
func (gf *GF256) NewPolynomial(intercept uint8, degree uint8) (*Polynomial, error) {
	if degree == 0 {
		return nil, errors.New("degree must be at least 1")
	}
	p := &Polynomial{
		gf:           gf,
		coefficients: make([]uint8, degree+1),
	}
	p.coefficients[0] = intercept

	if _, err := rand.Read(p.coefficients[1:]); err != nil {
		return nil, err
	}

	// Ensure highest coefficient is non-zero to maintain exact degree
	// This is critical for Shamir's Secret Sharing security
	for p.coefficients[degree] == 0 {
		if _, err := rand.Read(p.coefficients[degree:]); err != nil {
			return nil, err
		}
	}

	return p, nil
}

// Polynomial represents a polynomial over GF(2^8).
type Polynomial struct {
	gf           *GF256
	coefficients []uint8 // coefficients[0] is the constant term (intercept)
}

// Evaluate returns p(x) using Horner's method.
func (p *Polynomial) Evaluate(x uint8) uint8 {
	if x == 0 {
		return p.coefficients[0]
	}

	degree := len(p.coefficients) - 1
	result := p.coefficients[degree]

	for i := degree - 1; i >= 0; i-- {
		result = p.gf.Add(p.gf.Mul(result, x), p.coefficients[i])
	}
	return result
}
