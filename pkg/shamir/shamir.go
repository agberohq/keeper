package shamir

import (
	"crypto/rand"
	"errors"
	"fmt"
	"math/big"
)

// Shamir provides Shamir's Secret Sharing operations.
type Shamir struct {
	gf *GF256
}

// NewShamir creates a new Shamir instance.
func NewShamir() *Shamir {
	return &Shamir{
		gf: NewGF256(),
	}
}

// Share represents a single share with x coordinate and y values.
type Share struct {
	X uint8
	Y []uint8
}

// Split divides secret into n shares, requiring k to reconstruct.
func (s *Shamir) Split(secret []byte, parts, threshold int) ([]*Share, error) {
	if parts < threshold {
		return nil, errors.New("parts cannot be less than threshold")
	}
	if parts > 255 {
		return nil, errors.New("parts cannot exceed 255")
	}
	if threshold < 2 {
		return nil, errors.New("threshold must be at least 2")
	}
	if threshold > 255 {
		return nil, errors.New("threshold cannot exceed 255")
	}
	if len(secret) == 0 {
		return nil, errors.New("cannot split empty secret")
	}

	// Generate unique x coordinates (1..255)
	xCoords, err := s.generateXCoords(parts)
	if err != nil {
		return nil, fmt.Errorf("failed to generate x coordinates: %w", err)
	}

	// Create shares
	shares := make([]*Share, parts)
	for i := 0; i < parts; i++ {
		shares[i] = &Share{
			X: xCoords[i],
			Y: make([]uint8, len(secret)),
		}
	}

	// For each byte of secret, create a polynomial and evaluate at each x
	for byteIdx, byteVal := range secret {
		poly, err := s.gf.NewPolynomial(byteVal, uint8(threshold-1))
		if err != nil {
			return nil, fmt.Errorf("failed to create polynomial: %w", err)
		}

		for i, x := range xCoords {
			shares[i].Y[byteIdx] = poly.Evaluate(x)
		}
	}

	return shares, nil
}

// generateXCoords generates n unique random x coordinates in range 1..255.
func (s *Shamir) generateXCoords(n int) ([]uint8, error) {
	if n > 255 {
		return nil, errors.New("too many parts")
	}

	// Fisher-Yates shuffle of 1..255
	coords := make([]uint8, 255)
	for i := range coords {
		coords[i] = uint8(i + 1)
	}

	for i := 254; i > 0; i-- {
		jBig, err := rand.Int(rand.Reader, big.NewInt(int64(i+1)))
		if err != nil {
			return nil, err
		}
		j := int(jBig.Int64())
		coords[i], coords[j] = coords[j], coords[i]
	}

	return coords[:n], nil
}

// Combine reconstructs secret from shares using Lagrange interpolation.
func (s *Shamir) Combine(shares []*Share) ([]byte, error) {
	if len(shares) < 2 {
		return nil, errors.New("need at least 2 shares")
	}

	// Verify all shares have same length
	yLen := len(shares[0].Y)
	for i, sh := range shares {
		if len(sh.Y) != yLen {
			return nil, fmt.Errorf("share %d has wrong length", i)
		}
	}

	// Check for duplicate x coordinates
	xMap := make(map[uint8]bool)
	for _, sh := range shares {
		if xMap[sh.X] {
			return nil, errors.New("duplicate x coordinate detected")
		}
		xMap[sh.X] = true
	}

	// Reconstruct each byte
	secret := make([]uint8, yLen)

	for byteIdx := 0; byteIdx < yLen; byteIdx++ {
		// Build points for this byte position
		xSamples := make([]uint8, len(shares))
		ySamples := make([]uint8, len(shares))

		for i, sh := range shares {
			xSamples[i] = sh.X
			ySamples[i] = sh.Y[byteIdx]
		}

		secret[byteIdx] = s.interpolate(xSamples, ySamples, 0)
	}

	return secret, nil
}

// interpolate computes f(x) using Lagrange interpolation.
func (s *Shamir) interpolate(xSamples, ySamples []uint8, x uint8) uint8 {
	n := len(xSamples)
	var result uint8 = 0

	for i := 0; i < n; i++ {
		// Compute Lagrange basis polynomial l_i(x)
		basis := uint8(1)

		for j := 0; j < n; j++ {
			if i == j {
				continue
			}

			// l_i(x) = prod_{j!=i} (x - x_j) / (x_i - x_j)
			numerator := s.gf.Sub(x, xSamples[j])
			denominator := s.gf.Sub(xSamples[i], xSamples[j])
			term := s.gf.Div(numerator, denominator)
			basis = s.gf.Mul(basis, term)
		}

		// Add y_i * l_i(x) to result
		group := s.gf.Mul(ySamples[i], basis)
		result = s.gf.Add(result, group)
	}

	return result
}

// SerializeShare converts a share to bytes for storage.
func (s *Shamir) SerializeShare(sh *Share) []byte {
	// Format: [1 byte x][y values...]
	result := make([]byte, 1+len(sh.Y))
	result[0] = sh.X
	copy(result[1:], sh.Y)
	return result
}

// DeserializeShare converts bytes back to a share.
func (s *Shamir) DeserializeShare(data []byte) (*Share, error) {
	if len(data) < 2 {
		return nil, errors.New("share data too short")
	}
	// Copy Y data so secureZero on input doesn't corrupt the share
	yCopy := make([]byte, len(data)-1)
	copy(yCopy, data[1:])
	return &Share{
		X: data[0],
		Y: yCopy,
	}, nil
}
