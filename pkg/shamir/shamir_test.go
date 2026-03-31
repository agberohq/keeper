package shamir

import (
	"bytes"
	"testing"
)

// TestGF256BasicOperations tests basic GF(2^8) arithmetic
func TestGF256BasicOperations(t *testing.T) {
	gf := NewGF256()

	// Test Add/Sub (XOR)
	tests := []struct {
		a, b, expected uint8
	}{
		{0x00, 0x00, 0x00},
		{0xFF, 0x00, 0xFF},
		{0xFF, 0xFF, 0x00},
		{0xAB, 0xCD, 0x66},
		{0x12, 0x34, 0x26},
	}

	for _, tt := range tests {
		result := gf.Add(tt.a, tt.b)
		if result != tt.expected {
			t.Errorf("Add(%02x, %02x) = %02x, want %02x", tt.a, tt.b, result, tt.expected)
		}

		// Sub is same as Add
		result = gf.Sub(tt.a, tt.b)
		if result != tt.expected {
			t.Errorf("Sub(%02x, %02x) = %02x, want %02x", tt.a, tt.b, result, tt.expected)
		}
	}
}

// TestGF256Mul tests multiplication
func TestGF256Mul(t *testing.T) {
	gf := NewGF256()

	// Test basic multiplication properties
	tests := []struct {
		a, b, expected uint8
	}{
		{0x00, 0x00, 0x00}, // Zero * anything = zero
		{0x00, 0xAB, 0x00},
		{0xAB, 0x00, 0x00},
		{0x01, 0xAB, 0xAB}, // One * anything = anything
		{0xAB, 0x01, 0xAB},
	}

	for _, tt := range tests {
		result := gf.Mul(tt.a, tt.b)
		if result != tt.expected {
			t.Errorf("Mul(%02x, %02x) = %02x, want %02x", tt.a, tt.b, result, tt.expected)
		}
	}

	// Test commutativity: a*b = b*a
	for a := 1; a < 256; a += 17 { // Sample, not all 65536 combinations
		for b := 1; b < 256; b += 23 {
			ab := gf.Mul(uint8(a), uint8(b))
			ba := gf.Mul(uint8(b), uint8(a))
			if ab != ba {
				t.Errorf("Mul not commutative: %02x*%02x=%02x, %02x*%02x=%02x",
					a, b, ab, b, a, ba)
			}
		}
	}
}

// TestGF256MulDivInverse tests that a * (1/a) = 1
func TestGF256MulDivInverse(t *testing.T) {
	gf := NewGF256()

	for a := 1; a < 256; a++ {
		invA := gf.Inv(uint8(a))
		product := gf.Mul(uint8(a), invA)
		if product != 0x01 {
			t.Errorf("Mul(%02x, Inv(%02x)) = %02x, want 01", a, a, product)
		}
	}

	// Test: a / a = 1 (for non-zero a)
	for a := 1; a < 256; a += 7 {
		result := gf.Div(uint8(a), uint8(a))
		if result != 0x01 {
			t.Errorf("Div(%02x, %02x) = %02x, want 01", a, a, result)
		}
	}
}

// TestGF256DivByZero panics
func TestGF256DivByZero(t *testing.T) {
	gf := NewGF256()

	defer func() {
		if r := recover(); r == nil {
			t.Error("Div by zero should panic")
		}
	}()

	gf.Div(0xAB, 0x00)
}

// TestGF256MulDivConsistency tests that (a*b)/b = a
func TestGF256MulDivConsistency(t *testing.T) {
	gf := NewGF256()

	for a := 1; a < 256; a += 11 {
		for b := 1; b < 256; b += 13 {
			product := gf.Mul(uint8(a), uint8(b))
			quotient := gf.Div(product, uint8(b))
			if quotient != uint8(a) {
				t.Errorf("(%02x * %02x) / %02x = %02x, want %02x",
					a, b, b, quotient, a)
			}
		}
	}
}

// TestPolynomialEvaluation tests polynomial evaluation
func TestPolynomialEvaluation(t *testing.T) {
	gf := NewGF256()

	// Create polynomial: f(x) = 5 + 3x + 7x^2
	p := &Polynomial{
		gf:           gf,
		coefficients: []uint8{5, 3, 7},
	}

	// f(0) should be intercept (5)
	if p.Evaluate(0) != 5 {
		t.Errorf("f(0) = %d, want 5", p.Evaluate(0))
	}

	// Manual check: f(2) = 5 + 3*2 + 7*4 = 5 + 6 + 28 = 39 (mod 256)
	// In GF: 5 + 3*2 + 7*4
	expected := gf.Add(5, gf.Add(gf.Mul(3, 2), gf.Mul(7, gf.Mul(2, 2))))
	// Or simpler: gf.Add(5, gf.Add(gf.Mul(3, 2), gf.Mul(7, 4)))
	result := p.Evaluate(2)
	if result != expected {
		t.Errorf("f(2) = %d, want %d", result, expected)
	}
}

// TestNewPolynomialRandomness tests that polynomials are random
func TestNewPolynomialRandomness(t *testing.T) {
	gf := NewGF256()

	// Create multiple polynomials with same intercept
	intercept := uint8(0x42)
	polys := make([]*Polynomial, 10)

	for i := range polys {
		p, err := gf.NewPolynomial(intercept, 2)
		if err != nil {
			t.Fatal(err)
		}
		polys[i] = p
	}

	// Check that coefficients (except intercept) are different
	// (probability of collision is negligible)
	for i := 1; i < len(polys); i++ {
		if bytes.Equal(polys[0].coefficients, polys[i].coefficients) {
			t.Error("Polynomial coefficients should be random")
		}
	}

	// All should have same intercept
	for i, p := range polys {
		if p.coefficients[0] != intercept {
			t.Errorf("Polynomial %d has wrong intercept: %02x", i, p.coefficients[0])
		}
	}
}

// TestShamirSplitValidation tests input validation
func TestShamirSplitValidation(t *testing.T) {
	shamir := NewShamir()

	// Empty secret
	if _, err := shamir.Split([]byte{}, 3, 2); err == nil {
		t.Error("Should reject empty secret")
	}

	// Threshold > parts
	if _, err := shamir.Split([]byte("secret"), 2, 3); err == nil {
		t.Error("Should reject threshold > parts")
	}

	// Threshold < 2
	if _, err := shamir.Split([]byte("secret"), 3, 1); err == nil {
		t.Error("Should reject threshold < 2")
	}

	// Parts > 255
	if _, err := shamir.Split([]byte("secret"), 256, 2); err == nil {
		t.Error("Should reject parts > 255")
	}

	// Threshold > 255
	if _, err := shamir.Split([]byte("secret"), 255, 256); err == nil {
		t.Error("Should reject threshold > 255")
	}
}

// TestShamirBasicSplitCombine tests basic split and reconstruct
func TestShamirBasicSplitCombine(t *testing.T) {
	shamir := NewShamir()

	secret := []byte("hello world")
	parts := 5
	threshold := 3

	shares, err := shamir.Split(secret, parts, threshold)
	if err != nil {
		t.Fatalf("Split failed: %v", err)
	}

	if len(shares) != parts {
		t.Errorf("Expected %d shares, got %d", parts, len(shares))
	}

	// Reconstruct with exactly threshold shares
	reconstructed, err := shamir.Combine(shares[:threshold])
	if err != nil {
		t.Fatalf("Combine failed: %v", err)
	}

	if !bytes.Equal(reconstructed, secret) {
		t.Errorf("Reconstructed %q, want %q", reconstructed, secret)
	}
}

// TestShamirDifferentThresholds tests various threshold combinations
func TestShamirDifferentThresholds(t *testing.T) {
	shamir := NewShamir()

	secrets := [][]byte{
		[]byte("a"),
		[]byte("short"),
		[]byte("medium length secret here"),
		[]byte("a much longer secret that spans multiple bytes and tests the implementation thoroughly"),
	}

	configs := []struct {
		parts, threshold int
	}{
		{3, 2},
		{5, 3},
		{10, 5},
		{50, 25},
		{100, 51},
		{255, 128},
	}

	for _, secret := range secrets {
		for _, cfg := range configs {
			shares, err := shamir.Split(secret, cfg.parts, cfg.threshold)
			if err != nil {
				t.Errorf("Split(%d, %d) failed: %v", cfg.parts, cfg.threshold, err)
				continue
			}

			// Reconstruct with threshold
			reconstructed, err := shamir.Combine(shares[:cfg.threshold])
			if err != nil {
				t.Errorf("Combine(%d, %d) failed: %v", cfg.parts, cfg.threshold, err)
				continue
			}

			if !bytes.Equal(reconstructed, secret) {
				t.Errorf("Reconstruction failed for %d/%d", cfg.threshold, cfg.parts)
			}
		}
	}
}

// TestShamirInsufficientShares tests that fewer than threshold shares fail
func TestShamirInsufficientShares(t *testing.T) {
	shamir := NewShamir()

	secret := []byte("secret message")
	shares, err := shamir.Split(secret, 5, 3)
	if err != nil {
		t.Fatal(err)
	}

	// Try with 2 shares (should produce garbage or fail gracefully)
	// Note: Shamir will produce *some* result, but it won't be the secret
	reconstructed, err := shamir.Combine(shares[:2])
	if err != nil {
		t.Logf("Combine with insufficient shares returned error (acceptable): %v", err)
		return
	}

	// If no error, result should NOT match secret
	if bytes.Equal(reconstructed, secret) {
		t.Error("Reconstruction with insufficient shares should not produce correct secret")
	}
}

// TestShamirAnySubsetReconstructs tests that any threshold shares work
func TestShamirAnySubsetReconstructs(t *testing.T) {
	shamir := NewShamir()

	secret := []byte("test secret")
	shares, err := shamir.Split(secret, 5, 3)
	if err != nil {
		t.Fatal(err)
	}

	// Test all combinations of 3 shares from 5
	combinations := [][]int{
		{0, 1, 2},
		{0, 1, 3},
		{0, 1, 4},
		{0, 2, 3},
		{0, 2, 4},
		{0, 3, 4},
		{1, 2, 3},
		{1, 2, 4},
		{1, 3, 4},
		{2, 3, 4},
	}

	for _, combo := range combinations {
		subset := []*Share{
			shares[combo[0]],
			shares[combo[1]],
			shares[combo[2]],
		}

		reconstructed, err := shamir.Combine(subset)
		if err != nil {
			t.Errorf("Combine %v failed: %v", combo, err)
			continue
		}

		if !bytes.Equal(reconstructed, secret) {
			t.Errorf("Combination %v failed to reconstruct", combo)
		}
	}
}

// TestShamirMoreThanThreshold tests using more than threshold shares
func TestShamirMoreThanThreshold(t *testing.T) {
	shamir := NewShamir()

	secret := []byte("more shares test")
	shares, err := shamir.Split(secret, 5, 3)
	if err != nil {
		t.Fatal(err)
	}

	// Use all 5 shares (more than threshold)
	reconstructed, err := shamir.Combine(shares)
	if err != nil {
		t.Fatalf("Combine with all shares failed: %v", err)
	}

	if !bytes.Equal(reconstructed, secret) {
		t.Error("Reconstruction with all shares failed")
	}
}

// TestShamirDuplicateShares tests that duplicate shares are detected
func TestShamirDuplicateShares(t *testing.T) {
	shamir := NewShamir()

	secret := []byte("duplicate test")
	shares, err := shamir.Split(secret, 3, 2)
	if err != nil {
		t.Fatal(err)
	}

	// Try to combine with duplicate
	duplicateShares := []*Share{shares[0], shares[0]}
	_, err = shamir.Combine(duplicateShares)
	if err == nil {
		t.Error("Should detect duplicate shares")
	}
}

// TestShamirSingleShare tests that single share fails
func TestShamirSingleShare(t *testing.T) {
	shamir := NewShamir()

	_, err := shamir.Combine([]*Share{{X: 1, Y: []uint8{0xAB, 0xCD}}})
	if err == nil {
		t.Error("Should reject single share")
	}
}

// TestShamirMismatchedShareLengths tests share length validation
func TestShamirMismatchedShareLengths(t *testing.T) {
	shamir := NewShamir()

	shares := []*Share{
		{X: 1, Y: []uint8{0x01, 0x02}},
		{X: 2, Y: []uint8{0x03}}, // Different length
	}

	_, err := shamir.Combine(shares)
	if err == nil {
		t.Error("Should reject shares with different lengths")
	}
}

// TestShamirSerialization tests share serialization/deserialization
func TestShamirSerialization(t *testing.T) {
	shamir := NewShamir()

	original := &Share{
		X: 42,
		Y: []uint8{0x01, 0x02, 0x03, 0x04, 0x05},
	}

	serialized := shamir.SerializeShare(original)
	expectedLen := 1 + len(original.Y)
	if len(serialized) != expectedLen {
		t.Errorf("Serialized length %d, want %d", len(serialized), expectedLen)
	}

	if serialized[0] != original.X {
		t.Errorf("Serialized X = %d, want %d", serialized[0], original.X)
	}

	if !bytes.Equal(serialized[1:], original.Y) {
		t.Error("Serialized Y mismatch")
	}

	// Deserialize
	deserialized, err := shamir.DeserializeShare(serialized)
	if err != nil {
		t.Fatal(err)
	}

	if deserialized.X != original.X {
		t.Errorf("Deserialized X = %d, want %d", deserialized.X, original.X)
	}

	if !bytes.Equal(deserialized.Y, original.Y) {
		t.Error("Deserialized Y mismatch")
	}
}

// TestShamirDeserializeShortData tests deserialization of short data
func TestShamirDeserializeShortData(t *testing.T) {
	shamir := NewShamir()

	_, err := shamir.DeserializeShare([]byte{0x01}) // Only 1 byte
	if err == nil {
		t.Error("Should reject too short data")
	}

	_, err = shamir.DeserializeShare([]byte{}) // Empty
	if err == nil {
		t.Error("Should reject empty data")
	}
}

// TestShamirBinarySecret tests with binary data (including zeros)
func TestShamirBinarySecret(t *testing.T) {
	shamir := NewShamir()

	// Secret with all byte values including zeros
	secret := make([]byte, 256)
	for i := range secret {
		secret[i] = uint8(i)
	}

	shares, err := shamir.Split(secret, 10, 5)
	if err != nil {
		t.Fatal(err)
	}

	reconstructed, err := shamir.Combine(shares[:5])
	if err != nil {
		t.Fatal(err)
	}

	if !bytes.Equal(reconstructed, secret) {
		t.Error("Binary secret reconstruction failed")
	}
}

// TestShamirAllSameByte tests secret with all same byte
func TestShamirAllSameByte(t *testing.T) {
	shamir := NewShamir()

	secret := bytes.Repeat([]byte{0xAB}, 100)

	shares, err := shamir.Split(secret, 5, 3)
	if err != nil {
		t.Fatal(err)
	}

	reconstructed, err := shamir.Combine(shares[:3])
	if err != nil {
		t.Fatal(err)
	}

	if !bytes.Equal(reconstructed, secret) {
		t.Error("All-same-byte secret reconstruction failed")
	}
}

// TestShamirRandomXCoords tests that x coordinates are unique
func TestShamirRandomXCoords(t *testing.T) {
	shamir := NewShamir()

	secret := []byte("unique x test")
	shares, err := shamir.Split(secret, 100, 50)
	if err != nil {
		t.Fatal(err)
	}

	xMap := make(map[uint8]bool)
	for _, sh := range shares {
		if xMap[sh.X] {
			t.Errorf("Duplicate X coordinate: %d", sh.X)
		}
		xMap[sh.X] = true
		if sh.X == 0 {
			t.Error("X coordinate should never be 0")
		}
	}
}

// BenchmarkShamirSplit benchmarks secret splitting
func BenchmarkShamirSplit(b *testing.B) {
	shamir := NewShamir()
	secret := make([]byte, 32) // 256-bit secret

	for i := 0; i < b.N; i++ {
		_, err := shamir.Split(secret, 10, 5)
		if err != nil {
			b.Fatal(err)
		}
	}
}

// BenchmarkShamirCombine benchmarks secret reconstruction
func BenchmarkShamirCombine(b *testing.B) {
	shamir := NewShamir()
	secret := make([]byte, 32)
	shares, _ := shamir.Split(secret, 10, 5)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, err := shamir.Combine(shares[:5])
		if err != nil {
			b.Fatal(err)
		}
	}
}

// BenchmarkGF256Mul benchmarks multiplication
func BenchmarkGF256Mul(b *testing.B) {
	gf := NewGF256()

	for i := 0; i < b.N; i++ {
		_ = gf.Mul(uint8(i), uint8(i>>8))
	}
}

// BenchmarkPolynomialEvaluate benchmarks polynomial evaluation
func BenchmarkPolynomialEvaluate(b *testing.B) {
	gf := NewGF256()
	p, _ := gf.NewPolynomial(0x42, 10) // degree 10

	for i := 0; i < b.N; i++ {
		_ = p.Evaluate(uint8(i))
	}
}
