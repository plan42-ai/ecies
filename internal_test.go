package ecies

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"testing"
)

func TestDeriveKey(t *testing.T) {
	t.Parallel()
	dhSecret := []byte{0x00, 0x01, 0x02, 0x03, 0x04}
	sharedInfo := []byte{0x05, 0x06, 0x07}
	derived := deriveKey(dhSecret, sharedInfo)

	input := append(append(append([]byte{}, dhSecret...), 0, 0, 0, 1), sharedInfo...)
	expectedHash := sha256.Sum256(input)
	expected := expectedHash[:]

	requireEqualBytes(t, expected, derived)
}

func TestToX963(t *testing.T) {
	t.Parallel()
	privKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate key: %v", err)
	}

	pub := privKey.Public().(*ecdsa.PublicKey)
	encoded := ToX963(pub)

	if len(encoded) != 65 {
		t.Fatalf("unexpected length: %d", len(encoded))
	}
	if encoded[0] != 4 {
		t.Fatalf("unexpected prefix: %d", encoded[0])
	}

	expectedX := make([]byte, 32)
	pub.X.FillBytes(expectedX)
	for i := range expectedX {
		if expectedX[i] != encoded[1+i] {
			t.Fatalf("x coordinate mismatch at %d", i)
		}
	}

	expectedY := make([]byte, 32)
	pub.Y.FillBytes(expectedY)
	for i := range expectedY {
		if expectedY[i] != encoded[33+i] {
			t.Fatalf("y coordinate mismatch at %d", i)
		}
	}
}

func requireEqualBytes(t *testing.T, expected, actual []byte) {
	t.Helper()
	if len(expected) != len(actual) {
		t.Fatalf("length mismatch: expected %d got %d", len(expected), len(actual))
	}
	for i := range expected {
		if expected[i] != actual[i] {
			t.Fatalf("byte mismatch at %d", i)
		}
	}
}
