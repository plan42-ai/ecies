package ecies_test

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"testing"

	"github.com/debugging-sucks/ecies"
	"github.com/stretchr/testify/require"
)

func TestRoundTrip(t *testing.T) {
	t.Parallel()
	privKeyReceiver, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	w, err := ecies.Wrap([]byte("hello"), privKeyReceiver.Public().(*ecdsa.PublicKey))
	require.NoError(t, err)
	data, err := ecies.Unwrap(w, privKeyReceiver)
	require.NoError(t, err)
	require.Equal(t, "hello", string(data))
}
