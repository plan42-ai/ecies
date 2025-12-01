package ecies_test

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"math/big"
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

func TestWrappedSecretMarshalJSON(t *testing.T) {
	t.Parallel()
	privKeyReceiver, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	w, err := ecies.Wrap([]byte("payload"), privKeyReceiver.Public().(*ecdsa.PublicKey))
	require.NoError(t, err)

	encoded, err := json.Marshal(w)
	require.NoError(t, err)

	var payload struct {
		EncryptionAlgorithm string
		EncryptedData       []byte
		EphemeralPublicKey  string
	}
	require.NoError(t, json.Unmarshal(encoded, &payload))
	require.Equal(t, w.EncryptionAlgorithm(), payload.EncryptionAlgorithm)
	require.Equal(t, w.EncryptedData, payload.EncryptedData)

	expectedPEM, err := ecies.PubKeyToPem(w.EphemeralPublicKey)
	require.NoError(t, err)
	require.Equal(t, expectedPEM, payload.EphemeralPublicKey)
}

func TestWrappedSecretMarshalJSONError(t *testing.T) {
	t.Parallel()
	invalidKey := &ecdsa.PublicKey{Curve: elliptic.P256(), X: big.NewInt(0), Y: big.NewInt(0)}
	ws := ecies.WrappedSecret{EncryptedData: []byte("data"), EphemeralPublicKey: invalidKey}
	_, err := ws.MarshalJSON()
	require.Error(t, err)
}

func TestWrappedSecretUnmarshalJSON(t *testing.T) {
	t.Parallel()
	privKeyReceiver, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	w, err := ecies.Wrap([]byte("secret"), privKeyReceiver.Public().(*ecdsa.PublicKey))
	require.NoError(t, err)

	encoded, err := json.Marshal(w)
	require.NoError(t, err)

	var decoded ecies.WrappedSecret
	require.NoError(t, json.Unmarshal(encoded, &decoded))
	require.Equal(t, w.EncryptedData, decoded.EncryptedData)
	require.Equal(t, w.EncryptionAlgorithm(), decoded.EncryptionAlgorithm())

	originalPEM, err := ecies.PubKeyToPem(w.EphemeralPublicKey)
	require.NoError(t, err)
	decodedPEM, err := ecies.PubKeyToPem(decoded.EphemeralPublicKey)
	require.NoError(t, err)
	require.Equal(t, originalPEM, decodedPEM)
}

func TestWrappedSecretUnmarshalJSONInvalidAlgorithm(t *testing.T) {
	t.Parallel()
	privKeyReceiver, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	w, err := ecies.Wrap([]byte("secret"), privKeyReceiver.Public().(*ecdsa.PublicKey))
	require.NoError(t, err)
	pubPEM, err := ecies.PubKeyToPem(w.EphemeralPublicKey)
	require.NoError(t, err)

	payload := map[string]any{
		"EncryptionAlgorithm": "INVALID",
		"EncryptedData":       w.EncryptedData,
		"EphemeralPublicKey":  pubPEM,
	}
	encoded, err := json.Marshal(payload)
	require.NoError(t, err)

	var decoded ecies.WrappedSecret
	require.Error(t, json.Unmarshal(encoded, &decoded))
}

func TestWrappedSecretUnmarshalJSONInvalidPEM(t *testing.T) {
	t.Parallel()
	payload := map[string]any{
		"EncryptionAlgorithm": (&ecies.WrappedSecret{}).EncryptionAlgorithm(),
		"EncryptedData":       []byte{0x01, 0x02, 0x03},
		"EphemeralPublicKey":  "not pem",
	}
	encoded, err := json.Marshal(payload)
	require.NoError(t, err)

	var decoded ecies.WrappedSecret
	require.Error(t, json.Unmarshal(encoded, &decoded))
}

func TestWrappedSecretUnmarshalJSONWrongKeyType(t *testing.T) {
	t.Parallel()
	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	der, err := x509.MarshalPKIXPublicKey(&rsaKey.PublicKey)
	require.NoError(t, err)

	var block pem.Block
	block.Type = "PUBLIC KEY"
	block.Bytes = der
	rsaPEM := string(pem.EncodeToMemory(&block))

	payload := map[string]any{
		"EncryptionAlgorithm": (&ecies.WrappedSecret{}).EncryptionAlgorithm(),
		"EncryptedData":       []byte{0x01, 0x02, 0x03},
		"EphemeralPublicKey":  rsaPEM,
	}
	encoded, err := json.Marshal(payload)
	require.NoError(t, err)

	var decoded ecies.WrappedSecret
	require.Error(t, json.Unmarshal(encoded, &decoded))
}

func TestPubKeyToPemRoundTrip(t *testing.T) {
	t.Parallel()
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	pemString, err := ecies.PubKeyToPem(priv.Public())
	require.NoError(t, err)

	parsed, err := ecies.PemToPubKey(pemString)
	require.NoError(t, err)
	parsedECDSA, ok := parsed.(*ecdsa.PublicKey)
	require.True(t, ok)
	require.Equal(t, priv.Public().(*ecdsa.PublicKey).Curve, parsedECDSA.Curve)
	require.Equal(t, priv.Public().(*ecdsa.PublicKey).X, parsedECDSA.X)
	require.Equal(t, priv.Public().(*ecdsa.PublicKey).Y, parsedECDSA.Y)
}

func TestPemToPubKeyInvalidInput(t *testing.T) {
	t.Parallel()
	_, err := ecies.PemToPubKey("not pem")
	require.Error(t, err)
}

func TestUnwrapTamperedCiphertext(t *testing.T) {
	t.Parallel()
	privKeyReceiver, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	w, err := ecies.Wrap([]byte("secret"), privKeyReceiver.Public().(*ecdsa.PublicKey))
	require.NoError(t, err)

	tamperedSecret := *w
	tamperedSecret.EncryptedData = append([]byte{}, w.EncryptedData...)
	tamperedSecret.EncryptedData[len(tamperedSecret.EncryptedData)-1] ^= 0x01

	_, err = ecies.Unwrap(&tamperedSecret, privKeyReceiver)
	require.Error(t, err)
}
