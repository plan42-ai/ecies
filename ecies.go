package ecies

import (
	"bytes"
	"crypto"
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"encoding/pem"
	"errors"
)

// WrappedSecret represents data encrypted using ecies, specifically with the
// kSecKeyAlgorithmECIESEncryptionCofactorVariableIVX963SHA256AESGCM algorithm supported on apple platforms.
// See https://darthnull.org/secure-enclave-ecies/ for more info.
type WrappedSecret struct {
	EncryptedData      []byte           // EncryptedData is the cypher text + AES GCM tag
	EphemeralPublicKey *ecdsa.PublicKey // EphermalPublicKey is the public key from the ephemeral keypair used to encrypt the data.
}

type wrappedSecretJSON struct {
	EncryptionAlgorithm string
	EncryptedData       []byte
	EphemeralPublicKey  string
}

// MarshalJSON marshals an ecies.WrappedSecret to JSON.
// It includes the encryption algorithm in the output, so that we can implement polymorphic deserialization
// of shared secrets in the future (the repo we stole this from supported both RSA-AES and ECIES), so there
// were two types ecies.WrappedSecret and rsa_aes.WrappedSecret both implementing a common interface.
// We don't need RSA AES support, so this library just has the one type. But we kept the implementation as is
// so that if we do need to support multiple algorithms in the future, we can do so without breaking backwards
// compatibility.
func (ws WrappedSecret) MarshalJSON() ([]byte, error) {
	pubPem, err := PubKeyToPem(ws.EphemeralPublicKey)
	if err != nil {
		return nil, err
	}

	tmp := wrappedSecretJSON{
		EncryptionAlgorithm: ws.EncryptionAlgorithm(),
		EncryptedData:       ws.EncryptedData,
		EphemeralPublicKey:  pubPem,
	}

	return json.Marshal(tmp)
}

// UnmarshalJSON unmarshals a WrappedSecret from JSON.
// It verifies that the encryption algorithm matches the expected value.
func (ws *WrappedSecret) UnmarshalJSON(bytes []byte) error {
	var tmp wrappedSecretJSON
	err := json.Unmarshal(bytes, &tmp)
	if err != nil {
		return err
	}
	if tmp.EncryptionAlgorithm != ws.EncryptionAlgorithm() {
		return errors.New("invalid encryption algorithm")
	}
	pubKey, err := PemToPubKey(tmp.EphemeralPublicKey)
	if err != nil {
		return err
	}
	pubKeyEcdsa, ok := pubKey.(*ecdsa.PublicKey)
	if !ok {
		return errors.New("invalid public key type")
	}

	*ws = WrappedSecret{
		EncryptedData:      tmp.EncryptedData,
		EphemeralPublicKey: pubKeyEcdsa,
	}
	return nil
}

const EciesCofactorVariableIVX963SHA256AESGCM = "ECIES.Cofactor.VariableIV.X963.SHA256.AESGCM"

// EncryptionAlgorithm returns the name of the encryption algorithm used by this WrappedSecret.
func (ws *WrappedSecret) EncryptionAlgorithm() string {
	return "ECIES.Cofactor.VariableIV.X963.SHA256.AESGCM"
}

// Wrap encrypts data using the kSecKeyAlgorithmECIESEncryptionCofactorVariableIVX963SHA256AESGCM algorithm supported on
// apple platforms. See https://darthnull.org/secure-enclave-ecies/ for more info.
// This algorithm:
//  1. Generates a random ephemeral ECDH keypair
//  2. Computes the shared secret between the ephemeral private key and the target public key using ECDH
//  3. Uses the ANSI X9.63 Key Derivation algorithm to derive a 32 byte key from the shared secret, using the X9.63 public key
//     format of the ephemeral public key as the shared info.
//  4. Uses the first 16 bytes of the derived key as the AES-GCM key, and the last 16 bytes as the AES-GCM IV (nonce)
//  5. Encrypts the data using AES-GCM.
//
// Note: Because the IV is derived from the ephemeral public key and the ecdh shared secret, we don't need to store it
// as one normally would when doing AES-GCM encryption.
//
// Only the P256 curve and SHA256 hash are supported.
func Wrap(data []byte, target *ecdsa.PublicKey) (*WrappedSecret, error) {
	if target.Curve.Params().Name != elliptic.P256().Params().Name {
		return nil, errors.New("unsupported curve")
	}
	ephemeralPrivKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	ephemeralPrivKeyECDH, err := ephemeralPrivKey.ECDH()
	if err != nil {
		return nil, err
	}
	targetECDH, err := target.ECDH()
	if err != nil {
		return nil, err
	}
	sharedSecret, err := ephemeralPrivKeyECDH.ECDH(targetECDH)
	if err != nil {
		return nil, err
	}

	pubKeyBytes := ToX963(ephemeralPrivKey.Public().(*ecdsa.PublicKey))

	derived := deriveKey(sharedSecret, pubKeyBytes)
	blockCipher, err := aes.NewCipher(derived[:16])
	if err != nil {
		return nil, err
	}

	gcm, err := cipher.NewGCMWithNonceSize(blockCipher, 16)
	if err != nil {
		return nil, err
	}
	encryptedData := gcm.Seal(nil, derived[16:], data, nil)

	return &WrappedSecret{
		EncryptedData:      encryptedData,
		EphemeralPublicKey: ephemeralPrivKey.Public().(*ecdsa.PublicKey),
	}, nil
}

// Unwrap decrypts a WrappedSecret instance.
func Unwrap(w *WrappedSecret, privKey *ecdsa.PrivateKey) ([]byte, error) {
	if privKey.Curve.Params().Name != elliptic.P256().Params().Name {
		return nil, errors.New("unsupported curve")
	}
	if w.EphemeralPublicKey.Curve.Params().Name != elliptic.P256().Params().Name {
		return nil, errors.New("unsupported curve")
	}
	privKeyECDH, err := privKey.ECDH()
	if err != nil {
		return nil, err
	}
	ephemeralPubKeyECDH, err := w.EphemeralPublicKey.ECDH()
	if err != nil {
		return nil, err
	}
	sharedSecret, err := privKeyECDH.ECDH(ephemeralPubKeyECDH)
	if err != nil {
		return nil, err
	}

	pubKeyBytes := ToX963(w.EphemeralPublicKey)

	derived := deriveKey(sharedSecret, pubKeyBytes)
	blockCipher, err := aes.NewCipher(derived[:16])
	if err != nil {
		return nil, err
	}

	gcm, err := cipher.NewGCMWithNonceSize(blockCipher, 16)
	if err != nil {
		return nil, err
	}

	return gcm.Open(nil, derived[16:], w.EncryptedData, nil)
}

// deriveKey derives a key from the dhSecret and sharedInfo using the ANSI X9.63 Key Derivation Function with SHA256.
func deriveKey(dhSecret []byte, sharedInfo []byte) []byte {
	// The code is a single iteration of the ANSI X9.63 KDF.
	// Normally, we would loop counter from 1 to ceil(keydatalen / hashlen) and at each step compute
	// SHA256(dhSecret || bigendian(counter) || sharedInfo) to produce a "block" of output,	concatenate the blocks
	// together and then take keydatalen bytes as the derived key. However, in our case,
	// hashLen == keyDataLen == 32 bytes (SHA256 output size), so we only need one iteration.
	// Thus we remove the loop because the hash size and the output size are identical... This just becomes
	// a sah256 sum of dhSecret || bigendian(1) || sharedInfo
	var hashInput = make([]byte, len(dhSecret)+len(sharedInfo)+4)
	copy(hashInput, dhSecret)
	binary.BigEndian.PutUint32(hashInput[len(dhSecret):], 1) // hard code counter == 1
	copy(hashInput[len(dhSecret)+4:], sharedInfo)
	ret := sha256.Sum256(hashInput)
	return ret[:]
}

// ToX963 converts an ecdsa.PublicKey to the ANSI X9.63 public key format.
// This is just `0x04 || bigendian(pubKey.X) || bigendian(pubKey.Y)`.
func ToX963(pubKey *ecdsa.PublicKey) []byte {
	ret := make([]byte, 65)
	ret[0] = 4
	pubKey.X.FillBytes(ret[1:33])
	pubKey.Y.FillBytes(ret[33:65])
	return ret
}

func KeyHash(key crypto.PublicKey) (string, error) {
	der, err := x509.MarshalPKIXPublicKey(key)
	if err != nil {
		return "", err
	}
	keyHash := sha256.Sum256(der)
	return base64.RawURLEncoding.EncodeToString(keyHash[:]), nil
}

// PubKeyToPem converts a crypto.PublicKey to a PEM encoded string.
func PubKeyToPem(key crypto.PublicKey) (string, error) {
	der, err := x509.MarshalPKIXPublicKey(key)
	if err != nil {
		return "", err
	}
	var buf bytes.Buffer
	err = pem.Encode(
		&buf,
		&pem.Block{
			Type:  "PUBLIC KEY",
			Bytes: der,
		},
	)
	if err != nil {
		return "", err
	}
	return buf.String(), nil
}

// PemToPubKey decodes a PEM encoded public key into a crypto.PublicKey.
func PemToPubKey(key string) (crypto.PublicKey, error) {
	block, _ := pem.Decode([]byte(key))
	if block == nil {
		return nil, errors.New("failed to decode pem block")
	}
	return x509.ParsePKIXPublicKey(block.Bytes)
}
