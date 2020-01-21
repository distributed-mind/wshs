package wshs

import (
	"log"
	"crypto/rand"
	"crypto/ed25519"
	"crypto/sha256"
	"github.com/agl/ed25519/extra25519"
)

const (
	// NetworkKeyString defaults to "dev"
	NetworkKeyString string = "dev"
)

var (
	// NetworkKeyBytes .
	NetworkKeyBytes = [32]byte{}
)

func init() {
	NetworkKeyBytes = CalculateNetworkKey(NetworkKeyString)
}

// GenerateEphemeralCurve25519KeyPair generates a curve25519 key pair
// which is designated for ephemeral usage per each handshake
func GenerateEphemeralCurve25519KeyPair() (pub, priv [32]byte) {
	ed25519PublicKey, ed25519PrivateKey := generateEd25519KeyPairByteArrays()
	curve25519PrivateKeyEphemeral := [32]byte{}
	extra25519.PrivateKeyToCurve25519(
		&curve25519PrivateKeyEphemeral,
		&ed25519PrivateKey,
	)
	curve25519PublicKeyEphemeral := [32]byte{}
	extra25519.PublicKeyToCurve25519(
		&curve25519PublicKeyEphemeral,
		&ed25519PublicKey,
	)
	
	return curve25519PublicKeyEphemeral, curve25519PrivateKeyEphemeral
}

// PrivateKeyToCurve25519 .
func PrivateKeyToCurve25519(e [64]byte) ([32]byte) {
	curve25519PrivateKey := [32]byte{}
	extra25519.PrivateKeyToCurve25519(
		&curve25519PrivateKey,
		&e,
	)
	return curve25519PrivateKey
}

// PublicKeyToCurve25519 .
func PublicKeyToCurve25519(e [32]byte) ([32]byte) {
	curve25519PublicKey := [32]byte{}
	extra25519.PublicKeyToCurve25519(
		&curve25519PublicKey,
		&e,
	)
	return curve25519PublicKey
}

// CalculateNetworkKey from string
func CalculateNetworkKey(s string) [32]byte {
	h := sha256.New()
	h.Write([]byte(s))
	networkKey := [32]byte{}
	copy(networkKey[:], h.Sum(nil))

	return networkKey
}

func generateEd25519KeyPairByteArrays() (publicKey [32]byte, privateKey [64]byte) {
	ed25519PublicKey, ed25519PrivateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		log.Fatalf("generate ed25519 key: %v", err)
	}
	privateKeyByteArray := [64]byte{}
	copy(privateKeyByteArray[:], ed25519PrivateKey)
	publicKeyByteArray := [32]byte{}
	copy(publicKeyByteArray[:], ed25519PublicKey)

	return publicKeyByteArray, privateKeyByteArray
}

