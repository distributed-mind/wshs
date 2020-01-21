package client

import (
	"log"
	"crypto/ed25519"
	"crypto/sha256"
	"golang.org/x/crypto/curve25519"
)

// SignatureA client signs target network key, 
// and public id, and hash of shared secret
func SignatureA(
	networkKey,
	serverLongTermPublicIdentity,
	sharedSecretHash [32]byte,
	clientEd25519PrivateKey [64]byte) ([]byte) {
	// detached_signature_A = nacl_sign_detached(
	//   msg: concat(
	// 	   network_identifier,
	// 	   server_longterm_pk,
	// 	   sha256(shared_secret_ab)
	//   ),
	//   key: client_longterm_sk
	// )

	b := append(networkKey[:], serverLongTermPublicIdentity[:]...)
	b = append(b, sharedSecretHash[:]...)
	signature := ed25519.Sign(clientEd25519PrivateKey[:], b)
	return signature
}


// DeriveSharedABSecrets client calculates secrets ab and aB
func DeriveSharedABSecrets(
	clientEphemeralCurve25519PrivateKey,
	serverEphemeralCurve25519PublicKey,
	serverLongTermPublicIdentitytoCurve [32]byte) (s1, s2 [32]byte, h1, h2 []byte) {
	// shared_secret_ab = nacl_scalarmult(
	//   client_ephemeral_sk,
	//   server_ephemeral_pk
	// )
    //
	// shared_secret_aB = nacl_scalarmult(
	//   client_ephemeral_sk,
	//   pk_to_curve25519(server_longterm_pk)
	// )

	sharedSecretab := [32]byte{}
	curve25519.ScalarMult(&sharedSecretab, &clientEphemeralCurve25519PrivateKey, &serverEphemeralCurve25519PublicKey)
	hash1 := sha256.New()
	_, err := hash1.Write(sharedSecretab[:])
	if err != nil {
		log.Fatalf("Write hash Error: %v", err)
		return [32]byte{}, [32]byte{}, nil, nil
	}
	secret1Hash := hash1.Sum(nil)
	sharedSecretaB := [32]byte{}
	curve25519.ScalarMult(&sharedSecretaB, &clientEphemeralCurve25519PrivateKey, &serverLongTermPublicIdentitytoCurve)
	hash2 := sha256.New()
	_, err = hash2.Write(sharedSecretaB[:])
	if err != nil {
		log.Fatalf("Write hash Error: %v", err)
		return [32]byte{}, [32]byte{}, nil, nil
	}
	secret2Hash := hash2.Sum(nil)
	return sharedSecretab, sharedSecretaB, secret1Hash, secret2Hash
}

// DeriveThirdSharedABSecret client calculates final secret Ab
func DeriveThirdSharedABSecret(
	clientLongTermSecretEd25519KeytoCurve,
	serverEphemeralCurve25519PublicKey [32]byte) ([32]byte, []byte) {
	// shared_secret_Ab = nacl_scalarmult(
	// 	 sk_to_curve25519(client_longterm_sk),
	// 	 server_ephemeral_pk
	// )

	sharedSecretAb := [32]byte{}
	curve25519.ScalarMult(&sharedSecretAb, &clientLongTermSecretEd25519KeytoCurve, &serverEphemeralCurve25519PublicKey)
	hash := sha256.New()
	_, err := hash.Write(sharedSecretAb[:])
	if err != nil {
		log.Fatalf("Write hash Error: %v", err)
		return [32]byte{}, nil
	}
	secretHash := hash.Sum(nil)
	return sharedSecretAb, secretHash
}
