package server

import (
	"log"
	"crypto/ed25519"
	"crypto/sha256"
	"golang.org/x/crypto/curve25519"
)

// DeriveSharedABSecrets server calculates secrets ab and aB
func DeriveSharedABSecrets(
		serverEphemeralCurve25519PrivateKey,
		clientEphemeralCurve25519PublicKey,
		serverLongTermEd25519PrivateKeyToCurve [32]byte,
	) (s1, s2 [32]byte, h1, h2 []byte) {
	// shared_secret_ab = nacl_scalarmult(
	//   server_ephemeral_sk,
	//   client_ephemeral_pk
	// )
    //
	// shared_secret_aB = nacl_scalarmult(
	//   sk_to_curve25519(server_longterm_sk),
	//   client_ephemeral_pk
	// )

	sharedSecretab := [32]byte{}
	curve25519.ScalarMult(&sharedSecretab, &serverEphemeralCurve25519PrivateKey, &clientEphemeralCurve25519PublicKey)
	hash1 := sha256.New()
	_, err := hash1.Write(sharedSecretab[:])
	if err != nil {
		log.Fatalf("Write hash Error: %v", err)
		return [32]byte{}, [32]byte{}, nil, nil
	}
	secret1Hash := hash1.Sum(nil)

	sharedSecretaB := [32]byte{}
	curve25519.ScalarMult(&sharedSecretaB, &serverLongTermEd25519PrivateKeyToCurve, &clientEphemeralCurve25519PublicKey)
	hash2 := sha256.New()
	_, err = hash2.Write(sharedSecretaB[:])
	if err != nil {
		log.Fatalf("Write hash Error: %v", err)
		return [32]byte{}, [32]byte{}, nil, nil
	}
	secret2Hash := hash2.Sum(nil)

	return sharedSecretab, sharedSecretaB, secret1Hash, secret2Hash
}


// DeriveThirdSharedABSecret server calculates last secret Ab
func DeriveThirdSharedABSecret(
	serverEphemeralCurve25519PrivateKey,
	clientLongTermEd25519PublicKeyToCurve [32]byte) ([32]byte, []byte) {
	// shared_secret_Ab = nacl_scalarmult(
	// 	 server_ephemeral_sk,
	// 	 pk_to_curve25519(client_longterm_pk)
	// )
	sharedSecretAb := [32]byte{}
	curve25519.ScalarMult(&sharedSecretAb, &serverEphemeralCurve25519PrivateKey, &clientLongTermEd25519PublicKeyToCurve)
	hash := sha256.New()
	_, err := hash.Write(sharedSecretAb[:])
	if err != nil {
		log.Fatalf("Write hash Error: %v", err)
		return [32]byte{}, nil

	}
	secretHash := hash.Sum(nil)
	return sharedSecretAb, secretHash
}


// SignatureB server signs network key, shared secret, and client sig
func SignatureB(
	networkKey,
	clientLongTermEd25519PublicKey [32]byte,
	sharedSecretHash []byte,
	serverEd25519PrivateKey [64]byte,
	signatureA []byte) []byte {
	// detached_signature_B = nacl_sign_detached(
	//   msg: concat(
	// 	   network_identifier,
	// 	   detached_signature_A,
	// 	   client_longterm_pk,
	// 	   sha256(shared_secret_ab)
	//   ),
	//   key: server_longterm_sk
	// )

	b := append(networkKey[:], signatureA[:]...)
	b = append(b, clientLongTermEd25519PublicKey[:]...)
	b = append(b, sharedSecretHash[:]...)
	signature := ed25519.Sign(serverEd25519PrivateKey[:], b)
	return signature
}
