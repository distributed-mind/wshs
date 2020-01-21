package server

import (
	"log"
	"crypto/sha256"
	"crypto/ed25519"
	"golang.org/x/crypto/nacl/box"
	"github.com/gorilla/websocket"
)


// Read3 server receive (client authenticate): server receives 
// response to server-hello, receives msg3 naclbox, unbox
func Read3(
	conn *websocket.Conn,
	networkKey,
	serverLongTermPublicKey,
	secretab,
	secretaB [32]byte) (msg3, clientID, sigA []byte, success bool) {
	// msg3_plaintext = assert_nacl_secretbox_open(
	// 	ciphertext: msg3,
	// 	nonce: 24_bytes_of_zeros,
	// 	key: sha256(
	// 		concat(
	// 		network_identifier,
	// 		shared_secret_ab,
	// 		shared_secret_aB
	// 		)
	// 	)
	// )
    //
	// assert(length(msg3_plaintext) == 96)
    //
	// detached_signature_A = first_64_bytes(msg3_plaintext)
	// client_longterm_pk = last_32_bytes(msg3_plaintext)
    //
	// assert_nacl_sign_verify_detached(
	// 	sig: detached_signature_A,
	// 	msg: concat(
	// 		network_identifier,
	// 		server_longterm_pk,
	// 		sha256(shared_secret_ab)
	// 	),
	// 	key: client_longterm_pk
	// )

	_, msg3, err := conn.ReadMessage()
	if err != nil {
		log.Fatalf("error reading msg3: %v\n", err)
		return nil, nil, nil, false
	}
	if len(msg3) != 112 {
		log.Fatalf("handshake read: fail length, msg3 must be 112 bytes\n")
		return nil, nil, nil, false
	}
	h := sha256.New()
	h.Write(networkKey[:])
	h.Write(secretab[:])
	h.Write(secretaB[:])
	key := [32]byte{}
	copy(key[:], h.Sum(nil))
	nonce := [24]byte{}
	openBox := []byte{}
	openBox, ok := box.OpenAfterPrecomputation(openBox, msg3, &nonce, &key)
	if !ok {
		log.Fatalf("open box: fail\n")
		return nil, nil, nil, false
	}
	if len(openBox) != 96 {
		log.Fatalf("open box: fail length, must be 96 bytes\n")
		return nil, nil, nil, false
	}
	clientSignatureA := openBox[:64]
	clientLongTermPublicIdentity := openBox[64:]
	h = sha256.New()
	h.Write(secretab[:])
	msg := append(networkKey[:], serverLongTermPublicKey[:]...)
	msg = append(msg, h.Sum(nil)...)
	ok = ed25519.Verify(clientLongTermPublicIdentity, msg, clientSignatureA)
	if !ok {
		log.Fatalf("ed25519 verify: fail\n")
		return nil, nil, nil, false
	}

	return msg3, clientLongTermPublicIdentity, clientSignatureA, true
}
