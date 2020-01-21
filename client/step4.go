package client

import (
	"log"
	"crypto/sha256"
	"crypto/ed25519"
	"github.com/gorilla/websocket"
	"golang.org/x/crypto/nacl/box"

)


// Read4 client receive (server accept): client receives 
// response to client-authenticate, receives msg4 naclbox, unbox
func Read4(
	conn *websocket.Conn,
	networkKey,
	secretab,
	secretaB,
	secretAb,
	clientLongTermPublicIdentity,
	serverLongTermPublicIdentity [32]byte,
	signatureA []byte) (msg4, finalKey []byte, success bool) {
	// detached_signature_B = assert_nacl_secretbox_open(
	//   ciphertext: msg4,
	//   nonce: 24_bytes_of_zeros,
	//   key: sha256(
	//     concat(
	// 	     network_identifier,
	// 	     shared_secret_ab,
	// 	     shared_secret_aB,
	// 	     shared_secret_Ab
	// 	   )
	//   )
	// )
    //
	// assert_nacl_sign_verify_detached(
	//   sig: detached_signature_B,
	//   msg: concat(
	// 	   network_identifier,
	// 	   detached_signature_A,
	// 	   client_longterm_pk,
	// 	   sha256(shared_secret_ab)
	//   ),
	//   key: server_longterm_pk
	// )

	_, msg4, err := conn.ReadMessage()
	if err != nil {
		log.Println(err)
		conn.Close()
		return nil, nil, false
	}
	if len(msg4) != 80 {
		log.Printf("handshake read: fail length, must be 80 bytes\n")
		conn.Close()
		return nil, nil, false
	}

	// calculate naclbox key
	h := sha256.New()
	h.Write(networkKey[:])
	h.Write(secretab[:])
	h.Write(secretaB[:])
	h.Write(secretAb[:])
	finalKey = h.Sum(nil)
	key := [32]byte{}
	copy(key[:], finalKey)

	// nonce
	nonce := [24]byte{}

	// open box msg4, using nonce and key, reveiling sigB 
	serverSignatureB := []byte{}
	serverSignatureB, ok := box.OpenAfterPrecomputation(serverSignatureB, msg4, &nonce, &key)
	if !ok {
		log.Printf("open box fail\n")
		conn.Close()
		return nil, nil, false
	}
	// verify server signature
	msg := append(networkKey[:], signatureA...)
	msg = append(msg, clientLongTermPublicIdentity[:]...)
	h = sha256.New()
	h.Write(secretab[:])
	msg = append(msg, h.Sum(nil)...)
	ok = ed25519.Verify(serverLongTermPublicIdentity[:], msg, serverSignatureB)
	if !ok {
		log.Printf("ed25519 verify server signature fail\n")
		conn.Close()
		return nil, nil, false
	}
	return msg4, finalKey, true
}
