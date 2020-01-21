package client

import (
	"log"
	"crypto/sha256"
	"golang.org/x/crypto/nacl/box"
	"github.com/gorilla/websocket"
)


// Write3 client send (client authenticate):
// responds to server-hello with msg3 naclbox 
func Write3(
	conn *websocket.Conn,
	clientLongTermPublicIdentity,
	networkKey,
	secretab,
	secretaB [32]byte,
	signatureA []byte) ([]byte, bool) {
	// nacl_secret_box(
	//   msg: concat(
	// 	   detached_signature_A,
	// 	   client_longterm_pk
	//   ),
	//   nonce: 24_bytes_of_zeros,
	//   key: sha256(
	// 	   concat(
	// 	     network_identifier,
	// 	     shared_secret_ab,
	// 	     shared_secret_aB
	// 	   )
	//   )
	// )

	msg := append(signatureA, clientLongTermPublicIdentity[:]...)
	nonce := [24]byte{}
	h := sha256.New()
	h.Write(networkKey[:])
	h.Write(secretab[:])
	h.Write(secretaB[:])
	key := [32]byte{}
	copy(key[:], h.Sum(nil))
	msg3 := []byte{}
	msg3 = box.SealAfterPrecomputation(msg3, msg, &nonce, &key)
	if len(msg3) != 112 {
		log.Println("msg3 length error: not 112 bytes")
		conn.Close()
		return nil, false		
	}
	err := conn.WriteMessage(websocket.BinaryMessage, msg3)
	if err != nil {
		log.Println("Write Message Error: ", err)
		conn.Close()
		return nil, false
	}
	return msg3, true
}
