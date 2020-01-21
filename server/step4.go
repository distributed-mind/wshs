package server

import (
	"log"
	"crypto/sha256"
	"github.com/gorilla/websocket"
	"golang.org/x/crypto/nacl/box"
)


// Write4 server send (server accept):
// responds to client-authenticate with msg4 naclbox 
func Write4(
	conn *websocket.Conn,
	clientLongTermPublicIdentity,
	networkKey,
	secretab,
	secretaB,
	secretAb [32]byte,
	signatureB []byte) ([]byte, bool) {
	// nacl_secret_box(
	// 	 msg: detached_signature_B,
	// 	 nonce: 24_bytes_of_zeros,
	// 	 key: sha256(
	// 	   concat(
	// 	     network_identifier,
	// 	     shared_secret_ab,
	// 		 shared_secret_aB,
	// 		 shared_secret_Ab
	// 	   )
	// 	 )
	// )

	// calculate naclbox key
	h := sha256.New()
	h.Write(networkKey[:])
	h.Write(secretab[:])
	h.Write(secretaB[:])
	h.Write(secretAb[:])
	key := [32]byte{}
	copy(key[:],  h.Sum(nil))

	// nonce
	nonce := [24]byte{}

	// msg
	msg4 := []byte{}
	msg4 = box.SealAfterPrecomputation(msg4, signatureB, &nonce, &key)
	if len(msg4) != 80 {
		log.Println("msg4 length error: not 80 bytes")
		return nil, false		
	}
	err := conn.WriteMessage(websocket.BinaryMessage, msg4)
	if err != nil {
		log.Println("Write Message Error: ", err)
		return nil, false
	}
	return msg4, true
}
