package client

import (
	"log"
	"crypto/hmac"
	"crypto/sha512"
	"github.com/gorilla/websocket"
)

// Write1 client sends (client hello): client 
// initiates connection, msg1
func Write1(conn *websocket.Conn, clientEphemeralPublicKey, networkKey [32]byte) ([]byte, bool) {
	// concat(
	//    nacl_auth(
	//    	msg: client_ephemeral_pk,
	//		key: network_identifier
	//	  ),
	//    client_ephemeral_pk
	// )

	h := hmac.New(sha512.New, networkKey[:])
	_, err := h.Write(clientEphemeralPublicKey[:])
	if err != nil {
		log.Fatalf("hmac write error: %v\n", err)
		conn.Close()
		return nil, false
	}
	clientHmac := h.Sum(nil)[:32]
	msg1 := append(clientHmac, clientEphemeralPublicKey[:32]...)
	if len(msg1) != 64 {
		log.Fatalf("build msg1 length fail: must be 64 bytes\n")
		conn.Close()
		return nil, false
	}
	err = conn.WriteMessage(websocket.BinaryMessage, msg1)
	if err != nil {
		log.Fatalf("write msg1 error: %v", err)
		conn.Close()
		return nil, false
	}
	// succeed write step1
	return msg1, true
}