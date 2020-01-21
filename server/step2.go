package server

import (
	"log"
	"crypto/hmac"
	"crypto/sha512"
	"github.com/gorilla/websocket"
)

// Write2 server send (server hello): 
// server responds to client-initiated
// connection, sends msg2
func Write2(conn *websocket.Conn, serverEphemeralPublicKey, networkKey [32]byte) ([]byte, bool) {
	// concat(
	// 	 nacl_auth(
	// 	   msg: server_ephemeral_pk,
	// 	   key: network_identifier
	// 	 ),
	// 	 server_ephemeral_pk
	// )

	h := hmac.New(sha512.New, networkKey[:32])
	_, err := h.Write(serverEphemeralPublicKey[:])
	if err != nil {
		log.Fatalf("hmac write error: %v\n", err)
		conn.Close()
		return nil, false
	}
	serverHmac := h.Sum(nil)[:32]
	msg2 := append(serverHmac, serverEphemeralPublicKey[:]...)
	err = conn.WriteMessage(websocket.BinaryMessage, msg2)
	if err != nil {
		log.Fatalf("write msg2 error: %v", err)
		conn.Close()
		return nil, false
	}

	return msg2, true
}
