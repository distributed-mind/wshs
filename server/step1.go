package server

import (
	"log"
	"crypto/hmac"
	"crypto/sha512"
	"github.com/gorilla/websocket"
)

// Read1 server receive (client hello): server receives connection
// initiated by client, server verifies hmac, receives msg1
func Read1(conn *websocket.Conn, networkKey [32]byte) (msg1, clientEphemeralPublicKey[]byte, success bool) {
	// assert(length(msg1) == 64)
	//
	// client_hmac = first_32_bytes(msg1)
	// client_ephemeral_pk = last_32_bytes(msg1)
	//
	// assert_nacl_auth_verify(
	//   authenticator: client_hmac,
	//   msg: client_ephemeral_pk,
	//   key: network_identifier
	// )

	_, msg1, err := conn.ReadMessage()
	if err != nil {
		log.Println(err)
		conn.Close()
		return nil, nil, false
	}
	if len(msg1) != 64 {
		log.Fatalf("read msg1 length fail: must be 64 bytes\n")
		conn.Close()
		return nil, nil, false
	}
	clientHmac := msg1[:32]
	clientEphemeralPublicKey = msg1[32:]
	h := hmac.New(sha512.New, networkKey[:])
	h.Write(clientEphemeralPublicKey)
	ok := hmac.Equal(h.Sum(nil)[:32], clientHmac)
	if !ok {
		log.Fatalf("Hmac verify fail\n")
		conn.Close()
		return nil, nil, false
	}

	// succeed read step1
	return msg1, clientEphemeralPublicKey, true
}