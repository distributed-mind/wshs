package client


import (
	"log"
	"crypto/hmac"
	"crypto/sha512"
	"github.com/gorilla/websocket"
)


// Read2 client receive (server hello): client receives connection
// in response to client-hello, client verifies server-hmac, receives msg2
func Read2(conn *websocket.Conn, networkKey [32]byte) (msg2, serverEphemeralPK []byte, success bool) {
	// assert(length(msg2) == 64)
    //
	// server_hmac = first_32_bytes(msg2)
	// server_ephemeral_pk = last_32_bytes(msg2)
    //
	// assert_nacl_auth_verify(
	//   authenticator: server_hmac,
	//   msg: server_ephemeral_pk,
	//   key: network_identifier
	// )

	_, msg2, err := conn.ReadMessage()
	if err != nil {
		log.Fatalf("read msg2 error: %v\n", err)
		conn.Close()
		return nil, nil, false
	}
	if len(msg2) != 64 {
		log.Fatalf("msg2 length fail: must be 64 bytes\n")
		conn.Close()
		return nil, nil, false
	}
	serverHmac := msg2[:32]
	serverEphemeralPK = msg2[32:]
	h := hmac.New(sha512.New, networkKey[:32])
	h.Write(serverEphemeralPK)
	ok := hmac.Equal(h.Sum(nil)[:32], serverHmac)
	if !ok {
		log.Fatalf("hmac verify fail\n")
		conn.Close()
		return nil, nil, false
	}
	return msg2, serverEphemeralPK, true
}
