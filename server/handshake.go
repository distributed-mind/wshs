package server

import (
	"github.com/distributed-mind/wshs"
	"github.com/gorilla/websocket"
)

var (
	// Meta .
	Meta struct {
		LocalLongTermEd25519PrivateKey     [64]byte
		LocalLongTermEd25519PublicKey      [32]byte
		RemoteLongTermEd25519PublicKey     [32]byte
		LocalEphemeralCurve25519PrivateKey [32]byte
		LocalEphemeralCurve25519PublicKey  [32]byte
		RemoteEphemeralCurve25519PublicKey [32]byte
		NetworkKey		     			   [32]byte
		Message1Received   				   []byte
		Message2Sent                       []byte
		Message3Received   				   []byte
		Message4Sent                       []byte
		Secretab 						   [32]byte	
		SecretaB 						   [32]byte	
		SecretAb 						   [32]byte
		SecretabHash					   []byte	
		SecretaBHash 					   []byte	
		SecretAbHash 					   []byte
		SignatureA 						   []byte
		SignatureB 						   []byte
	}
)

// Shake .
func Shake(
	conn *websocket.Conn,
	localPublicIdentity,
	localPrivateKey []byte) (ok bool) {

	copy(Meta.LocalLongTermEd25519PublicKey[:], localPublicIdentity)
	copy(Meta.LocalLongTermEd25519PrivateKey[:], localPrivateKey)

	pub, priv := wshs.GenerateEphemeralCurve25519KeyPair()
	Meta.LocalEphemeralCurve25519PublicKey  = pub
	Meta.LocalEphemeralCurve25519PrivateKey = priv
	Meta.NetworkKey = wshs.NetworkKeyBytes

	msg1, clientEphemeralPubKey, ok := Read1(conn, Meta.NetworkKey)
	if ok {
		Meta.Message1Received = msg1
		copy(Meta.RemoteEphemeralCurve25519PublicKey[:], clientEphemeralPubKey)
	} else {
		conn.Close()
		return false
	}

	msg2, ok := Write2(conn, Meta.LocalEphemeralCurve25519PublicKey, Meta.NetworkKey)
	if ok {
		Meta.Message2Sent = msg2
	} else {
		conn.Close()
		return false
	}

	s1, s2, h1, h2 := DeriveSharedABSecrets(
		Meta.LocalEphemeralCurve25519PrivateKey,
		Meta.RemoteEphemeralCurve25519PublicKey,
		wshs.PrivateKeyToCurve25519(Meta.LocalLongTermEd25519PrivateKey),
	)

	Meta.Secretab = s1
	Meta.SecretaB = s2
	Meta.SecretabHash = h1
	Meta.SecretaBHash = h2

	msg3, clientID, sigA, ok := Read3(
		conn,
		Meta.NetworkKey,
		Meta.LocalLongTermEd25519PublicKey,
		Meta.Secretab,
		Meta.SecretaB,
	)
	if ok {
		Meta.Message1Received = msg3
		Meta.SignatureA = sigA
		copy(Meta.RemoteLongTermEd25519PublicKey[:], clientID)
	} else {
		conn.Close()
		return false
	}
	Ab, Abhash := DeriveThirdSharedABSecret(
		Meta.LocalEphemeralCurve25519PrivateKey,
		wshs.PublicKeyToCurve25519(Meta.RemoteLongTermEd25519PublicKey),
	)

	Meta.SecretAb = Ab
	Meta.SecretAbHash = Abhash

	sb := SignatureB(
		Meta.NetworkKey,
		Meta.RemoteLongTermEd25519PublicKey,
		Meta.SecretabHash,
		Meta.LocalLongTermEd25519PrivateKey,
		Meta.SignatureA,
	)
	Meta.SignatureB = sb

	msg4, ok := Write4(
		conn,
		Meta.RemoteLongTermEd25519PublicKey,
		Meta.NetworkKey,
		Meta.Secretab,
		Meta.SecretaB,
		Meta.SecretAb,
		Meta.SignatureB,
	)
	if ok {
		Meta.Message2Sent = msg4
	} else {
		conn.Close()
		return false
	}
	
	return true	
}

