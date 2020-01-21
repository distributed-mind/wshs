package client

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
		Message1Sent    				   []byte
		Message2Received				   []byte
		Message3Sent    				   []byte
		Message4Received				   []byte
		Secretab 						   [32]byte	
		SecretaB 						   [32]byte	
		SecretAb 						   [32]byte
		SecretabHash					   []byte	
		SecretaBHash 					   []byte	
		SecretAbHash 					   []byte
		SignatureA 						   []byte
		SignatureB 						   []byte
		FinalSharedSecret                  []byte
	}
)

// Shake client handshake
func Shake(
	conn *websocket.Conn,
	localPublicIdentity,
	remoteIdentity [32]byte,
	localPrivateKey [64]byte) (bool) {

	Meta.LocalLongTermEd25519PublicKey = localPublicIdentity
	Meta.LocalLongTermEd25519PrivateKey = localPrivateKey
	Meta.RemoteLongTermEd25519PublicKey = remoteIdentity
	pub, priv := wshs.GenerateEphemeralCurve25519KeyPair()
	Meta.LocalEphemeralCurve25519PublicKey  = pub
	Meta.LocalEphemeralCurve25519PrivateKey = priv
	Meta.NetworkKey = wshs.NetworkKeyBytes
	msg1, ok := Write1(conn, Meta.LocalEphemeralCurve25519PublicKey, Meta.NetworkKey)
	if ok {
		Meta.Message1Sent = msg1
	} else {
		conn.Close()
		return false
	}
	msg2, serverEphermeralPub, ok := Read2(conn, Meta.NetworkKey)
	if ok {
		Meta.Message2Received = msg2
		copy(Meta.RemoteEphemeralCurve25519PublicKey[:], serverEphermeralPub)
	} else {
		conn.Close()
		return false
	}

	ab, aB, abHash, aBHash := DeriveSharedABSecrets(
		Meta.LocalEphemeralCurve25519PrivateKey,
		Meta.RemoteEphemeralCurve25519PublicKey,
		wshs.PublicKeyToCurve25519(Meta.RemoteLongTermEd25519PublicKey),
	)

	Meta.Secretab = ab
	Meta.SecretaB = aB
	Meta.SecretabHash = abHash
	Meta.SecretaBHash = aBHash

	tmpHash := [32]byte{}
	copy(tmpHash[:], Meta.SecretabHash)

	Meta.SignatureA = SignatureA(
		Meta.NetworkKey,
		Meta.RemoteLongTermEd25519PublicKey,
		tmpHash,
		Meta.LocalLongTermEd25519PrivateKey,
	)

	msg3, ok := Write3(
		conn, 
		Meta.LocalLongTermEd25519PublicKey, 
		Meta.NetworkKey,
		Meta.Secretab,
		Meta.SecretaB,
		Meta.SignatureA,
	)
	if ok {
		Meta.Message3Sent = msg3
	} else {
		conn.Close()
		return false
	}

	Ab, Abhash := DeriveThirdSharedABSecret(
		wshs.PrivateKeyToCurve25519(Meta.LocalLongTermEd25519PrivateKey),
		Meta.RemoteEphemeralCurve25519PublicKey,
	)
	
	Meta.SecretAb = Ab
	Meta.SecretAbHash = Abhash

	msg4, finalKey, ok := Read4(
		conn,
		Meta.NetworkKey,
		Meta.Secretab,
		Meta.SecretaB,
		Meta.SecretAb,
		Meta.LocalLongTermEd25519PublicKey,
		Meta.RemoteLongTermEd25519PublicKey,
		Meta.SignatureA,
	)
	if ok {
		Meta.Message4Received = msg4
		Meta.FinalSharedSecret = finalKey
	} else {
		conn.Close()
		return false
	}
	
	return true	
}

