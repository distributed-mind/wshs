package main

import (
	"context"
	"encoding/base64"
	"fmt"
	"github.com/gorilla/websocket"
	"log"
	"net/http"
	"net/url"
	"os"
	"os/signal"

	"github.com/distributed-mind/wshs/client"
	"github.com/distributed-mind/wshs/server"
)

const (
	// client
	clientPublicKeyString  string = "rI1v1fBu/74+EL3RGOK4mIXC8mLBFPefg5HRJIsBr4w="
	clientPrivateKeyString string = "C7v4sggDQyHkCiLVHaSnMl3JsK6PmT6rSyzpO9A+gNysjW/V8G7/vj4QvdEY4riYhcLyYsEU95+DkdEkiwGvjA=="
	
	// server
	serverPublicKeyString  string = "Y8iEiWU3CuFQOqDeAW2Zo5UgaRa3a00dy3vZfIFb8RE="
	serverPrivateKeyString string = "GYZRWz6lbG+jQfO6sDCg4z+wvX43U8188+cl1arW8d1jyISJZTcK4VA6oN4BbZmjlSBpFrdrTR3Le9l8gVvxEQ=="
)

var (
	clientPublicKey  []byte
	clientPrivateKey []byte
	serverPublicKey  []byte
	serverPrivateKey []byte
	address = "127.0.0.10:8089"
	upgrader = websocket.Upgrader{
		ReadBufferSize:  1024,
		WriteBufferSize: 1024,
	}
)

func init() {
	clientPublicKey  = decodeBase64Key(clientPublicKeyString)
	clientPrivateKey = decodeBase64Key(clientPrivateKeyString)
	serverPublicKey  = decodeBase64Key(serverPublicKeyString)
	serverPrivateKey = decodeBase64Key(serverPrivateKeyString)
}

func main() {
	switch arg := os.Args[1]; arg {
	case "server":
		{
			runServer()
			return
		}
	case "client":
		{
			runClient()
			return
		}
	}
}

func decodeBase64Key(s string) []byte {
	k, err := base64.StdEncoding.DecodeString(s)
	if err != nil {
		log.Fatalf("%v\n", err)
	}
	return k
}

// ###########
// server
func runServer() {
	stop := make(chan os.Signal, 1)
	signal.Notify(stop, os.Interrupt)
	fmt.Printf("%v\n", "Running server...")
	mux := http.NewServeMux()
	mux.HandleFunc("/ws", ws)
	h := &http.Server{
		Addr: address,
		Handler: mux,
	}
	go func() {
		err := h.ListenAndServe()
		if err != nil {
			log.Fatalf("%v\n", err)
		}
	}()
	<-stop
	h.Shutdown(context.Background())
}


func ws(w http.ResponseWriter, r *http.Request) {
	upgrader.CheckOrigin = func(r *http.Request) bool {
		return true
	}
	ws, err := upgrader.Upgrade(w, r, nil)
	if err != nil {
		log.Println(err)
	}
	// log.Println("Client Connected")
	ok := server.Shake(
		ws,
		serverPublicKey,
		serverPrivateKey,
	)
	if ok {
		log.Printf("%s\n", "Handshake Success: server")
	} else {
		log.Printf("%s\n", "Handshake Fail: server")	
	}
}


// ###########
// client

func runClient() {
	u := url.URL{
		Scheme: "ws",
		Host: address,
		Path: "/ws",
	}
	fmt.Printf("%v\n", "Running client...")


	c, _, err := websocket.DefaultDialer.Dial(u.String(), nil)
	if err != nil {
		log.Fatal("dial:", err)
	}
	defer c.Close()


	cPublicKey := [32]byte{}
	copy(cPublicKey[:], clientPublicKey)
	cPrivateKey := [64]byte{}
	copy(cPrivateKey[:], clientPrivateKey)
	sPublicKey := [32]byte{}
	copy(sPublicKey[:], serverPublicKey)

	ok := client.Shake(
		c,
		cPublicKey,
		sPublicKey,
		cPrivateKey,
	)
	if ok {
		//
		log.Printf("%s\n", "Handshake Success: client")
	} else {
		log.Printf("%s\n", "Handshake Fail: client")
	}
}
