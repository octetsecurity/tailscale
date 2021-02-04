package main

import (
	"log"
	"net"
	"tailscale.com/derp/derphttp"
	"tailscale.com/types/key"
)

func main() {

	// Build client 2
	c2PrivKey := key.NewPrivate()
	c1PubKey := []byte("2ef34da45e83a02e6564f641f13fae83515d8b6b9238be9017f8a800d7678472")
	var dstPubKey [32]byte
	copy(dstPubKey[:], c1PubKey)

	log.Println("Client 2 dialing...")
	cout2, err := net.Dial("tcp", "159.65.73.98:3340")
	if err != nil {
		log.Fatal(err)
	}
	defer cout2.Close()
	// 2021.1.27: Jason: use derphttp
	// c2, err := derp.NewClient(c2PrivKey, cout2, brw2, log.Printf)
	c2, err := derphttp.NewClient(c2PrivKey, "http://159.65.73.98:3340/derp", log.Printf)
	if err != nil {
		log.Fatal(err)
	}
	for {
		msg := []byte("hello 0->1\n")
		if err := c2.Send(dstPubKey, msg); err != nil {
			log.Fatal(err)
		}
	//	m, err := c2.Recv()
	//	recvChan2 := make(chan []byte)
	//	if err != nil {
	//		log.Fatal(err)
	//	}
	//	log.Printf("Received message is: %s\n", m)
	//	switch m := m.(type) {
	//	default:
	//		log.Println("unexpected message type %T", m)
	//	case derp.PeerGoneMessage:
	//		log.Println("Peer gone")
	//	case derp.ReceivedPacket:
	//		if m.Source.IsZero() {
	//			log.Println("zero Source address in ReceivedPacket")
	//		}
	//		recvChan2 <- append([]byte(nil), m.Data...)
	//	}
	}
}