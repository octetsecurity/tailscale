package main

import (
	"log"
	"net"
	"tailscale.com/derp"
	"tailscale.com/derp/derphttp"
	"tailscale.com/types/key"
)

func main() {

	// Build client 1
	c1PrivKey := key.NewPrivate()
	c1PubKey := c1PrivKey.Public()
	log.Println("Client 1 dialing...")
	log.Printf("Client 1's public key is: %x\n", c1PubKey)
	cout1, err := net.Dial("tcp", "159.65.73.98:3340")
	if err != nil {
		log.Fatal(err)
	}
	defer cout1.Close()
	// 2021.1.27: Jason: use derphttp
	// c1, err := derp.NewClient(c1PrivKey, cout1, brw1, log.Printf)
	c1, err := derphttp.NewClient(c1PrivKey, "http://159.65.73.98:3340/derp", log.Printf)
	if err != nil {
		log.Fatal(err)
	}
	for {
		m, err := c1.Recv()
		log.Printf("Received message is: %s\n", m)
		// 2021.2.3: Don't use chan.
		if err != nil {
			log.Fatal(err)
		}
		switch m := m.(type) {
		default:
			log.Println("unexpected message type %T", m)
		case derp.PeerGoneMessage:
			log.Println("Peer gone")
		case derp.ReceivedPacket:
			if m.Source.IsZero() {
				log.Println("zero Source address in ReceivedPacket")
			}
		}
	}
}