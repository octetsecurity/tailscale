package main

import (
	"log"
	"net"
)

func HandleConn(c net.Conn) {
	defer c.Close()

	// handle incoming data
	buffer := make([]byte, 1024)
	numBytes, err := c.Read(buffer)
	if err != nil {
		log.Fatal(err)
	}
	log.Println("received", numBytes, "bytes:", string(buffer))

	// handle reply
	msg := string(buffer[:numBytes]) + " back"
	_, err = c.Write([]byte(msg))
	if err != nil {
		log.Fatal(err)
	}
}

func main() {

	l, err := net.Listen("tcp", "0.0.0.0:8888")
	if err != nil {
		log.Fatal(err)
	}
	defer l.Close()

	// accept connection
	log.Println("Waiting for new connection...")
	conn, err := l.Accept()
	if err != nil {
		log.Fatal(err)
	}

	// handle connection
	go HandleConn(conn)

}
