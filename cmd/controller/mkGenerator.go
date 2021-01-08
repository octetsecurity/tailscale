package main


import (
	"fmt"
	"tailscale.com/types/wgkey"

)

func main() {
	machineKey, _ := wgkey.NewPrivate()

	fmt.Printf(machineKey.Public().HexString())
	// b7c250e602f94f9b752ba6dbac502db03ebc428705a1a5e08c8f523b1994016e
	//
}

