package main

import (
	"fmt"
	"log"
	"net"
	"whiteshadow/sock5"
)

func main() {
	if svr, err := net.Listen("tcp", fmt.Sprintf("%s:%d", "0.0.0.0", sock5.ServerConfig.Port)); err == nil {
		log.Printf("Listen sock5 server on %d", sock5.ServerConfig.Port)
		for {
			conn, err := svr.Accept()
			if err != nil {
				continue
			}
			log.Printf("Client %s connected.\n", conn.RemoteAddr().String())

			p := sock5.NewServerProtocol(conn)
			go p.Process()
		}
	} else {
		log.Fatal(err)
	}
}
