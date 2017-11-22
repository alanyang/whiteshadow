package main

import (
	"flag"
	"fmt"
	"log"
	"net"
	"whiteshadow/sock5"
)

var (
	Port       int
	BufferSize int

	Name     string
	Password string
)

func main() {
	flag.Parse()
	sock5.InitConfig(Name, Password, Port, BufferSize)
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

func init() {
	flag.IntVar(&Port, "port", 1080, "Server Listen Port")
	flag.IntVar(&BufferSize, "buffer", 2048, "Socket Buffer Size")

	flag.StringVar(&Name, "name", "", "User Name can be to empty")
	flag.StringVar(&Password, "password", "", "User password canbe to empty")
}
