package sock5

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	// "io"
	"log"
	"net"
	"strconv"
	"strings"
)

const (
	Sock5Version = 0x5

	CmdConnect byte = iota
	CmdBind
	CmdUdpAssociate
	CmdRsv

	AddressTypeIpv4   = 0x1
	AddressTypeDomain = 0x3
	AddressTypeIpv6   = 0x4
)

type (
	processor func([]byte) (processor, error)

	Protocol interface {
		Process()
	}

	serverProtocol struct {
		conn             net.Conn
		processor        processor
		remoteAddress    string
		remoteAddressRaw []byte
		transport        Transporter
	}
)

func NewServerProtocol(conn net.Conn) Protocol {
	sp := &serverProtocol{
		conn: conn,
	}
	sp.processor = sp.handshake
	return sp
}

func (sp *serverProtocol) Process() {
	for {
		b := make([]byte, ServerConfig.TcpBufferSize)
		n, err := sp.conn.Read(b)
		if err != nil {
			log.Println(err)
			break
		}

		if next, err := sp.processor(b[:n]); err == nil {
			if next != nil {
				sp.processor = next
			} else {
				//to transport
				remote, err := net.Dial("tcp", sp.remoteAddress)

				if err != nil {
					sp.conn.Write([]byte{Sock5Version, 0x04, 0x00, AddressTypeIpv4})
					// sp.conn.Write(sp.remoteAddressRaw)
					goto CLOSE
				}
				resp := []byte{Sock5Version, 0x00, 0x00, AddressTypeIpv4}
				resp = append(resp, sp.remoteAddressRaw...)
				log.Println(resp)
				// sp.conn.Write([]byte{Sock5Version, 0x00, 0x00, AddressTypeIpv4})
				// sp.conn.Write(sp.remoteAddressRaw)
				sp.conn.Write(resp)

				log.Printf("Connect to remote %s", sp.remoteAddress)
				// cipher, err := NewRc4Md5Crypto(ServerConfig.User.Password)
				// if err != nil {
				// 	goto CLOSE
				// }
				sp.transport = NewSecureTransport(remote, sp.conn, Server, nil)
				break
			}
		} else {
			log.Println(err)
			sp.conn.Close()
			break
		}
	}

	if sp.transport != nil {
		log.Println("Pipe")
		sp.transport.Pipe()
	}

CLOSE:
	sp.conn.Close()
}

//ver
func (sp *serverProtocol) handshake(b []byte) (processor, error) {
	if b[0] != Sock5Version {
		return nil, errors.New("Is not sock5 protocol")
	}

	if ServerConfig.User != nil {
		sp.conn.Write([]byte{Sock5Version, AuthPassword})
		return sp.auth, nil
	}

	sp.conn.Write([]byte{Sock5Version, AuthNone})
	return sp.request, nil
}

//ver nname name  npassword  password
// 1   1      n       1          n
func (sp *serverProtocol) auth(b []byte) (processor, error) {
	nameLen := b[1]
	name := b[2 : 2+nameLen]
	passwordLen := b[2+nameLen]
	password := b[2+nameLen : 2+nameLen+passwordLen]

	if string(name) != ServerConfig.User.Name || string(password) != ServerConfig.User.Password {
		sp.conn.Write([]byte{Sock5Version, AuthRefuse})
		return nil, errors.New("username or password unmatch")
	}
	sp.conn.Write([]byte{Sock5Version, AuthPass})
	return sp.request, nil
}

/*
req
+----+-----+-------+------+----------+----------+
  | VER| CMD | RSV   | ATYP |  DST.ADDR|  DST.PORT|
  +----+-----+-------+------+----------+----------+
  | 1  | 1   | X'00' | 1    | variable |      2   |
  +----+-----+-------+------+----------+----------+
resp
+----+-----+-------+------+----------+----------+
 |VER | REP |  RSV  | ATYP | BND.ADDR | BND.PORT |
 +----+-----+-------+------+----------+----------+
 | 1  |  1  | X'00' |  1   | Variable |    2     |
 +----+-----+-------+------+----------+----------+
*/

func (sp *serverProtocol) request(b []byte) (processor, error) {
	cmd := b[1]
	if cmd != CmdConnect {
		return nil, errors.New("Command unsupported")
	}

	atype := b[3]
	switch atype {
	case AddressTypeIpv4:
		ip := net.IPv4(b[4], b[5], b[6], b[7])
		var port uint16
		buf := bytes.NewBuffer(b[6:8])
		err := binary.Read(buf, binary.BigEndian, &port)
		if err != nil {
			return nil, err
		}
		sp.remoteAddress = fmt.Sprintf("%s:%d", ip.String(), port)
		sp.remoteAddressRaw = b[4:10]

	case AddressTypeDomain:
		domainLen := b[4]
		domain := b[5 : domainLen+5]
		addr, err := net.LookupHost(string(domain))
		log.Printf("Remote target %s", string(domain))
		if err != nil {
			return nil, errors.New("Invalid domain")
		}

		var port uint16
		r := bytes.NewBuffer(b[domainLen+5 : domainLen+7])
		binary.Read(r, binary.BigEndian, &port)
		sp.remoteAddress = fmt.Sprintf("%s:%d", addr[0], port)
		ip := convertIP(addr[0])
		if ip == nil {
			return nil, errors.New("Convert domain to ip failure")
		}
		sp.remoteAddressRaw = append(ip, b[domainLen+5:domainLen+7]...)

	case AddressTypeIpv6:
		return nil, errors.New("Unsupport ipv6")
	}

	return nil, nil
}

func convertIP(ip string) (b []byte) {
	as := strings.Split(ip, ".")
	if len(as) != 4 {
		return
	}
	for _, a := range as {
		n, err := strconv.Atoi(a)
		if err != nil {
			return
		}
		b = append(b, byte(n))
	}
	return
}
