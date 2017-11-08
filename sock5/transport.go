package sock5

import (
	"log"
	"net"
)

const (
	Local Kind = iota
	Server
)

type (
	Kind int

	Transporter interface {
		WriteToRemote([]byte) (int, error)

		ReadFromRemote() ([]byte, error)

		WriteToClient([]byte) (int, error)

		ReadFromClient() ([]byte, error)

		Pipe()
	}

	SecureTransport struct {
		remote net.Conn
		client net.Conn

		crypto  Crypto
		running bool
		kind    Kind
	}
)

func NewSecureTransport(r, c net.Conn, k Kind, crypto Crypto) *SecureTransport {
	return &SecureTransport{
		remote: r,
		client: c,
		crypto: crypto,
		kind:   k,
	}
}

func (st *SecureTransport) WriteToRemote(b []byte) (int, error) {
	if st.crypto != nil && st.kind == Local {
		b = st.crypto.Encrypto(b)
	}

	n, err := st.remote.Write(b)
	if err != nil {
		log.Println(err)
	}
	return n, err
}

func (st *SecureTransport) WriteToClient(b []byte) (int, error) {
	if st.crypto != nil && st.kind == Server {
		b = st.crypto.Encrypto(b)
	}

	n, err := st.client.Write(b)
	if err != nil {
		log.Println(err)
	}
	return n, err
}

func (st *SecureTransport) ReadFromRemote() ([]byte, error) {
	b := make([]byte, ServerConfig.TcpBufferSize)
	n, err := st.remote.Read(b)
	if err != nil {
		log.Println(err)
	}

	data := b[:n]
	if st.crypto != nil && st.kind == Local {
		data = st.crypto.Decrypto(b[:n])
	}
	return data, err
}

func (st *SecureTransport) ReadFromClient() ([]byte, error) {
	b := make([]byte, ServerConfig.TcpBufferSize)
	n, err := st.client.Read(b)
	if err != nil {
		log.Println(err)
	}

	data := b[:n]
	if st.crypto != nil && st.kind == Server {
		data = st.crypto.Decrypto(b[:n])
	}

	return data, err
}

func (st *SecureTransport) Pipe() {
	defer func() {
		if p := recover(); p != nil {
			log.Println(p)
		}
	}()

	defer st.Close()

	go func() {
		for {
			b, err := st.ReadFromRemote()
			log.Printf("S->C %dbytes", len(b))
			if err != nil {
				break
			}
			st.WriteToClient(b)
		}
	}()

	for {
		b, err := st.ReadFromClient()
		log.Printf("C->S %dbytes", len(b))
		if err != nil {
			break
		}
		st.WriteToRemote(b)
	}
}

func (st *SecureTransport) Close() {
	st.client.Close()
	st.remote.Close()
}
