package sock5

import (
	"crypto/md5"
	"crypto/rc4"
	"log"
)

const (
	Rc4Md5KeySize = 16
	Rc4Md5IvSize  = 16
)

type (
	Crypto interface {
		Encrypto([]byte) []byte

		Decrypto([]byte) []byte

		GetIv() []byte
	}

	Rc4Md5Crypto struct {
		key       []byte
		iv        []byte
		rc4md5Key []byte
		cipher    *rc4.Cipher
	}
)

func md5sum(d []byte) []byte {
	h := md5.New()
	h.Write(d)
	return h.Sum(nil)
}

func evpBytesToKey(password string, keyLen, ivLen int) (key, iv []byte) {
	const md5Len = 16

	cnt := (keyLen+ivLen-1)/md5Len + 1
	m := make([]byte, cnt*(md5Len+ivLen))
	copy(m, md5sum([]byte(password)))

	d := make([]byte, md5Len+len(password))
	start := 0
	for i := 1; i < cnt; i++ {
		start += md5Len
		copy(d, m[start-md5Len:start])
		copy(d[md5Len:], password)
		copy(m[start:], md5sum(d))
	}
	key, iv = m[:keyLen], m[keyLen:keyLen+ivLen]
	return
}

func NewRc4Md5Crypto(raw string, iv []byte) *Rc4Md5Crypto {
	key, _ := evpBytesToKey(raw, Rc4Md5KeySize, Rc4Md5IvSize)

	h := md5.New()
	h.Write(key)
	h.Write(iv)

	k := h.Sum(nil)

	log.Printf("%x", k)
	cipher, err := rc4.NewCipher(k)
	if err != nil {
		return nil
	}
	return &Rc4Md5Crypto{cipher: cipher, key: key, iv: iv, rc4md5Key: k}
}

func (rm *Rc4Md5Crypto) md5Key() []byte {
	h := md5.New()
	h.Write(rm.key)
	h.Write(rm.iv)
	return h.Sum(nil)
}

func (rm *Rc4Md5Crypto) xor(b []byte) (d []byte) {
	// rm.cipher.Reset()
	cipher, _ := rc4.NewCipher(rm.md5Key())
	d = make([]byte, len(b))
	cipher.XORKeyStream(d, b)
	return
}

func (rm *Rc4Md5Crypto) Encrypto(b []byte) []byte {
	return rm.xor(b)
}

func (rm *Rc4Md5Crypto) Decrypto(b []byte) []byte {
	return rm.xor(b)
}

func (rm *Rc4Md5Crypto) GetIv() []byte {
	return rm.iv
}
