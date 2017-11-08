package sock5

import (
	"fmt"
	"net"
	"testing"
)

func Test_PasswordToKey(t *testing.T) {
	expectKey := []byte{225, 10, 220, 57, 73, 186, 89, 171, 190, 86, 224, 87, 242, 15, 136, 62, 101, 180, 173, 39, 11, 59, 152, 9, 141, 37, 106, 179, 47, 91, 143, 186}
	expectIv := []byte{148, 144, 184, 120, 11, 25, 134, 215, 25, 96, 55, 232, 55, 192, 159, 22, 171, 9, 17, 91, 110, 142, 243, 213, 55, 69, 216, 83, 218, 113, 164, 233}

	password := "123456"
	keyLen, ivLen := 32, 32

	key, iv := evpBytesToKey(password, keyLen, ivLen)

	if fmt.Sprintf("%X", expectKey) != fmt.Sprintf("%X", key) {
		t.Fatalf("Crypto key error, expect: [%X] got: [%X]", expectKey, key)
	}
	if fmt.Sprintf("%X", expectIv) != fmt.Sprintf("%X", iv) {
		t.Fatalf("Crypto key error, expect: [%X] got: [%X]", expectIv, iv)
	}

	addr, err := net.LookupHost("videojj.com")
	t.Log(addr, err)
}
