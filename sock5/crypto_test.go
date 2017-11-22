package sock5

import (
	"crypto/rc4"
	"fmt"
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
}

func Test_Rc4Md5(t *testing.T) {
	src := `
	{"id":"","segs":{"FLV-HD":[{"url":"http://k.youku.com/player/getFlvPath/sid/051071641273612d60812/st/flv/fileid/030002010059089E0280150000000166679156-192A-41C7-42B2-1B04AC652F3D?k=694776922b903a84282cd2a0\u0026hd=0\u0026myp=0\u0026ts=51\u0026ctype=12\u0026ev=1\u0026token=0534\u0026oip=1783312517\u0026ep=cieVGk6MUMoB5yTcjj8bMyrifHYNXP4J9h%2BFg9JjALshQei3kEvRxZWwT%2FpCFvkZciIGEe33rdfu%0Aa0USYfFKqxkQ20%2FbPvrk%2FILh5awhxJRxFR8zcLvUwFSeRjP1\u0026ccode=0401\u0026duration=50\u0026expire=18000\u0026psid=5c76bdc9fd9ed530316fa8c12c0d2685\u0026ups_client_netip=6a4b3085\u0026ups_ts=1510716412\u0026ups_userid=\u0026utid=%2FKGSEr7IjgQCAWpLMIXQtGPr\u0026vid=XMjc1NDk4MzgxNg%3D%3D\u0026vkey=Ab7e30f49b8f0dfb90463da96d9fbbbb6","size":1891688,"number":0,"seconds":50.533}],"MP4-HD-Mobile-M3u8":[{"url":"http://pl-ali.youku.com/playlist/m3u8?vid=XMjc1NDk4MzgxNg%3D%3D\u0026type=flv\u0026ups_client_netip=6a4b3085\u0026ups_ts=1510716412\u0026utid=%2FKGSEr7IjgQCAWpLMIXQtGPr\u0026ccode=0401\u0026psid=5c76bdc9fd9ed530316fa8c12c0d2685\u0026duration=50\u0026expire=18000\u0026ups_key=f7178d729fd6dfe0ac6dadd820cce623","size":0,"number":0,"seconds":50.533}]},"detail":{"name":"小伙街头撩妹以为占了大便宜,妹子说出了自己的职业小伙转身就跑","tags":[""],"categories":["94"],"site":"youku.com","logo":"https://vthumb.ykimg.com/0541040859261CBC1E58374305070414"},"use_time":0.26280305200000004,"parse_time":1510716412,"site":""}
	`
	iv := []byte{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 0, 1, 2, 3, 4, 5}

	cipher := NewRc4Md5Crypto("111111", iv)
	b := cipher.Encrypto([]byte(src))
	t.Logf("%x", b)

	if len(b) != len(src) {
		t.Fatalf("Crypto length error, expect: %d, got: %d", len(src), len(b))
	}

	if string(cipher.Decrypto(b)) != src {
		t.Fatal("Decrypto error")
	}
}

func Test_Rc4Md5Decrypto(t *testing.T) {
	src := []byte{199, 224, 195, 124, 148, 185, 205, 91, 197, 6, 19, 131, 130, 142, 178, 113, 176, 50, 243, 205, 21, 7, 40, 254, 112, 148, 152, 196, 199, 69, 243, 59, 24, 172, 33, 29, 203, 62, 78, 252, 176, 129, 161, 118, 240, 194, 247, 53, 231, 162, 208, 170, 119, 182, 226, 214, 151, 142, 108, 32, 229, 118, 181, 152, 80, 30, 35, 214, 220, 241, 50, 145, 8, 74, 240, 255, 180, 32, 79, 104, 131, 164, 67, 101, 47, 23, 153, 141, 35, 5, 238, 164, 24, 3, 170, 85, 245, 147, 170, 77, 24, 165, 230, 246, 110, 187, 14, 192, 111, 46, 206, 225, 16, 109, 98, 221, 78, 143, 188, 104, 238, 80, 182, 207, 47, 112, 99, 187, 137, 54, 32, 138, 164, 172, 252, 206, 71, 190, 134, 121, 80, 165, 94, 195, 115, 85, 8, 77, 54, 30, 185, 18, 91, 45, 78, 224, 175, 78, 251, 61, 236, 56, 245, 106, 19, 21, 41, 47}
	iv := []byte{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 0, 1, 2, 3, 4, 5}
	pw := "111111"
	cipher := NewRc4Md5Crypto(pw, iv)
	c, _ := rc4.NewCipher(cipher.rc4md5Key)
	s := make([]byte, len(src))
	copy(s, src)
	t.Log(cipher.Decrypto(s))
	dst := make([]byte, len(src))
	c.XORKeyStream(dst, src)
	t.Log(dst)
}
