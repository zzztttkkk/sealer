package sealer

import (
	"crypto/ed25519"
	"encoding/base64"
	"fmt"
	"math/rand/v2"
	"slices"
	"testing"
)

func TestSealer(t *testing.T) {
	sealer := New(":::::", Config{
		SignPrivateKey: "Mm9Gma0HgC7iNabXM4ej1RmKYO2NSjCvp+iMPI7NqcMgqokN/vQq9ffABibDTJdJHbNZCbYPLHdWed6Dlgrf0A==",
		SignPublicKey:  "IKqJDf70KvX3wAYmw0yXSR2zWQm2Dyx3Vnneg5YK39A=",
		Base64:         "V8AbrYwH6fEcFLmXxMUhaKZyjoTQes1d4Iz97l_qPC-kOt0WGJ5RpSNiD23gvuBn",
		AesKey:         "tZyn1Vc5TOlbWFJu",
	})
	txt, _ := sealer.Seal(map[string]string{"aaa": "4554"})
	fmt.Println(txt)
	fmt.Println(sealer.Open(txt, nil))
}

func TestGenKeys(t *testing.T) {
	pub, pri, _ := ed25519.GenerateKey(nil)
	fmt.Println("PRI: ", base64.StdEncoding.EncodeToString(pri))
	fmt.Println("PUB: ", base64.StdEncoding.EncodeToString(pub))
	bytes := []byte("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_")
	slices.SortFunc(bytes, func(a, b byte) int {
		if rand.IntN(10) > 5 {
			return 1
		}
		return -1
	})
	fmt.Println("BASE64: ", string(bytes))
}
