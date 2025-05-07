package sealer

import (
	"bytes"
	"crypto/ed25519"
	"encoding/base64"
	"fmt"
	"maps"
	"slices"
)

type Ed25519 struct {
	sign_key string
	private  []byte
	public   []byte
}

func NewEd25519(sign_key string, private string, public string) *Ed25519 {
	if sign_key == "" {
		sign_key = "__sign__"
	}
	pri, _ := base64.StdEncoding.DecodeString(private)
	pub, _ := base64.StdEncoding.DecodeString(public)

	return &Ed25519{
		sign_key: sign_key,
		private:  pri,
		public:   pub,
	}
}

func (ed *Ed25519) do(obj map[string]string, fnc func([]byte)) {
	_, ok := obj[ed.sign_key]
	if ok {
		panic(fmt.Errorf("map value contain field: %s", ed.sign_key))
	}
	var buf = bytes.NewBuffer(nil)
	keys := slices.Collect(maps.Keys(obj))
	slices.Sort(keys)
	for _, key := range keys {
		buf.WriteString(key)
		buf.WriteString(obj[key])
	}
	fnc(buf.Bytes())
}

func (ed *Ed25519) Sign(obj map[string]string) map[string]string {
	ed.do(obj, func(b []byte) {
		sign := ed25519.Sign((ed25519.PrivateKey)(ed.private), b)
		obj[ed.sign_key] = base64.StdEncoding.EncodeToString(sign)
	})
	return obj
}

func (ed *Ed25519) Verify(obj map[string]string) bool {
	prev_sign_txt := obj[ed.sign_key]
	delete(obj, ed.sign_key)
	if prev_sign_txt == "" {
		return false
	}
	prev_sign, err := base64.StdEncoding.DecodeString(prev_sign_txt)
	if err != nil {
		return false
	}
	var ok bool
	ed.do(obj, func(b []byte) {
		ok = ed25519.Verify(ed.public, b, prev_sign)
	})
	return ok
}
