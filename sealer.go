package sealer

import (
	"encoding/base64"
	"errors"
	"fmt"
	"strconv"
	"strings"
)

type Marshaler interface {
	Marshal(map[string]string) []byte
	Unmarshal([]byte) (map[string]string, error)
}

type Config struct {
	SignFieldName  string    `toml:"sign_field_name"`
	SignPrivateKey string    `toml:"sign_private_key"`
	SignPublicKey  string    `toml:"sign_public_key"`
	AesKey         string    `toml:"aes_key"`
	Base64         string    `toml:"base64"`
	Marshaler      Marshaler `toml:"-"`
}

type Sealer struct {
	Base64Enc *base64.Encoding

	version string
	cfg     Config
	signer  *Ed25519
}

func New(version string, cfg Config) *Sealer {
	if cfg.Marshaler == nil {
		cfg.Marshaler = StdJsonMarshaler
	}
	obj := &Sealer{
		version:   version,
		cfg:       cfg,
		Base64Enc: base64.NewEncoding(cfg.Base64),
		signer:    NewEd25519(cfg.SignFieldName, cfg.SignPrivateKey, cfg.SignPublicKey),
	}
	return obj
}

func (sealer *Sealer) Version() string {
	return sealer.version
}

func (sealer *Sealer) Seal(mapv map[string]string) (string, error) {
	bs, err := AesEncrypt(
		sealer.cfg.Marshaler.Marshal(sealer.signer.Sign(mapv)),
		[]byte(sealer.cfg.AesKey),
	)
	if err != nil {
		return "", err
	}
	body := sealer.Base64Enc.EncodeToString(bs)
	return fmt.Sprintf("%d:%s%s", len(sealer.version), sealer.version, body), nil
}

var (
	ErrBadSealFormat     = errors.New("bad format")
	ErrUnexpectedVersion = errors.New("unexpected version")
	ErrSignVerifyFailed  = errors.New("sign verify failed")
)

func (sealer *Sealer) Open(txt string, othercfgs map[string]Config) (map[string]string, error) {
	rawtxt := txt

	idx := strings.IndexByte(txt, ':')
	if idx < 0 {
		return nil, ErrBadSealFormat
	}

	vls := txt[:idx]
	vl, err := strconv.ParseInt(vls, 10, 64)
	if err != nil {
		return nil, ErrBadSealFormat
	}
	txt = txt[idx+1:]

	version := txt[:vl]
	txt = txt[vl:]

	if sealer.version != version {
		if othercfgs == nil {
			return nil, ErrUnexpectedVersion
		}
		cfg, ok := othercfgs[version]
		if !ok {
			return nil, ErrUnexpectedVersion
		}
		return New(version, cfg).Open(rawtxt, nil)
	}

	bs, err := sealer.Base64Enc.DecodeString(txt)
	if err != nil {
		return nil, err
	}
	bs, err = AesDecrypt(bs, []byte(sealer.cfg.AesKey))
	if err != nil {
		return nil, err
	}
	mapv, err := sealer.cfg.Marshaler.Unmarshal(bs)
	if err != nil {
		return nil, err
	}
	ok := sealer.signer.Verify(mapv)
	if !ok {
		return nil, ErrSignVerifyFailed
	}
	return mapv, nil
}
