package sealer

import "encoding/json"

type _StdJsonMarshaler struct{}

func (a _StdJsonMarshaler) Marshal(v map[string]string) []byte {
	bs, err := json.Marshal(v)
	if err != nil {
		panic(err)
	}
	return bs
}

func (a _StdJsonMarshaler) Unmarshal(bs []byte) (map[string]string, error) {
	var mv = map[string]string{}
	err := json.Unmarshal(bs, &mv)
	if err != nil {
		return nil, err
	}
	return mv, nil
}

var StdJsonMarshaler Marshaler = _StdJsonMarshaler{}
