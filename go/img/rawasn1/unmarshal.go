package rawasn1

import (
	"fmt"

	"github.com/galli-leo/emmutaler/img/cryptobyte"
	"github.com/galli-leo/emmutaler/img/cryptobyte/asn1"
)

func Unmarshal(data []byte) (*DERItem, error) {
	s := cryptobyte.String(data)
	return unmarshal(&s)
}

func unmarshal(s *cryptobyte.String) (*DERItem, error) {
	curr := &DERItem{}
	var tag asn1.Tag
	var out cryptobyte.String
	if !s.ReadAnyASN1Element(&out, &tag) {
		return nil, fmt.Errorf("failed to read any asn1 element")
	}
	outCopy := append([]byte(nil), out...)
	// get the tag
	tagb := outCopy[0:tag.Length()]
	curr.Tag = tagb

	var conts cryptobyte.String
	if !out.ReadASN1(&conts, tag) {
		return nil, fmt.Errorf("failed to read ")
	}
	contsSize := len(conts)
	lenSize := len(outCopy) - contsSize - int(tag.Length())
	lenb := outCopy[tag.Length() : int(tag.Length())+lenSize]
	curr.Length = lenb

	// if nested, then go nested!
	if tag.Method() == asn1.MethodConstructed {
		for len(conts) > 0 {
			child, err := unmarshal(&conts)
			if err != nil {
				// ok, maybe children no here?
				curr.Contents = conts
				curr.Children = []*DERItem{}
				break
			}
			curr.Children = append(curr.Children, child)
		}
	} else {
		curr.Contents = conts
	}

	return curr, nil
}
