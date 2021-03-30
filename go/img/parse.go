package img

import (
	"encoding/asn1"

	"golang.org/x/xerrors"
)

func Parse(data []byte) (*IMG4, error) {
	ret := &IMG4{}
	_, err := asn1.Unmarshal(data, ret)
	if err != nil {
		return nil, xerrors.Errorf("failed to unmarshal img: %s", err)
	}

	return ret, ret.Finish()
}

func (i *IMG4) Finish() error {
	if err := i.Payload.Finish(); err != nil {
		return err
	}
	return nil
	// return i.Manifest.Finish()
}

func (i *IM4P) Finish() error {
	// _, err := asn1.Unmarshal(i.KeybagsRaw.Bytes, &i.Keybags)
	return nil
}

func (i *IM4M) Finish() error {
	// for _, certRaw := range i.CertChain {
	// 	cert, err := x509.ParseCertificate(certRaw.FullBytes)
	// 	if err != nil {
	// 		return err
	// 	}
	// 	i.certificates = append(i.certificates, cert)
	// }

	return nil
}
