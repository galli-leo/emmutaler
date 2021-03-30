package img

import (
	"crypto/x509"
	"fmt"

	"github.com/galli-leo/emmutaler/img/cryptobyte"
	"github.com/galli-leo/emmutaler/img/cryptobyte/asn1"
)

func (c *CustomCert) UnmarshalASN1(s *cryptobyte.String) error {
	actData := []byte(*s)
	cert, err := x509.ParseCertificate(actData)
	*c = CustomCert(*cert)
	return err
}

func UnmarshalManifestProp(s *cryptobyte.String, conts *cryptobyte.String) error {
	var seq cryptobyte.String
	if !s.ReadASN1(&seq, asn1.SEQUENCE) {
		return fmt.Errorf("failed to read asn1 sequence for manifest property")
	}
	if !seq.SkipASN1(asn1.IA5String) {
		return fmt.Errorf("failed to read asn1 iastring describing property name")
	}
	if !seq.ReadAnyASN1Element(conts, nil) {
		return fmt.Errorf("failed to read asn1 actual contents")
	}

	return nil
}

func (man *ManBWrapper) UnmarshalASN1(s *cryptobyte.String) error {
	var conts cryptobyte.String
	if err := UnmarshalManifestProp(s, &conts); err != nil {
		return err
	}
	if err := cryptobyte.Unmarshal(conts, &man.ManB); err != nil {
		return err
	}
	return nil
}

func (man *ManPWrapper) UnmarshalASN1(s *cryptobyte.String) error {
	var conts cryptobyte.String
	if err := UnmarshalManifestProp(s, &conts); err != nil {
		return err
	}
	if err := cryptobyte.Unmarshal(conts, &man.ManP); err != nil {
		return err
	}
	return nil
}

func (info *PayloadManifestInfoWrapper) UnmarshalASN1(s *cryptobyte.String) error {
	var conts cryptobyte.String
	if err := UnmarshalManifestProp(s, &conts); err != nil {
		return err
	}
	if err := cryptobyte.Unmarshal(conts, &info.PayloadManifestInfo); err != nil {
		return err
	}
	return nil
}

func (b *ManifestBool) UnmarshalASN1(s *cryptobyte.String) error {
	var conts cryptobyte.String
	if err := UnmarshalManifestProp(s, &conts); err != nil {
		return err
	}
	conts.ReadASN1Boolean((*bool)(b))
	return nil
}

func (b *ManifestBytes) UnmarshalASN1(s *cryptobyte.String) error {
	var conts cryptobyte.String
	if err := UnmarshalManifestProp(s, &conts); err != nil {
		return err
	}
	conts.ReadASN1Bytes((*[]byte)(b), asn1.OCTET_STRING)
	return nil
}

func (b *ManifestInt) UnmarshalASN1(s *cryptobyte.String) error {
	var conts cryptobyte.String
	if err := UnmarshalManifestProp(s, &conts); err != nil {
		return err
	}
	conts.ReadASN1Integer((*int)(b))
	return nil
}
