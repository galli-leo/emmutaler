package img

import (
	"github.com/galli-leo/emmutaler/img/cryptobyte"
	"github.com/galli-leo/emmutaler/img/cryptobyte/asn1"
)

func (c *CustomCert) MarshalASN1(b *cryptobyte.Builder, tag asn1.Tag) error {
	data := c.Raw
	b.AddBytes(data)
	return nil
}

func MarshalManifestProp(b *cryptobyte.Builder, tag asn1.Tag, contF cryptobyte.BuilderContinuation) error {
	// tag should actually have correct info
	// lmao no idea why tag is already added????
	//b.AddASN1(tag, func(b *cryptobyte.Builder) {
	// SEQUENCE {
	// 	identifier IA5String (from tag)
	// 	actual data (variable)
	// }
	b.AddASN1(asn1.SEQUENCE, func(c *cryptobyte.Builder) {
		c.AddASN1(asn1.IA5String, func(c *cryptobyte.Builder) {
			tagNum := tag.TagNum()
			tagBytes := []byte{}
			for tagNum != 0 {
				b := tagNum & 0xff
				tagBytes = append([]byte{byte(b)}, tagBytes...)
				tagNum >>= 8
			}
			c.AddBytes(tagBytes)
		})
		contF(c)
	})
	//})
	return nil
}

func (mb *ManifestBool) MarshalASN1(b *cryptobyte.Builder, tag asn1.Tag) error {
	return MarshalManifestProp(b, tag, func(child *cryptobyte.Builder) {
		child.AddASN1Boolean(*(*bool)(mb))
	})
}

func (mb *ManifestBytes) MarshalASN1(b *cryptobyte.Builder, tag asn1.Tag) error {
	return MarshalManifestProp(b, tag, func(child *cryptobyte.Builder) {
		child.AddASN1(asn1.OCTET_STRING, func(child *cryptobyte.Builder) {
			child.AddBytes(*(*[]byte)(mb))
		})
	})
}

func (mb *ManifestInt) MarshalASN1(b *cryptobyte.Builder, tag asn1.Tag) error {
	return MarshalManifestProp(b, tag, func(child *cryptobyte.Builder) {
		child.AddASN1Int64(int64(*(*int)(mb))) // yes, I know this is ugly, but what you gonna do?
	})
}

func (man *ManBWrapper) MarshalASN1(b *cryptobyte.Builder, tag asn1.Tag) error {
	var err error = nil
	MarshalManifestProp(b, tag, func(c *cryptobyte.Builder) {
		var bytes []byte
		bytes, err = cryptobyte.MarshalStart(&man.ManB, asn1.SET)
		c.AddBytes(bytes)
	})
	return err
}

func (man *ManPWrapper) MarshalASN1(b *cryptobyte.Builder, tag asn1.Tag) error {
	var err error = nil
	MarshalManifestProp(b, tag, func(c *cryptobyte.Builder) {
		var bytes []byte
		bytes, err = cryptobyte.MarshalStart(&man.ManP, asn1.SET)
		c.AddBytes(bytes)
	})
	return err
}

func (info *PayloadManifestInfoWrapper) MarshalASN1(b *cryptobyte.Builder, tag asn1.Tag) error {
	var err error = nil
	MarshalManifestProp(b, tag, func(c *cryptobyte.Builder) {
		var bytes []byte
		bytes, err = cryptobyte.MarshalStart(&info.PayloadManifestInfo, asn1.SET)
		c.AddBytes(bytes)
	})
	return err
}
