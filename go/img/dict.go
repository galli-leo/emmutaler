package img

import (
	"fmt"
	"log"
	"os"

	"github.com/galli-leo/emmutaler/img/cryptobyte"
	"github.com/galli-leo/emmutaler/img/cryptobyte/asn1"
)

type dictGen struct {
	f *os.File
}

func GenerateDict(outFile string) {
	f, err := os.OpenFile(outFile, os.O_CREATE|os.O_TRUNC|os.O_RDWR, 0777)
	if err != nil {
		log.Fatalf("Failed to open %s for writing: %s", outFile, err)
	}
	d := &dictGen{f: f}
	d.Run()
	defer f.Close()
}

func (d *dictGen) Run() {
	tags := map[string]asn1.Tag{
		"empty":       asn1.Tag(0),
		"bool":        asn1.BOOLEAN,
		"int":         asn1.INTEGER,
		"bitstring":   asn1.BIT_STRING,
		"octet":       asn1.OCTET_STRING,
		"null":        asn1.NULL,
		"oid":         asn1.OBJECT_IDENTIFIER,
		"sequence":    asn1.SEQUENCE,
		"set":         asn1.SET,
		"iastr":       asn1.IA5String,
		"time":        asn1.UTCTime,
		"generaltime": asn1.GeneralizedTime,
	}
	for name, tag := range tags {
		d.WriteTag(name, tag)
	}

	apple_tags := []string{
		"MANP",
		"MANB",
		"ibec",
		"BORD",
		"BNCH",
		"CEPO",
		"CHIP",
		"CPRO",
		"CSEC",
		"ECID",
		"SDOM",
		"pcrp",
		"snon",
		"srvn",
		"AMNM",
	}
	for _, aplt := range apple_tags {
		d.WriteAppleTag(aplt)
	}
}

func (d *dictGen) WriteToken(name string, token []byte) {
	valEnc := ""
	for _, b := range token {
		valEnc += fmt.Sprintf(`\x%02x`, b)
	}

	line := fmt.Sprintf(`%s="%s"
`, name, valEnc)
	d.f.WriteString(line)
}

func (d *dictGen) WriteTagVariations(name string, tag asn1.Tag) {
	classes := map[string]asn1.Class{
		"universal":   asn1.ClassUniversal,
		"application": asn1.ClassApplication,
		"context":     asn1.ClassContextSpecific,
		"private":     asn1.ClassPrivate,
	}
	methods := map[string]asn1.Method{
		"primitive":   asn1.MethodPrimitive,
		"constructed": asn1.MethodConstructed,
	}
	for cname, cls := range classes {
		for mname, method := range methods {
			d.WriteTag(name+"_"+cname+"_"+mname, tag.WithClass(cls).WithMethod(method))
		}
	}
}

func (d *dictGen) WriteTag(name string, tag asn1.Tag) {
	b := cryptobyte.NewBuilder([]byte{})
	b.AddASN1(tag, func(child *cryptobyte.Builder) {})
	token, _ := b.Bytes()
	token = token[:len(token)-1] // remove last null byte
	d.WriteToken(name, token)
}

func (d *dictGen) WriteAppleTag(tag string) {
	t := asn1.FromChar(tag).WithClass(asn1.ClassPrivate).WithMethod(asn1.MethodConstructed)
	d.WriteTag("apple_"+tag, t)
	d.WriteToken("apple_raw", []byte(tag))
}
