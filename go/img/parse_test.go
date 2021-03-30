package img

import (
	"os"
	"testing"

	"github.com/galli-leo/emmutaler/img/cryptobyte"
	"github.com/galli-leo/emmutaler/img/cryptobyte/asn1"
	"github.com/stretchr/testify/assert"
)

const TestImg4 = "../../../ipsw/out.img4"

func TestFullParse(t *testing.T) {
	assert := assert.New(t)
	data, err := os.ReadFile(TestImg4)
	if err != nil {
		t.Fatalf("Could not read test file: %s", err)
	}
	img := IMG4{}
	err = cryptobyte.Unmarshal(data, &img)
	// img, err := Parse(data)
	if err != nil {
		t.Fatalf("Failed to parse image: %s", err)
	}
	assert.Equal(Img4ID, img.Identifier)
	assert.Equal(2, len(img.Payload.Keybags))
	assert.Equal([]byte{0x71, 0xd5, 0x83, 0xcc, 0x8a, 0xd2, 0xaf, 0x55, 0x7, 0x5d, 0xff, 0x7f, 0x81, 0x86, 0x31, 0xc8}, img.Payload.Keybags[0].IV)
	assert.Equal([]string{"Apple Inc."}, img.Manifest.CertChain[0].Issuer.Organization)
	assert.EqualValues(true, img.Manifest.RawManifest.ManB.IBEC.EnableKeys)
	assert.EqualValues([]byte{0xda, 0x98, 0x2, 0x8, 0xd2, 0xe1, 0x19, 0x3f, 0x2a, 0xcb, 0x6f, 0x4a, 0x23, 0x37, 0xb4, 0x20, 0xcc, 0xf4, 0x7a, 0xcf, 0x46, 0xba, 0xaa, 0xda, 0x31, 0x76, 0x54, 0xf1, 0x3c, 0x5e, 0xe6, 0x19}, img.Manifest.RawManifest.ManB.ManP.BootNonceHash)
}

func TestOtherParse(t *testing.T) {
	assert := assert.New(t)
	data, err := os.ReadFile(TestImg4)
	if err != nil {
		t.Fatalf("Could not read test file: %s", err)
	}
	s := cryptobyte.String(data)
	var imgseq cryptobyte.String
	assert.True(s.ReadASN1(&imgseq, asn1.SEQUENCE))
	var identifier cryptobyte.String
	var payloadseq cryptobyte.String
	var manifestseq cryptobyte.String
	assert.True(imgseq.ReadASN1(&identifier, asn1.IA5String))
	assert.True(imgseq.ReadASN1(&payloadseq, asn1.SEQUENCE))
	fuckYou := asn1.Tag(0).Constructed().ContextSpecific()
	assert.True(imgseq.ReadASN1(&manifestseq, fuckYou))
	var actmanifestseq cryptobyte.String
	assert.True(manifestseq.ReadASN1(&actmanifestseq, asn1.SEQUENCE))
	var manid, set cryptobyte.String
	var version int
	assert.True(actmanifestseq.ReadASN1(&manid, asn1.IA5String))
	assert.True(actmanifestseq.ReadASN1Integer(&version))
	assert.Equal(0, version)
	assert.True(actmanifestseq.ReadASN1(&set, asn1.SET))
	manb := asn1.Tag(1296125506).WithClass(asn1.ClassPrivate).Constructed()
	var manbs cryptobyte.String
	// var manbT asn1.Tag
	// assert.True(set.ReadAnyASN1(&manbs, &manbT))
	// t.Logf("Got Manifest tag: %s", manbT)
	assert.True(set.ReadASN1(&manbs, manb))
}
