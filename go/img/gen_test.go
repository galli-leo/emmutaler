package img

import (
	"encoding/hex"
	"strings"
	"testing"

	"github.com/galli-leo/emmutaler/img/cryptobyte"
	"github.com/stretchr/testify/assert"
)

func mustDecode(s string) []byte {
	s = strings.ReplaceAll(s, " ", "")
	dec, err := hex.DecodeString(s)
	if err != nil {
		panic(err)
	}

	return dec
}

func TestImg4Gen(t *testing.T) {
	assert := assert.New(t)
	img := IMG4{}
	img.FillID()
	img.Payload.Type = PayloadIBEC
	img.Payload.Contents = []byte{0xff, 0xff, 0xff, 0xff} // Should be invalid instructions lol??
	img.Payload.Info = "iBoot-6969.69.7"
	img.Payload.Keybags = []Keybag{} // Empty keybag, we running unencrypted

	manP := &img.Manifest.RawManifest.ManB.ManP
	manP.BootNonceHash = mustDecode("DA980208D2E1193F2ACB6F4A2337B420CCF47ACF46BAAADA317654F13C5EE619")
	manP.BoardID = 6
	manP.CertificateEpoch = 1
	manP.ChipID = 0x8030
	manP.CertificateProduction = true
	manP.CertificateSecurityMode = true
	manP.ChipID = 5973101246447662
	manP.SecurityDomain = 1

	ibec := &img.Manifest.RawManifest.ManB.IBEC
	ibec.EffectiveProduction = true
	ibec.EnableKeys = true
	ibec.EffectiveSecurityMode = true
	ibec.Digest = img.Payload.Digest()

	_, err := cryptobyte.Marshal(&img)
	assert.NoError(err)

}
