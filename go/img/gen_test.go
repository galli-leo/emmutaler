package img

import (
	"crypto"
	"crypto/rsa"
	"crypto/sha512"
	"encoding/hex"
	"log"
	"os"
	"strings"
	"testing"

	"github.com/galli-leo/emmutaler/img/certs"
	"github.com/galli-leo/emmutaler/img/cryptobyte"
	"github.com/galli-leo/emmutaler/img/cryptobyte/asn1"
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

func TestImg4GenTest(t *testing.T) {
	/// Lmao very sleazy doing this here, but sure I guess
	outFile := "/Users/leonardogalli/Code/ETH/thesis/img/lazy.img4"
	certDir := "/Users/leonardogalli/Code/ETH/thesis/certs"
	g := &imgGenerator{}
	g.rootKey, g.rootCert = certs.LoadRoot(certDir)
	leafInfo := certs.DefaultLeafInfo()
	g.leafKey, g.leafCert = certs.GenerateLeafTmp(&leafInfo, g.rootCert, g.rootKey, GenManifestExtension())

	img := IMG4{}
	img.FillID()
	img.Payload.Type = PayloadIBEC
	pay, err := BuildSimplePayload(RetValidPayload)
	if err != nil {
		log.Fatalf("Failed to build simple payload: %s", err)
	}
	img.Payload.Contents = pay
	img.Payload.Info = "iBoot-6969.69.7"
	img.Payload.Keybags = []Keybag{} // Empty keybag, we running unencrypted

	manP := &img.Manifest.RawManifest.ManB.ManP
	manP.BootNonceHash = mustDec("DA980208D2E1193F2ACB6F4A2337B420CCF47ACF46BAAADA317654F13C5EE619")
	manP.BoardID = 6
	manP.CertificateEpoch = 1
	manP.ChipID = 0x8030 //0x8101
	manP.CertificateProduction = true
	manP.CertificateSecurityMode = true
	manP.UniqueChipID = 5973101246447662
	manP.SecurityDomain = 1

	ibec := &img.Manifest.RawManifest.ManB.IBEC
	ibec.EffectiveProduction = true
	ibec.EnableKeys = false
	ibec.EffectiveSecurityMode = true
	payloadData, err := cryptobyte.Marshal(&img.Payload)
	if err != nil {
		log.Fatalf("Failed to marshal payload: %s", err)
	}
	payloadDgst := sha512.Sum384(payloadData)
	ibec.Digest = payloadDgst[:]

	img.Manifest.CertChain = append(img.Manifest.CertChain, CustomCert(*g.leafCert))

	manifestData, err := cryptobyte.MarshalStart(&img.Manifest.RawManifest, asn1.SET)
	if err != nil {
		log.Fatalf("Failed to marshal manifest: %s", err)
	}

	manifestDgst := sha512.Sum384(manifestData)
	signature, err := rsa.SignPKCS1v15(nil, g.leafKey, crypto.SHA384, manifestDgst[:])
	if err != nil {
		log.Fatalf("Failed to sign manifest: %s", err)
	}
	img.Manifest.Signature = signature

	// modify something

	res, err := cryptobyte.Marshal(&img)
	if err != nil {
		log.Fatalf("Failed to marshal img4: %s", err)
	}
	err = os.WriteFile(outFile, res, 0777)
	if err != nil {
		log.Fatalf("Failed to write outfile %s: %s", outFile, err)
	}
}
