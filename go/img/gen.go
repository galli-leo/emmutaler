package img

import (
	"crypto"
	"crypto/rsa"
	"crypto/sha512"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"log"
	"os"
	"path/filepath"
	"strings"

	"github.com/galli-leo/emmutaler/img/certs"
	"github.com/galli-leo/emmutaler/img/cryptobyte"
	"github.com/galli-leo/emmutaler/img/cryptobyte/asn1"
)

type imgGenerator struct {
	rootCert *x509.Certificate
	rootKey  *rsa.PrivateKey
	leafCert *x509.Certificate
	leafKey  *rsa.PrivateKey
}

func GenManifestExtension() *pkix.Extension {
	ext := &pkix.Extension{}
	ext.Id = certs.CertManifestOID
	ext.Critical = true
	certMani := &CertManifest{}
	certMani.ManP.CertificateEpoch = 1
	certMani.ManP.ChipID = 0x8030
	certMani.ManP.SecurityDomain = 1
	certManiData, err := cryptobyte.MarshalStart(certMani, asn1.SET)
	if err != nil {
		log.Fatalf("Failed to marshal certificate manifest: %s", err)
	}
	ext.Value = certManiData
	return ext
}

func GenerateImages(outDir string, certDir string) {
	log.Printf("Generating images to %s", outDir)
	g := &imgGenerator{}
	g.rootKey, g.rootCert = certs.LoadRoot(certDir)
	leafInfo := certs.DefaultLeafInfo()
	g.leafKey, g.leafCert = certs.GenerateLeafTmp(&leafInfo, g.rootCert, g.rootKey, GenManifestExtension())

	g.GenerateImage(filepath.Join(outDir, "test.img4"))
}

func mustDec(s string) []byte {
	s = strings.ReplaceAll(s, " ", "")
	dec, err := hex.DecodeString(s)
	if err != nil {
		panic(err)
	}

	return dec
}

// For now.
func (g *imgGenerator) GenerateImage(outFile string) {
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
	manP.ChipID = 0x8030
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

	res, err := cryptobyte.Marshal(&img)
	if err != nil {
		log.Fatalf("Failed to marshal img4: %s", err)
	}
	err = os.WriteFile(outFile, res, 0777)
	if err != nil {
		log.Fatalf("Failed to write outfile %s: %s", outFile, err)
	}
}
