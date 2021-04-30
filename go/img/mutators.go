package img

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"log"
	"math/big"

	random "math/rand"

	"github.com/galli-leo/emmutaler/img/certs"
)

func (img *IMG4) FillDefault(certDir string) {
	img.FillID()
	img.chain.img = img
	img.chain.certDir = certDir

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
	ibec.Digest = img.Payload.Digest()

	img.Manifest.rawDigest = img.Manifest.ToSign()
}

func GenFakeRoot() *certs.Pair {
	info := certs.DefaultRootInfo()
	cert := info.ToCert()
	cert.SerialNumber = big.NewInt(1337)
	cert.KeyUsage = x509.KeyUsageCertSign | x509.KeyUsageCRLSign
	cert.IsCA = true
	cert.BasicConstraintsValid = true
	cert.SignatureAlgorithm = x509.SHA384WithRSA
	p := certs.TmplPair(cert)
	if err := p.Generate(nil); err != nil {
		log.Fatalf("Failed to generate fake root certificate: %s", err)
	}
	return p
}

var fakeRoot *certs.Pair = nil

func (c *CertificateChain) MutateRoot(i int) {
	if i == 0 {
		// actual root
		c.chain = append(c.chain, certs.LoadPair(c.certDir, "root_ca"))
		c.fakeRoot = false
	} else if i == 1 {
		// fake root
		if fakeRoot == nil {
			fakeRoot = GenFakeRoot()
		}
		c.chain = append(c.chain, fakeRoot)
		c.fakeRoot = true
	} else {
		// no root, leaf used as root, so technically fake root
		c.chain = append(c.chain, nil)
		c.fakeRoot = true
	}

}

func GenKeys() []*rsa.PrivateKey {
	ret := []*rsa.PrivateKey{}

	for i := 0; i < 5; i++ {
		key, _ := rsa.GenerateKey(rand.Reader, certs.KeySize)
		ret = append(ret, key)
	}

	return ret
}

var randKeys []*rsa.PrivateKey

func (c *CertificateChain) MutateLeafs(numLeaf int) {
	info := certs.DefaultLeafInfo()
	for i := 0; i < numLeaf; i++ {
		cert := info.ToCert()
		cert.SerialNumber = big.NewInt(int64(certs.LeafSerial + i))
		cert.BasicConstraintsValid = true
		cert.SignatureAlgorithm = x509.SHA384WithRSA
		if i < numLeaf-1 {
			// intermediate, not actual leaf
			cert.KeyUsage = x509.KeyUsageCertSign | x509.KeyUsageCRLSign
			cert.IsCA = true
		} else {
			// actual leaf
			cert.KeyUsage = x509.KeyUsageDigitalSignature
			cert.ExtraExtensions = append(cert.ExtraExtensions, cert.Extensions...)
			manifestExt := GenManifestExtension()
			if manifestExt != nil {
				cert.ExtraExtensions = append(cert.ExtraExtensions, *manifestExt)
			}
			cert.Extensions = append(cert.Extensions, cert.ExtraExtensions...)
		}
		c.chain = append(c.chain, certs.TmplPair(cert))
	}
}

func (c *CertificateChain) MutateSignChain(i int) {
	if len(randKeys) == 0 {
		randKeys = GenKeys()
	}
	for i := 1; i < len(c.chain); i++ {
		parentIdx := i - 1
		leaf := c.chain[i]
		parent := c.chain[parentIdx]
		idx := random.Intn(len(randKeys) - 1)
		err := leaf.GenerateFast(parent, randKeys[idx])
		if err != nil {
			log.Printf("Failed to generate cert: %s", err)
			return
		}
		c.img.Manifest.CertChain = append(c.img.Manifest.CertChain, CustomCert(*leaf.Public))
	}
}

func (c *CertificateChain) MutateSignImg(i int) {
	// we only sign the image, if we didn't change either payload or manifest
	// or we have a fake root
	if c.fakeRoot == false {
		actPayloadDigest := c.img.Payload.Digest()
		actManifestDigest := c.img.Manifest.ToSign()
		if bytes.Compare(actPayloadDigest, c.img.Manifest.RawManifest.ManB.IBEC.Digest) != 0 {
			return
		}
		if bytes.Compare(actManifestDigest, c.img.Manifest.rawDigest) != 0 {
			return
		}
	} else {
		// if we have a fake root, the payload should never be executed!
		// Hence regenerate the payload here!
		c.img.Payload.Contents, _ = BuildSimplePayload(RetInvalidPayload)
		c.img.Manifest.RawManifest.ManB.IBEC.Digest = c.img.Payload.Digest()
	}
	if len(c.chain) == 0 {
		return
	}
	leaf := c.chain[len(c.chain)-1]
	if leaf == nil {
		// no root and no leaf, don't sign
		return
	}
	sign, err := leaf.Sign(c.img.Manifest.ToSign())
	if err != nil {
		log.Printf("Failed to sign manifest: %s", err)
	}
	c.img.Manifest.Signature = sign
}
