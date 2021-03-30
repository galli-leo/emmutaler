package certs

import (
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"io/ioutil"
	"log"
	"math/big"
	"path/filepath"
)

const LeafSerial = 69
const LeafCertName = "leaf.der"
const LeafKeyName = "leaf.key"

var CertManifestOID = ParseOID("1.2.840.113635.100.6.1.15")

func GenerateLeafTmp(info *CertificateInfo, rootCert *x509.Certificate, rootKey *rsa.PrivateKey, manifestExt *pkix.Extension) (*rsa.PrivateKey, *x509.Certificate) {
	log.Printf("Generating leaf ca")
	cert := info.ToCert()
	cert.SerialNumber = big.NewInt(LeafSerial)
	cert.KeyUsage = x509.KeyUsageDigitalSignature
	cert.BasicConstraintsValid = true
	cert.SignatureAlgorithm = x509.SHA384WithRSA
	// pkix.Extension
	cert.ExtraExtensions = append(cert.ExtraExtensions, cert.Extensions...)
	if manifestExt != nil {
		log.Printf("Manifest extension: %s", manifestExt.Value)
		cert.ExtraExtensions = append(cert.ExtraExtensions, *manifestExt)
	}
	cert.Extensions = append(cert.Extensions, cert.ExtraExtensions...)
	privKey, pubCert, err := CreateLeafCertificate(cert, rootCert, rootKey)
	if err != nil {
		log.Fatalf("Failed to create root ca certificates: %s", err)
	}
	pubCert.ExtraExtensions = append(pubCert.ExtraExtensions, cert.ExtraExtensions...)

	return privKey, pubCert
}

func GenerateLeaf(info *CertificateInfo, rootCert *x509.Certificate, rootKey *rsa.PrivateKey, outDir string) {
	privKey, pubCert := GenerateLeafTmp(info, rootCert, rootKey, nil)
	if err := ioutil.WriteFile(filepath.Join(outDir, LeafCertName), pubCert.Raw, 0777); err != nil {
		log.Fatalf("Failed to write root certificate: %s", err)
	}
	privData := x509.MarshalPKCS1PrivateKey(privKey)
	if err := ioutil.WriteFile(filepath.Join(outDir, LeafKeyName), privData, 0777); err != nil {
		log.Fatalf("Failed to write root key: %s", err)
	}
}
