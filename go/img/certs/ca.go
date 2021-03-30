package certs

import (
	"crypto/rsa"
	"crypto/x509"
	"io/ioutil"
	"log"
	"math/big"
	"os"
	"path/filepath"
)

const RootSerial = 420
const RootCertName = "root_ca.der"
const RootKeyName = "root_ca.key"

func GenerateRoot(info *CertificateInfo, outDir string) {
	log.Printf("Generating root ca to %s", outDir)
	cert := info.ToCert()
	cert.SerialNumber = big.NewInt(RootSerial)
	cert.KeyUsage = x509.KeyUsageCertSign | x509.KeyUsageCRLSign
	cert.BasicConstraintsValid = true
	cert.IsCA = true
	cert.SignatureAlgorithm = x509.SHA384WithRSA
	privKey, pubCert, err := CreateCertificate(cert)
	if err != nil {
		log.Fatalf("Failed to create root ca certificates: %s", err)
	}
	if err := ioutil.WriteFile(filepath.Join(outDir, RootCertName), pubCert.Raw, 0777); err != nil {
		log.Fatalf("Failed to write root certificate: %s", err)
	}
	privData := x509.MarshalPKCS1PrivateKey(privKey)
	if err := ioutil.WriteFile(filepath.Join(outDir, RootKeyName), privData, 0777); err != nil {
		log.Fatalf("Failed to write root key: %s", err)
	}
}

func LoadRoot(dir string) (privKey *rsa.PrivateKey, pubCert *x509.Certificate) {
	log.Printf("Loading root ca from %s", dir)
	certData, err := os.ReadFile(filepath.Join(dir, RootCertName))
	if err != nil {
		log.Fatalf("Failed to read root cert: %s", err)
	}
	pubCert, err = x509.ParseCertificate(certData)
	if err != nil {
		log.Fatalf("Failed to parse certificate data: %s", err)
	}
	privData, err := os.ReadFile(filepath.Join(dir, RootKeyName))
	if err != nil {
		log.Fatalf("Failed to read private key: %s", err)
	}
	privKey, err = x509.ParsePKCS1PrivateKey(privData)
	if err != nil {
		log.Fatalf("Failed to parse private key: %s", err)
	}

	return
}
