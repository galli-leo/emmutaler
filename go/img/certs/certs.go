package certs

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
)

const KeySize = 4096

func CreateCertificate(cert *x509.Certificate) (privKey *rsa.PrivateKey, pubCert *x509.Certificate, err error) {
	privKey, err = rsa.GenerateKey(rand.Reader, KeySize)
	if err != nil {
		return
	}

	var caBytes []byte
	caBytes, err = x509.CreateCertificate(rand.Reader, cert, cert, &privKey.PublicKey, privKey)
	if err != nil {
		return
	}

	pubCert, err = x509.ParseCertificate(caBytes)

	return
}

func CreateLeafCertificate(cert *x509.Certificate, rootCert *x509.Certificate, rootKey *rsa.PrivateKey) (privKey *rsa.PrivateKey, pubCert *x509.Certificate, err error) {
	privKey, err = rsa.GenerateKey(rand.Reader, KeySize)
	if err != nil {
		return
	}

	var caBytes []byte
	caBytes, err = x509.CreateCertificate(rand.Reader, cert, rootCert, &privKey.PublicKey, rootKey)
	if err != nil {
		return
	}

	pubCert, err = x509.ParseCertificate(caBytes)

	return
}
