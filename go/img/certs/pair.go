package certs

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha512"
	"crypto/x509"
	"io/ioutil"
	"log"
	"os"
	"path/filepath"

	"golang.org/x/xerrors"
)

// Creates a pair (to be generated) with the given tmpl as a basis for the certificate.
func TmplPair(tmpl *x509.Certificate) *Pair {
	return &Pair{
		Tmpl: tmpl,
	}
}

func LoadPair(dir, name string) *Pair {
	file := filepath.Join(dir, name)
	p := &Pair{}
	certData, err := os.ReadFile(file + ".der")
	if err != nil {
		log.Fatalf("Failed to read cert: %s", err)
	}
	pubCert, err := x509.ParseCertificate(certData)
	if err != nil {
		log.Fatalf("Failed to parse certificate data: %s", err)
	}
	privData, err := os.ReadFile(file + ".key")
	if err != nil {
		log.Fatalf("Failed to read private key: %s", err)
	}
	privKey, err := x509.ParsePKCS1PrivateKey(privData)
	if err != nil {
		log.Fatalf("Failed to parse private key: %s", err)
	}
	p.Public = pubCert
	p.Private = privKey
	return p
}

// Pair represents a public private key pair, where the public part is actually an x509 certificate.
type Pair struct {
	Public  *x509.Certificate
	Private *rsa.PrivateKey
	Tmpl    *x509.Certificate
}

// Generate generates the certificate, if it was created from a template. If parent is not nil, it will use parent's key to sign it.
// Otherwise, it is self signed.
func (p *Pair) Generate(parent *Pair) error {
	if p.Tmpl == nil {
		return xerrors.Errorf("not template pair, cannot generate")
	}
	var err error
	var privKey *rsa.PrivateKey
	var pubCert *x509.Certificate
	if parent == nil {
		privKey, pubCert, err = CreateCertificate(p.Tmpl)
	} else {
		privKey, pubCert, err = CreateLeafCertificate(p.Tmpl, parent.Public, parent.Private)
	}
	if err != nil {
		return xerrors.Errorf("failed to create certificate: %w", err)
	}

	p.Private = privKey
	p.Public = pubCert
	return nil
}

func (p *Pair) GenerateFast(parent *Pair, privKey *rsa.PrivateKey) error {
	if p.Tmpl == nil {
		return xerrors.Errorf("not template pair, cannot generate")
	}
	var err error
	var pubCert *x509.Certificate
	if parent == nil {
		var caBytes []byte
		caBytes, err = x509.CreateCertificate(rand.Reader, p.Tmpl, p.Tmpl, &privKey.PublicKey, privKey)
		if err != nil {
			return xerrors.Errorf("failed to create certificate: %w", err)
		}

		pubCert, err = x509.ParseCertificate(caBytes)
	} else {
		var caBytes []byte
		caBytes, err = x509.CreateCertificate(rand.Reader, p.Tmpl, parent.Public, &privKey.PublicKey, parent.Private)
		if err != nil {
			return xerrors.Errorf("failed to create certificate: %w", err)
		}

		pubCert, err = x509.ParseCertificate(caBytes)
	}
	if err != nil {
		return xerrors.Errorf("failed to create certificate: %w", err)
	}

	p.Private = privKey
	p.Public = pubCert
	return nil
}

// Save saves the key pair to the directory dir with name name (i.e. dir/name.key and dir/name.der).
func (p *Pair) Save(dir, name string) error {
	file := filepath.Join(dir, name)
	if err := ioutil.WriteFile(file+".der", p.Public.Raw, 0777); err != nil {
		return xerrors.Errorf("failed to write certificate to %s: %w", file+".der", err)
	}
	privData := x509.MarshalPKCS1PrivateKey(p.Private)
	if err := ioutil.WriteFile(file+".key", privData, 0777); err != nil {
		return xerrors.Errorf("failed to write private key to %s: %w", file+".key", err)
	}
	return nil
}

// Sign the data with SHA384 digest.
func (p *Pair) Sign(data []byte) ([]byte, error) {
	if p.Private == nil {
		return []byte{}, xerrors.Errorf("need to generate first!")
	}
	hdata := sha512.Sum384(data)
	return rsa.SignPKCS1v15(nil, p.Private, crypto.SHA384, hdata[:])
}
