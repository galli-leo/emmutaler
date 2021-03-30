package certs

import (
	"crypto/x509"
	"crypto/x509/pkix"
	"time"
)

type CertificateInfo struct {
	CommonName   string
	Organisation string
	Country      string
	NotBefore    time.Time
	NotAfter     time.Time
}

func DefaultRootInfo() CertificateInfo {
	return CertificateInfo{
		CommonName:   "Apple Secure Boot Root CA - G2",
		Organisation: "Apple Inc.",
		Country:      "US",
		NotBefore:    time.Now(),
		NotAfter:     time.Now().Add(time.Hour * 24 * 365 * 10), // 10 years ought to be enough right?
	}
}

func DefaultLeafInfo() CertificateInfo {
	return CertificateInfo{
		CommonName:   "T8030-TssLive-ManifestKey-RevA-DataCenter",
		Organisation: "Apple Inc.",
		Country:      "US",
		NotBefore:    time.Now(),
		NotAfter:     time.Now().Add(time.Hour * 24 * 365 * 9),
	}
}

func (c *CertificateInfo) ToCert() *x509.Certificate {
	return &x509.Certificate{
		Subject: pkix.Name{
			Organization: []string{c.Organisation},
			Country:      []string{c.Country},
			CommonName:   c.CommonName,
		},
		NotBefore: c.NotBefore,
		NotAfter:  c.NotAfter,
		Version:   3,
	}
}
