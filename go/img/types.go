package img

import (
	"crypto/sha512"
	"crypto/x509"
	"log"

	"github.com/galli-leo/emmutaler/img/certs"
	"github.com/galli-leo/emmutaler/img/cryptobyte"
	"github.com/galli-leo/emmutaler/img/cryptobyte/asn1"
)

type ObjectIdentifer string

const (
	Img4ID          ObjectIdentifer = "IMG4"
	Img4Payload     ObjectIdentifer = "IM4P"
	Img4Manifest    ObjectIdentifer = "IM4M"
	Img4Restore     ObjectIdentifer = "IM4R"
	ManifestBinary  ObjectIdentifer = "MANB"
	ManifestPayload ObjectIdentifer = "MANP"
)

type PayloadIdentifier string

const (
	PayloadIBEC PayloadIdentifier = "ibec"
	PayloadIBSS PayloadIdentifier = "ibss"
	PayloadIBOT PayloadIdentifier = "ibot"
)

type ImgObject struct {
	// expectedId ObjectIdentifer
	Identifier ObjectIdentifer
}

type IMG4 struct {
	Identifier ObjectIdentifer
	Payload    IM4P
	Manifest   IM4M             `asn1:"nested,tag:0,context,constructed"`
	chain      CertificateChain `asn1:"skip"`
}

func (i *IMG4) FillID() {
	i.Identifier = Img4ID
	i.Payload.FillID()
	i.Manifest.FillID()
}

// Used for unmarshaling x509 certificates correctly!
type CustomCert x509.Certificate

type IM4M struct {
	Identifier  ObjectIdentifer
	Version     int64
	RawManifest Manifest `asn1:"set"`
	Signature   []byte
	CertChain   []CustomCert
	rawDigest   []byte `asn1:"skip"`
}

func (i *IM4M) FillID() {
	i.Identifier = Img4Manifest
}

func (i *IM4M) ToSign() []byte {
	manifestData, err := cryptobyte.MarshalStart(&i.RawManifest, asn1.SET)
	if err != nil {
		log.Fatalf("Failed to marshal manifest: %s", err)
	}
	return manifestData
}

type ManPWrapper struct {
	ManP
}

type ManP struct {
	BootNonceHash           ManifestBytes `asn1:"ctag:BNCH,private,constructed,omitempty"`
	BoardID                 ManifestInt   `asn1:"ctag:BORD,private,constructed,omitempty"`
	CertificateEpoch        ManifestInt   `asn1:"ctag:CEPO,private,constructed,omitempty"`
	ChipID                  ManifestInt   `asn1:"ctag:CHIP,private,constructed,omitempty"`
	CertificateProduction   ManifestBool  `asn1:"ctag:CPRO,private,constructed,omitempty"`
	CertificateSecurityMode ManifestBool  `asn1:"ctag:CSEC,private,constructed,omitempty"`
	UniqueChipID            ManifestInt   `asn1:"ctag:ECID,private,constructed,omitempty"`
	SecurityDomain          ManifestInt   `asn1:"ctag:SDOM,private,constructed,omitempty"`
	PCRP                    ManifestBytes `asn1:"ctag:pcrp,private,constructed,omitempty"`
	SEPNonce                ManifestBytes `asn1:"ctag:snon,private,constructed,omitempty"`
	SRVN                    ManifestBytes `asn1:"ctag:srvn,private,constructed,omitempty"`
	AllowMixNMatch          ManifestBool  `asn1:"ctag:AMNM,private,constructed,omitempty"`
}

type ManBWrapper struct {
	ManB
}

type ManB struct {
	ManP ManPWrapper                `asn1:"ctag:MANP,private,constructed"`
	IBEC PayloadManifestInfoWrapper `asn1:"ctag:ibec,private,constructed"`
}

// This type is used for the certificate extensions.
type CertManifest struct {
	ManP ManPWrapper                `asn1:"ctag:MANP,private,constructed"`
	ObjP PayloadManifestInfoWrapper `asn1:"ctag:OBJP,private,constructed"`
}

type ManifestBool bool

type ManifestBytes []byte

type ManifestInt int

type PayloadManifestInfoWrapper struct {
	PayloadManifestInfo `asn1:"set"`
}

type PayloadManifestInfo struct {
	Digest ManifestBytes `asn1:"ctag:DGST,private,constructed,omitempty"`

	EnableKeys            ManifestBool `asn1:"ctag:EKEY,private,constructed,omitempty"`
	EffectiveProduction   ManifestBool `asn1:"ctag:EPRO,private,constructed,omitempty"`
	EffectiveSecurityMode ManifestBool `asn1:"ctag:ESEC,private,constructed,omitempty"`
}

type Manifest struct {
	ManB ManBWrapper `asn1:"ctag:MANB,private,constructed"`
}

type Keybag struct {
	Type int
	IV   []byte
	Key  []byte
}

type PayloadCompression struct {
	Type             int64
	UncompressedSize int64
}

type IM4P struct {
	Identifier ObjectIdentifer
	Type       PayloadIdentifier
	Info       string
	Contents   []byte
	Keybags    []Keybag `asn1:"nested"`
	// Not emmitting this should just work?
	// Compression PayloadCompression
}

func (i *IM4P) FillID() {
	i.Identifier = Img4Payload
}

func (i *IM4P) Digest() []byte {
	payloadData, err := cryptobyte.Marshal(i)
	if err != nil {
		log.Fatalf("Failed to marshal payload: %s", err)
	}
	payloadDgst := sha512.Sum384(payloadData)
	return payloadDgst[:]
}

// Used to generate images.
type CertificateChain struct {
	fakeRoot bool
	noRoot   bool
	chain    []*certs.Pair
	img      *IMG4
	certDir  string
}
