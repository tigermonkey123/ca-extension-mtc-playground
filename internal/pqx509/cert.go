// Copyright (C) 2026 DigiCert, Inc.
//
// Licensed under the dual-license model:
//   1. GNU Affero General Public License v3.0 (AGPL v3) — see LICENSE.txt
//   2. DigiCert Commercial License — see LICENSE_COMMERCIAL.txt
//
// For commercial licensing, contact sales@digicert.com.

// Package pqx509 builds small demo X.509 chains for algorithms that Go's
// crypto/x509 generator does not yet support.
package pqx509

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/pem"
	"fmt"
	"math/big"
	"strings"
	"time"

	circlsign "github.com/cloudflare/circl/sign"
	"github.com/cloudflare/circl/sign/schemes"
)

var (
	oidSubjectAltName        = asn1.ObjectIdentifier{2, 5, 29, 17}
	oidKeyUsage              = asn1.ObjectIdentifier{2, 5, 29, 15}
	oidExtKeyUsage           = asn1.ObjectIdentifier{2, 5, 29, 37}
	oidBasicConstraints      = asn1.ObjectIdentifier{2, 5, 29, 19}
	oidSubjectKeyIdentifier  = asn1.ObjectIdentifier{2, 5, 29, 14}
	oidAuthorityKeyIdentifier = asn1.ObjectIdentifier{2, 5, 29, 35}
)

// DemoChain is a PEM-encoded leaf certificate, issuer certificate, and leaf key.
type DemoChain struct {
	Algorithm string
	CertPEM   []byte
	CertDER   []byte
	CAPEM     []byte
	CADER     []byte
	KeyPEM    []byte
}

type algorithmIdentifier struct {
	Algorithm asn1.ObjectIdentifier
}

type validity struct {
	NotBefore time.Time
	NotAfter  time.Time
}

type subjectPublicKeyInfo struct {
	Algorithm        algorithmIdentifier
	SubjectPublicKey asn1.BitString
}

type tbsCertificate struct {
	Version            int `asn1:"optional,explicit,tag:0,default:0"`
	SerialNumber       *big.Int
	SignatureAlgorithm algorithmIdentifier
	Issuer             asn1.RawValue
	Validity           validity
	Subject            asn1.RawValue
	SubjectPubKeyInfo  asn1.RawValue
	Extensions         []pkix.Extension `asn1:"optional,explicit,tag:3"`
}

type certificate struct {
	TBSCertificate     asn1.RawValue
	SignatureAlgorithm algorithmIdentifier
	SignatureValue     asn1.BitString
}

// GenerateDemoChain creates a local CA and a leaf certificate using alg.
//
// alg can be "ec", "ML-DSA-44", "ML-DSA-65", "ML-DSA-87", or any pure
// SLH-DSA scheme name exposed by circl, such as "SLH-DSA-SHA2-128s".
func GenerateDemoChain(alg, domain string, validityDuration time.Duration) (*DemoChain, error) {
	if validityDuration == 0 {
		validityDuration = 365 * 24 * time.Hour
	}
	if isEC(alg) {
		return generateECDemoChain(domain, validityDuration)
	}
	return generatePQDemoChain(alg, domain, validityDuration)
}

func generateECDemoChain(domain string, validityDuration time.Duration) (*DemoChain, error) {
	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("pqx509: generate EC CA key: %w", err)
	}
	leafKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("pqx509: generate EC leaf key: %w", err)
	}

	now := time.Now().UTC().Truncate(time.Second)
	caSerial, err := generateSerial()
	if err != nil {
		return nil, err
	}
	caTemplate := &x509.Certificate{
		SerialNumber: caSerial,
		Subject: pkix.Name{
			CommonName:   "PQC Demo Local CA",
			Organization: []string{"MTC Demo"},
			Country:      []string{"US"},
		},
		NotBefore:             now,
		NotAfter:              now.Add(10 * 365 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
		MaxPathLen:            0,
		MaxPathLenZero:        true,
	}
	caDER, err := x509.CreateCertificate(rand.Reader, caTemplate, caTemplate, &caKey.PublicKey, caKey)
	if err != nil {
		return nil, fmt.Errorf("pqx509: create EC CA cert: %w", err)
	}
	caCert, err := x509.ParseCertificate(caDER)
	if err != nil {
		return nil, fmt.Errorf("pqx509: parse EC CA cert: %w", err)
	}

	leafSerial, err := generateSerial()
	if err != nil {
		return nil, err
	}
	leafTemplate := &x509.Certificate{
		SerialNumber: leafSerial,
		Subject: pkix.Name{
			CommonName:   domain,
			Organization: []string{"MTC Demo"},
			Country:      []string{"US"},
		},
		NotBefore:             now,
		NotAfter:              now.Add(validityDuration),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
		BasicConstraintsValid: true,
		IsCA:                  false,
		DNSNames:              []string{domain},
	}
	leafDER, err := x509.CreateCertificate(rand.Reader, leafTemplate, caCert, &leafKey.PublicKey, caKey)
	if err != nil {
		return nil, fmt.Errorf("pqx509: create EC leaf cert: %w", err)
	}

	keyDER, err := x509.MarshalECPrivateKey(leafKey)
	if err != nil {
		return nil, fmt.Errorf("pqx509: marshal EC leaf key: %w", err)
	}

	return &DemoChain{
		Algorithm: "ec",
		CertPEM:   pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: leafDER}),
		CertDER:   leafDER,
		CAPEM:     pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: caDER}),
		CADER:     caDER,
		KeyPEM:    pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER}),
	}, nil
}

func generatePQDemoChain(alg, domain string, validityDuration time.Duration) (*DemoChain, error) {
	scheme := schemes.ByName(alg)
	if scheme == nil {
		return nil, fmt.Errorf("pqx509: unsupported algorithm %q", alg)
	}
	oid, err := oidForScheme(scheme.Name())
	if err != nil {
		return nil, err
	}

	caPub, caPriv, err := scheme.GenerateKey()
	if err != nil {
		return nil, fmt.Errorf("pqx509: generate %s CA key: %w", scheme.Name(), err)
	}
	leafPub, leafPriv, err := scheme.GenerateKey()
	if err != nil {
		return nil, fmt.Errorf("pqx509: generate %s leaf key: %w", scheme.Name(), err)
	}

	now := time.Now().UTC().Truncate(time.Second)
	caSubject := pkix.Name{
		CommonName:   "PQC Demo Local CA",
		Organization: []string{"MTC Demo"},
		Country:      []string{"US"},
	}
	caSerial, err := generateSerial()
	if err != nil {
		return nil, err
	}
	caDER, err := buildPQCertificate(pqCertInput{
		Serial:     caSerial,
		Subject:    caSubject,
		Issuer:     caSubject,
		NotBefore:  now,
		NotAfter:   now.Add(10 * 365 * 24 * time.Hour),
		SubjectKey: caPub,
		SignerKey:  caPriv,
		SignerPub:  caPub,
		Scheme:     scheme,
		OID:        oid,
		Extensions: caExtensions(caPub),
	})
	if err != nil {
		return nil, fmt.Errorf("pqx509: create %s CA cert: %w", scheme.Name(), err)
	}

	leafSerial, err := generateSerial()
	if err != nil {
		return nil, err
	}
	leafDER, err := buildPQCertificate(pqCertInput{
		Serial: leafSerial,
		Subject: pkix.Name{
			CommonName:   domain,
			Organization: []string{"MTC Demo"},
			Country:      []string{"US"},
		},
		Issuer:     caSubject,
		NotBefore:  now,
		NotAfter:   now.Add(validityDuration),
		SubjectKey: leafPub,
		SignerKey:  caPriv,
		SignerPub:  caPub,
		Scheme:     scheme,
		OID:        oid,
		Extensions: leafExtensions(domain, caPub),
	})
	if err != nil {
		return nil, fmt.Errorf("pqx509: create %s leaf cert: %w", scheme.Name(), err)
	}

	leafKeyDER, err := leafPriv.MarshalBinary()
	if err != nil {
		return nil, fmt.Errorf("pqx509: marshal %s leaf key: %w", scheme.Name(), err)
	}

	return &DemoChain{
		Algorithm: scheme.Name(),
		CertPEM:   pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: leafDER}),
		CertDER:   leafDER,
		CAPEM:     pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: caDER}),
		CADER:     caDER,
		KeyPEM:    pem.EncodeToMemory(&pem.Block{Type: scheme.Name() + " PRIVATE KEY", Bytes: leafKeyDER}),
	}, nil
}

type pqCertInput struct {
	Serial     *big.Int
	Subject    pkix.Name
	Issuer     pkix.Name
	NotBefore  time.Time
	NotAfter   time.Time
	SubjectKey circlsign.PublicKey
	SignerKey  circlsign.PrivateKey
	SignerPub  circlsign.PublicKey
	Scheme     circlsign.Scheme
	OID        asn1.ObjectIdentifier
	Extensions []pkix.Extension
}

func buildPQCertificate(in pqCertInput) ([]byte, error) {
	subjectDER, err := asn1.Marshal(in.Subject.ToRDNSequence())
	if err != nil {
		return nil, fmt.Errorf("marshal subject: %w", err)
	}
	issuerDER, err := asn1.Marshal(in.Issuer.ToRDNSequence())
	if err != nil {
		return nil, fmt.Errorf("marshal issuer: %w", err)
	}
	spkiDER, err := marshalPQSubjectPublicKeyInfo(in.SubjectKey, in.OID)
	if err != nil {
		return nil, err
	}
	var spkiRaw asn1.RawValue
	if _, err := asn1.Unmarshal(spkiDER, &spkiRaw); err != nil {
		return nil, fmt.Errorf("parse SPKI: %w", err)
	}

	algID := algorithmIdentifier{Algorithm: in.OID}
	tbs := tbsCertificate{
		Version:            2,
		SerialNumber:       in.Serial,
		SignatureAlgorithm: algID,
		Issuer:             asn1.RawValue{FullBytes: issuerDER},
		Validity:           validity{NotBefore: in.NotBefore, NotAfter: in.NotAfter},
		Subject:            asn1.RawValue{FullBytes: subjectDER},
		SubjectPubKeyInfo:  spkiRaw,
		Extensions:         in.Extensions,
	}
	tbsDER, err := asn1.Marshal(tbs)
	if err != nil {
		return nil, fmt.Errorf("marshal TBS: %w", err)
	}

	signature := in.Scheme.Sign(in.SignerKey, tbsDER, nil)
	if len(signature) == 0 {
		return nil, fmt.Errorf("sign TBS with %s returned empty signature", in.Scheme.Name())
	}
	if !in.Scheme.Verify(in.SignerPub, tbsDER, signature, nil) {
		return nil, fmt.Errorf("self-check failed for %s signature", in.Scheme.Name())
	}

	return asn1.Marshal(certificate{
		TBSCertificate:     asn1.RawValue{FullBytes: tbsDER},
		SignatureAlgorithm: algID,
		SignatureValue:     asn1.BitString{Bytes: signature, BitLength: len(signature) * 8},
	})
}

func marshalPQSubjectPublicKeyInfo(pub circlsign.PublicKey, oid asn1.ObjectIdentifier) ([]byte, error) {
	pubBytes, err := pub.MarshalBinary()
	if err != nil {
		return nil, fmt.Errorf("marshal public key: %w", err)
	}
	return asn1.Marshal(subjectPublicKeyInfo{
		Algorithm:        algorithmIdentifier{Algorithm: oid},
		SubjectPublicKey: asn1.BitString{Bytes: pubBytes, BitLength: len(pubBytes) * 8},
	})
}

func leafExtensions(domain string, issuerKey circlsign.PublicKey) []pkix.Extension {
	return []pkix.Extension{
		sanExtension(domain),
		keyUsageExtension(x509.KeyUsageDigitalSignature),
		extKeyUsageExtension([]asn1.ObjectIdentifier{
			{1, 3, 6, 1, 5, 5, 7, 3, 1},
			{1, 3, 6, 1, 5, 5, 7, 3, 2},
		}),
		basicConstraintsExtension(false),
		authorityKeyIDExtension(keyID(issuerKey)),
	}
}

func caExtensions(pub circlsign.PublicKey) []pkix.Extension {
	id := keyID(pub)
	return []pkix.Extension{
		keyUsageExtension(x509.KeyUsageCertSign | x509.KeyUsageCRLSign),
		basicConstraintsExtension(true),
		subjectKeyIDExtension(id),
	}
}

func sanExtension(domain string) pkix.Extension {
	value, _ := asn1.Marshal([]asn1.RawValue{{
		Tag:   2,
		Class: asn1.ClassContextSpecific,
		Bytes: []byte(domain),
	}})
	return pkix.Extension{Id: oidSubjectAltName, Value: value}
}

func keyUsageExtension(usage x509.KeyUsage) pkix.Extension {
	var bits [2]byte
	bits[0] = reverseBitsInByte(byte(usage))
	bits[1] = reverseBitsInByte(byte(usage >> 8))

	padding := 0
	bytes := bits[:]
	bitLength := 16
	if bits[1] == 0 {
		padding = countTrailingZeros(bits[0])
		bytes = bits[:1]
		bitLength = 8
	} else {
		padding = countTrailingZeros(bits[1])
	}
	value, _ := asn1.Marshal(asn1.BitString{Bytes: bytes, BitLength: bitLength - padding})
	return pkix.Extension{Id: oidKeyUsage, Critical: true, Value: value}
}

func extKeyUsageExtension(oids []asn1.ObjectIdentifier) pkix.Extension {
	value, _ := asn1.Marshal(oids)
	return pkix.Extension{Id: oidExtKeyUsage, Value: value}
}

func basicConstraintsExtension(isCA bool) pkix.Extension {
	type basicConstraints struct {
		IsCA       bool `asn1:"optional"`
		MaxPathLen int  `asn1:"optional,default:-1"`
	}
	maxPathLen := -1
	if isCA {
		maxPathLen = 0
	}
	value, _ := asn1.Marshal(basicConstraints{IsCA: isCA, MaxPathLen: maxPathLen})
	return pkix.Extension{Id: oidBasicConstraints, Critical: true, Value: value}
}

func subjectKeyIDExtension(id []byte) pkix.Extension {
	value, _ := asn1.Marshal(id)
	return pkix.Extension{Id: oidSubjectKeyIdentifier, Value: value}
}

func authorityKeyIDExtension(id []byte) pkix.Extension {
	type authorityKeyID struct {
		KeyID []byte `asn1:"optional,tag:0"`
	}
	value, _ := asn1.Marshal(authorityKeyID{KeyID: id})
	return pkix.Extension{Id: oidAuthorityKeyIdentifier, Value: value}
}

func keyID(pub circlsign.PublicKey) []byte {
	pubBytes, err := pub.MarshalBinary()
	if err != nil {
		return nil
	}
	sum := sha256.Sum256(pubBytes)
	return sum[:20]
}

func oidForScheme(name string) (asn1.ObjectIdentifier, error) {
	switch strings.ToUpper(name) {
	case "ML-DSA-44":
		return asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 3, 17}, nil
	case "ML-DSA-65":
		return asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 3, 18}, nil
	case "ML-DSA-87":
		return asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 3, 19}, nil
	case "SLH-DSA-SHA2-128S":
		return asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 3, 20}, nil
	case "SLH-DSA-SHA2-128F":
		return asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 3, 21}, nil
	case "SLH-DSA-SHA2-192S":
		return asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 3, 22}, nil
	case "SLH-DSA-SHA2-192F":
		return asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 3, 23}, nil
	case "SLH-DSA-SHA2-256S":
		return asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 3, 24}, nil
	case "SLH-DSA-SHA2-256F":
		return asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 3, 25}, nil
	case "SLH-DSA-SHAKE-128S":
		return asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 3, 26}, nil
	case "SLH-DSA-SHAKE-128F":
		return asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 3, 27}, nil
	case "SLH-DSA-SHAKE-192S":
		return asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 3, 28}, nil
	case "SLH-DSA-SHAKE-192F":
		return asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 3, 29}, nil
	case "SLH-DSA-SHAKE-256S":
		return asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 3, 30}, nil
	case "SLH-DSA-SHAKE-256F":
		return asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 3, 31}, nil
	default:
		return nil, fmt.Errorf("pqx509: no X.509 OID mapping for %q", name)
	}
}

func generateSerial() (*big.Int, error) {
	max := new(big.Int).Lsh(big.NewInt(1), 128)
	serial, err := rand.Int(rand.Reader, max)
	if err != nil {
		return nil, fmt.Errorf("pqx509: generate serial: %w", err)
	}
	return serial, nil
}

func isEC(alg string) bool {
	switch strings.ToLower(strings.TrimSpace(alg)) {
	case "", "ec", "ecdsa", "p-256", "p256":
		return true
	default:
		return false
	}
}

func reverseBitsInByte(in byte) byte {
	var out byte
	for i := 0; i < 8; i++ {
		out <<= 1
		out |= in & 1
		in >>= 1
	}
	return out
}

func countTrailingZeros(b byte) int {
	for i := 0; i < 8; i++ {
		if b&(1<<i) != 0 {
			return i
		}
	}
	return 8
}
