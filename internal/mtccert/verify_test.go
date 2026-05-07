// Copyright (C) 2026 DigiCert, Inc.
//
// Licensed under the dual-license model:
//   1. GNU Affero General Public License v3.0 (AGPL v3) — see LICENSE.txt
//   2. DigiCert Commercial License — see LICENSE_COMMERCIAL.txt
//
// For commercial licensing, contact sales@digicert.com.

package mtccert

import (
	"crypto"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"testing"
	"time"

	"github.com/briantrzupek/ca-extension-merkle/internal/merkle"
	"github.com/briantrzupek/ca-extension-merkle/internal/mtcformat"
	"github.com/cloudflare/circl/sign/mldsa/mldsa44"
)

func TestVerifyMTCCertStandaloneEd25519(t *testing.T) {
	certDER, opts := buildSignedTestCert(t, signTestEd25519)

	result, err := VerifyMTCCert(certDER, opts)
	if err != nil {
		t.Fatalf("VerifyMTCCert: %v", err)
	}
	if !result.ProofValid {
		t.Fatal("ProofValid = false, want true")
	}
	if result.Mode != "signed" {
		t.Fatalf("Mode = %q, want signed", result.Mode)
	}
	if result.SignaturesVerified != 1 {
		t.Fatalf("SignaturesVerified = %d, want 1", result.SignaturesVerified)
	}
}

func TestVerifyMTCCertStandaloneMLDSA44(t *testing.T) {
	certDER, opts := buildSignedTestCert(t, signTestMLDSA44)

	result, err := VerifyMTCCert(certDER, opts)
	if err != nil {
		t.Fatalf("VerifyMTCCert: %v", err)
	}
	if !result.ProofValid {
		t.Fatal("ProofValid = false, want true")
	}
	if result.SignaturesVerified != 1 {
		t.Fatalf("SignaturesVerified = %d, want 1", result.SignaturesVerified)
	}
}

func TestVerifyMTCCertStandaloneTamperedInclusionProofFails(t *testing.T) {
	certDER, opts := buildSignedTestCert(t, signTestEd25519, func(proof *mtcformat.MTCProof) {
		proof.InclusionProof[0][0] ^= 0xff
	})

	result, err := VerifyMTCCert(certDER, opts)
	if err != nil {
		t.Fatalf("VerifyMTCCert: %v", err)
	}
	if result.ProofValid {
		t.Fatal("ProofValid = true, want false")
	}
}

func TestVerifyMTCCertStandaloneTamperedSignatureFails(t *testing.T) {
	certDER, opts := buildSignedTestCert(t, signTestEd25519, func(proof *mtcformat.MTCProof) {
		proof.Signatures[0].Signature[0] ^= 0xff
	})

	result, err := VerifyMTCCert(certDER, opts)
	if err != nil {
		t.Fatalf("VerifyMTCCert: %v", err)
	}
	if result.ProofValid {
		t.Fatal("ProofValid = true, want false")
	}
	if result.SignaturesVerified != 0 {
		t.Fatalf("SignaturesVerified = %d, want 0", result.SignaturesVerified)
	}
}

func TestVerifyMTCCertStandaloneUnknownCosignerIgnored(t *testing.T) {
	certDER, opts := buildSignedTestCert(t, signTestEd25519)
	opts.CosignerKeys = map[string]CosignerKey{
		"other": opts.CosignerKeys["test-cosigner"],
	}

	result, err := VerifyMTCCert(certDER, opts)
	if err != nil {
		t.Fatalf("VerifyMTCCert: %v", err)
	}
	if result.ProofValid {
		t.Fatal("ProofValid = true, want false")
	}
}

func TestVerifyMTCCertSignaturelessLandmarkMismatchFails(t *testing.T) {
	csr := testCSR(t)
	notBefore := time.Now().UTC().Truncate(time.Second)
	notAfter := notBefore.Add(time.Hour)
	leafHash, proofHashes := testLogTree(t, csr, "test-log", notBefore, notAfter)
	proofBytes := hashesToBytes(proofHashes)
	proof := &mtcformat.MTCProof{
		Start:          0,
		End:            2,
		InclusionProof: proofBytes,
	}
	certDER, err := BuildMTCCertFromCSR(csr, "test-log", notBefore, notAfter, []string{"test.example.com"}, 0, proof)
	if err != nil {
		t.Fatalf("BuildMTCCertFromCSR: %v", err)
	}

	badRoot := merkle.LeafHash([]byte("wrong landmark"))
	result, err := VerifyMTCCert(certDER, VerifyOptions{
		Landmarks: map[int64]merkle.Hash{2: badRoot},
		LogID:     []byte("test-log"),
	})
	if err != nil {
		t.Fatalf("VerifyMTCCert: %v", err)
	}
	if result.ProofValid {
		t.Fatalf("ProofValid = true, want false; leaf hash was %x", leafHash)
	}
}

func TestVerifyMTCCertSignaturelessWithoutTrustedSubtreeFails(t *testing.T) {
	csr := testCSR(t)
	notBefore := time.Now().UTC().Truncate(time.Second)
	notAfter := notBefore.Add(time.Hour)
	_, proofHashes := testLogTree(t, csr, "test-log", notBefore, notAfter)
	proof := &mtcformat.MTCProof{
		Start:          0,
		End:            2,
		InclusionProof: hashesToBytes(proofHashes),
	}
	certDER, err := BuildMTCCertFromCSR(csr, "test-log", notBefore, notAfter, []string{"test.example.com"}, 0, proof)
	if err != nil {
		t.Fatalf("BuildMTCCertFromCSR: %v", err)
	}

	result, err := VerifyMTCCert(certDER, VerifyOptions{})
	if err != nil {
		t.Fatalf("VerifyMTCCert: %v", err)
	}
	if result.ProofValid {
		t.Fatal("ProofValid = true, want false without trusted landmark material")
	}
}

func TestVerifyMTCCertSignaturelessTrustedSubtree(t *testing.T) {
	csr := testCSR(t)
	logID := "test-log"
	notBefore := time.Now().UTC().Truncate(time.Second)
	notAfter := notBefore.Add(time.Hour)

	logEntryDER, err := mtcformat.BuildLogEntryFromCSR(logID, notBefore, notAfter, csr, []string{"test.example.com"})
	if err != nil {
		t.Fatalf("BuildLogEntryFromCSR: %v", err)
	}
	contentsOctets, err := mtcformat.DERContentsOctets(logEntryDER)
	if err != nil {
		t.Fatalf("DERContentsOctets: %v", err)
	}
	certEntry, err := mtcformat.MarshalEntry(&mtcformat.MerkleTreeCertEntry{Type: mtcformat.EntryTypeTBSCert, Data: contentsOctets})
	if err != nil {
		t.Fatalf("MarshalEntry cert: %v", err)
	}
	nullEntry, err := mtcformat.MarshalEntry(&mtcformat.MerkleTreeCertEntry{Type: mtcformat.EntryTypeNull})
	if err != nil {
		t.Fatalf("MarshalEntry null: %v", err)
	}

	leaves := [][]byte{nullEntry, certEntry, nullEntry}
	leafHashes := make([]merkle.Hash, len(leaves))
	for i, leaf := range leaves {
		leafHashes[i] = merkle.LeafHash(leaf)
	}
	hashAt := func(idx int64) merkle.Hash { return leafHashes[idx] }
	proofHashes, err := merkle.InclusionProof(0, 2, func(idx int64) merkle.Hash {
		return hashAt(idx + 1)
	})
	if err != nil {
		t.Fatalf("InclusionProof: %v", err)
	}
	trustedRoot := merkle.SubtreeHash(1, 3, hashAt)
	proof := &mtcformat.MTCProof{
		Start:          1,
		End:            3,
		InclusionProof: hashesToBytes(proofHashes),
	}
	certDER, err := BuildMTCCertFromCSR(csr, logID, notBefore, notAfter, []string{"test.example.com"}, 1, proof)
	if err != nil {
		t.Fatalf("BuildMTCCertFromCSR: %v", err)
	}

	result, err := VerifyMTCCert(certDER, VerifyOptions{
		TrustedSubtrees: []TrustedSubtree{{Start: 1, End: 3, Root: trustedRoot}},
		LogID:           []byte(logID),
	})
	if err != nil {
		t.Fatalf("VerifyMTCCert: %v", err)
	}
	if !result.ProofValid {
		t.Fatal("ProofValid = false, want true")
	}
	if result.Mode != "signatureless" {
		t.Fatalf("Mode = %q, want signatureless", result.Mode)
	}
}

type testSigner func(t *testing.T, input []byte) (mtcformat.MTCSignature, CosignerKey)

func buildSignedTestCert(t *testing.T, signer testSigner, mutators ...func(*mtcformat.MTCProof)) ([]byte, VerifyOptions) {
	t.Helper()
	csr := testCSR(t)
	logID := []byte("test-log")
	notBefore := time.Now().UTC().Truncate(time.Second)
	notAfter := notBefore.Add(time.Hour)
	subtreeRoot, proofHashes := testLogTree(t, csr, string(logID), notBefore, notAfter)
	input, err := mtcformat.BuildSubtreeSignatureInput([]byte("test-cosigner"), logID, 0, 2, subtreeRoot[:])
	if err != nil {
		t.Fatalf("BuildSubtreeSignatureInput: %v", err)
	}
	mtcSig, key := signer(t, input)
	proof := &mtcformat.MTCProof{
		Start:          0,
		End:            2,
		InclusionProof: hashesToBytes(proofHashes),
		Signatures:     []mtcformat.MTCSignature{mtcSig},
	}
	for _, mutate := range mutators {
		mutate(proof)
	}
	certDER, err := BuildMTCCertFromCSR(csr, string(logID), notBefore, notAfter, []string{"test.example.com"}, 0, proof)
	if err != nil {
		t.Fatalf("BuildMTCCertFromCSR: %v", err)
	}
	return certDER, VerifyOptions{
		LogID: logID,
		CosignerKeys: map[string]CosignerKey{
			"test-cosigner": key,
		},
	}
}

func signTestEd25519(t *testing.T, input []byte) (mtcformat.MTCSignature, CosignerKey) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	sig := ed25519.Sign(priv, input)
	return mtcformat.MTCSignature{CosignerID: []byte("test-cosigner"), Signature: sig}, CosignerKey{
		Algorithm: "ed25519",
		PublicKey: pub,
	}
}

func signTestMLDSA44(t *testing.T, input []byte) (mtcformat.MTCSignature, CosignerKey) {
	t.Helper()
	pub, priv, err := mldsa44.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	sig, err := priv.Sign(rand.Reader, input, crypto.Hash(0))
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}
	pubBytes, err := pub.MarshalBinary()
	if err != nil {
		t.Fatalf("MarshalBinary: %v", err)
	}
	return mtcformat.MTCSignature{CosignerID: []byte("test-cosigner"), Signature: sig}, CosignerKey{
		Algorithm: "ML-DSA-44",
		PublicKey: pubBytes,
	}
}

func testLogTree(t *testing.T, csr *x509.CertificateRequest, logID string, notBefore, notAfter time.Time) (merkle.Hash, []merkle.Hash) {
	t.Helper()
	logEntryDER, err := mtcformat.BuildLogEntryFromCSR(logID, notBefore, notAfter, csr, []string{"test.example.com"})
	if err != nil {
		t.Fatalf("BuildLogEntryFromCSR: %v", err)
	}
	contentsOctets, err := mtcformat.DERContentsOctets(logEntryDER)
	if err != nil {
		t.Fatalf("DERContentsOctets: %v", err)
	}
	certEntry, err := mtcformat.MarshalEntry(&mtcformat.MerkleTreeCertEntry{Type: mtcformat.EntryTypeTBSCert, Data: contentsOctets})
	if err != nil {
		t.Fatalf("MarshalEntry cert: %v", err)
	}
	nullEntry, err := mtcformat.MarshalEntry(&mtcformat.MerkleTreeCertEntry{Type: mtcformat.EntryTypeNull})
	if err != nil {
		t.Fatalf("MarshalEntry null: %v", err)
	}
	leaves := [][]byte{certEntry, nullEntry}
	hashAt := func(idx int64) merkle.Hash { return merkle.LeafHash(leaves[idx]) }
	root := merkle.MTH(leaves)
	proof, err := merkle.InclusionProof(0, int64(len(leaves)), hashAt)
	if err != nil {
		t.Fatalf("InclusionProof: %v", err)
	}
	return root, proof
}

func hashesToBytes(hashes []merkle.Hash) [][]byte {
	result := make([][]byte, len(hashes))
	for i, h := range hashes {
		result[i] = make([]byte, merkle.HashSize)
		copy(result[i], h[:])
	}
	return result
}
