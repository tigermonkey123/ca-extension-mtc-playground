// Copyright (C) 2026 DigiCert, Inc.
//
// Licensed under the dual-license model:
//   1. GNU Affero General Public License v3.0 (AGPL v3) — see LICENSE.txt
//   2. DigiCert Commercial License — see LICENSE_COMMERCIAL.txt
//
// For commercial licensing, contact sales@digicert.com.

// Command mtc-verify-cert verifies MTC certificates. It auto-detects the format:
//
//   - MTC-spec format: signatureAlgorithm = id-alg-mtcProof, proof in signatureValue
//   - Legacy format: ECDSA signature + MTC inclusion proof in X.509 extension
//
// Usage:
//
//	mtc-verify-cert -cert cert.pem [-bridge-url http://localhost:8080]
package main

import (
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/briantrzupek/ca-extension-merkle/internal/localca"
	"github.com/briantrzupek/ca-extension-merkle/internal/merkle"
	"github.com/briantrzupek/ca-extension-merkle/internal/mtccert"
)

var (
	certFile  = flag.String("cert", "", "PEM-encoded certificate to verify (required)")
	bridgeURL = flag.String("bridge-url", "", "mtc-bridge base URL for checkpoint verification (optional)")
)

func main() {
	flag.Parse()

	if *certFile == "" {
		fmt.Fprintf(os.Stderr, "Usage: mtc-verify-cert -cert <cert.pem> [-bridge-url <url>]\n")
		os.Exit(1)
	}

	certPEM, err := os.ReadFile(*certFile)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error reading certificate: %v\n", err)
		os.Exit(1)
	}

	block, _ := pem.Decode(certPEM)
	if block == nil {
		fmt.Fprintf(os.Stderr, "Error: no PEM block found in %s\n", *certFile)
		os.Exit(1)
	}

	// Auto-detect format: MTC-spec (id-alg-mtcProof) vs legacy (X.509 extension).
	if mtccert.IsMTCCertificate(block.Bytes) {
		verifyMTCFormat(block.Bytes)
	} else {
		verifyLegacyFormat(block.Bytes)
	}
}

func verifyMTCFormat(certDER []byte) {
	fmt.Println("=== MTC-Spec Certificate Verification ===")
	fmt.Println()

	parsed, err := mtccert.ParseMTCCertificate(certDER)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error parsing MTC certificate: %v\n", err)
		os.Exit(1)
	}

	fmt.Printf("Format:       MTC-spec (signatureAlgorithm = id-alg-mtcProof)\n")
	fmt.Printf("Serial/Index: %d\n", parsed.SerialNumber)
	fmt.Printf("Not Before:   %s\n", parsed.NotBefore.Format(time.RFC3339))
	fmt.Printf("Not After:    %s\n", parsed.NotAfter.Format(time.RFC3339))
	fmt.Printf("Extensions:   %d\n", len(parsed.Extensions))
	fmt.Println()

	if parsed.Proof == nil {
		fmt.Println("[FAIL] No MTCProof found in signatureValue")
		os.Exit(1)
	}

	fmt.Println("--- MTCProof ---")
	fmt.Printf("Subtree:        [%d, %d)\n", parsed.Proof.Start, parsed.Proof.End)
	fmt.Printf("Inclusion proof: %d hashes\n", len(parsed.Proof.InclusionProof))
	for i, h := range parsed.Proof.InclusionProof {
		fmt.Printf("  hash[%d]: %s\n", i, hex.EncodeToString(h))
	}
	fmt.Printf("Signatures:     %d\n", len(parsed.Proof.Signatures))
	for i, sig := range parsed.Proof.Signatures {
		fmt.Printf("  sig[%d]: cosigner_id=%q, %d bytes\n", i, string(sig.CosignerID), len(sig.Signature))
	}
	if len(parsed.Proof.Signatures) == 0 {
		fmt.Printf("Mode:           signatureless\n")
	} else {
		fmt.Printf("Mode:           signed (%d cosigners)\n", len(parsed.Proof.Signatures))
	}
	fmt.Println()

	opts := mtccert.VerifyOptions{}
	if *bridgeURL != "" {
		trust, err := fetchCosignerTrust()
		if err != nil {
			fmt.Printf("[WARN] Could not fetch cosigner trust material: %v\n", err)
		} else {
			opts.LogID = []byte(trust.LogID)
			opts.CosignerKeys = trust.CosignerKeys
			fmt.Printf("[INFO] Loaded %d trusted cosigner keys from bridge\n", len(opts.CosignerKeys))
		}
		subtrees, err := fetchTrustedSubtrees()
		if err != nil {
			fmt.Printf("[WARN] Could not fetch trusted subtrees: %v\n", err)
		} else {
			opts.TrustedSubtrees = subtrees
			fmt.Printf("[INFO] Loaded %d trusted landmark subtree(s) from bridge\n", len(opts.TrustedSubtrees))
		}
	}

	// Verify the inclusion proof and, for signed standalone proofs, trusted
	// cosigner signatures when trust material is available.
	result, err := mtccert.VerifyMTCCert(certDER, opts)
	if err != nil {
		fmt.Printf("[FAIL] Verification error: %v\n", err)
		os.Exit(1)
	}

	if result.ProofValid {
		fmt.Printf("[PASS] Inclusion proof valid (leaf %d in subtree [%d, %d))\n",
			result.LeafIndex, result.SubtreeStart, result.SubtreeEnd)
	} else {
		fmt.Printf("[FAIL] MTC proof invalid\n")
	}
	fmt.Printf("[INFO] Mode: %s\n", result.Mode)
	if result.SignaturesVerified > 0 {
		fmt.Printf("[PASS] %d trusted cosigner signature(s) verified\n", result.SignaturesVerified)
	} else if len(parsed.Proof.Signatures) > 0 {
		if *bridgeURL == "" {
			fmt.Printf("[WARN] No trusted cosigner signatures verified; use -bridge-url to load /cosigners\n")
		} else {
			fmt.Printf("[FAIL] No trusted cosigner signatures verified\n")
		}
	}

	// Bridge checkpoint verification for MTC certs.
	if *bridgeURL != "" {
		fmt.Println()
		fmt.Println("--- Bridge Checkpoint ---")
		verifyMTCCheckpoint(parsed)
		checkRevocation(parsed.SerialNumber)
	}
}

type cosignerTrust struct {
	LogID        string
	CosignerKeys map[string]mtccert.CosignerKey
}

func fetchCosignerTrust() (*cosignerTrust, error) {
	url := strings.TrimRight(*bridgeURL, "/") + "/cosigners"
	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Get(url)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("bridge returned %d for /cosigners", resp.StatusCode)
	}

	var body struct {
		LogID     string `json:"log_id"`
		Cosigners []struct {
			CosignerID string `json:"cosigner_id"`
			Algorithm  string `json:"algorithm"`
			PublicKey  string `json:"public_key"`
		} `json:"cosigners"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
		return nil, err
	}

	keys := make(map[string]mtccert.CosignerKey)
	for _, c := range body.Cosigners {
		pub, err := hex.DecodeString(c.PublicKey)
		if err != nil {
			return nil, fmt.Errorf("decode public key for %q: %w", c.CosignerID, err)
		}
		keys[c.CosignerID] = mtccert.CosignerKey{
			Algorithm: c.Algorithm,
			PublicKey: pub,
		}
	}
	return &cosignerTrust{LogID: body.LogID, CosignerKeys: keys}, nil
}

func fetchTrustedSubtrees() ([]mtccert.TrustedSubtree, error) {
	url := strings.TrimRight(*bridgeURL, "/") + "/trusted-subtrees"
	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Get(url)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("bridge returned %d for /trusted-subtrees", resp.StatusCode)
	}

	var body []struct {
		Start    int64  `json:"start"`
		End      int64  `json:"end"`
		RootHash string `json:"root_hash"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
		return nil, err
	}

	subtrees := make([]mtccert.TrustedSubtree, 0, len(body))
	for _, st := range body {
		rootBytes, err := hex.DecodeString(st.RootHash)
		if err != nil {
			return nil, fmt.Errorf("decode trusted subtree [%d,%d): %w", st.Start, st.End, err)
		}
		if len(rootBytes) != merkle.HashSize {
			return nil, fmt.Errorf("trusted subtree [%d,%d) root has %d bytes", st.Start, st.End, len(rootBytes))
		}
		var root merkle.Hash
		copy(root[:], rootBytes)
		subtrees = append(subtrees, mtccert.TrustedSubtree{Start: st.Start, End: st.End, Root: root})
	}
	return subtrees, nil
}

func verifyMTCCheckpoint(parsed *mtccert.ParsedMTCCert) {
	url := strings.TrimRight(*bridgeURL, "/") + "/checkpoint"
	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Get(url)
	if err != nil {
		fmt.Printf("[SKIP] Could not fetch checkpoint: %v\n", err)
		return
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		fmt.Printf("[SKIP] Could not read checkpoint: %v\n", err)
		return
	}

	if resp.StatusCode != http.StatusOK {
		fmt.Printf("[SKIP] Bridge returned %d for checkpoint\n", resp.StatusCode)
		return
	}

	lines := strings.Split(string(body), "\n")
	if len(lines) < 3 {
		fmt.Printf("[SKIP] Invalid checkpoint format\n")
		return
	}

	liveTreeSize, err := strconv.ParseInt(lines[1], 10, 64)
	if err != nil {
		fmt.Printf("[SKIP] Invalid tree size in checkpoint: %v\n", err)
		return
	}

	proofEnd := int64(parsed.Proof.End)
	if proofEnd <= liveTreeSize {
		fmt.Printf("[PASS] Subtree end (%d) <= live tree size (%d)\n", proofEnd, liveTreeSize)
	} else {
		fmt.Printf("[WARN] Subtree end (%d) > live tree size (%d)\n", proofEnd, liveTreeSize)
	}

	proofURL := strings.TrimRight(*bridgeURL, "/") +
		fmt.Sprintf("/proof/inclusion?index=%d", parsed.SerialNumber)
	presp, err := client.Get(proofURL)
	if err != nil {
		fmt.Printf("[SKIP] Could not fetch live proof: %v\n", err)
		return
	}
	defer presp.Body.Close()

	if presp.StatusCode == http.StatusOK {
		var liveProof struct {
			LeafHash string `json:"leaf_hash"`
			TreeSize int64  `json:"tree_size"`
		}
		if err := json.NewDecoder(presp.Body).Decode(&liveProof); err == nil {
			fmt.Printf("[PASS] Entry exists in live log at index %d (tree_size=%d)\n",
				parsed.SerialNumber, liveProof.TreeSize)
		}
	}
}

func verifyLegacyFormat(certDER []byte) {
	fmt.Println("=== Legacy Certificate Verification ===")
	fmt.Println()

	cert, err := x509.ParseCertificate(certDER)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error parsing certificate: %v\n", err)
		os.Exit(1)
	}

	fmt.Printf("Format:     Legacy (ECDSA + X.509 extension)\n")
	fmt.Printf("Subject:    %s\n", cert.Subject.CommonName)
	fmt.Printf("Issuer:     %s\n", cert.Issuer.CommonName)
	fmt.Printf("Serial:     %s\n", cert.SerialNumber.String())
	fmt.Printf("Not Before: %s\n", cert.NotBefore.Format(time.RFC3339))
	fmt.Printf("Not After:  %s\n", cert.NotAfter.Format(time.RFC3339))
	if len(cert.DNSNames) > 0 {
		fmt.Printf("DNS Names:  %s\n", strings.Join(cert.DNSNames, ", "))
	}
	fmt.Println()

	proof, ok, err := localca.VerifyEmbeddedProof(certDER)
	if err != nil {
		fmt.Printf("[FAIL] %v\n", err)
		os.Exit(1)
	}

	fmt.Println("--- Inclusion Proof ---")
	fmt.Printf("Log Origin: %s\n", proof.LogOrigin)
	fmt.Printf("Leaf Index: %d\n", proof.LeafIndex)
	fmt.Printf("Tree Size:  %d\n", proof.TreeSize)
	fmt.Printf("Root Hash:  %s\n", hex.EncodeToString(proof.RootHash))
	fmt.Printf("Proof Path: %d hashes\n", len(proof.ProofHashes))
	for i, h := range proof.ProofHashes {
		fmt.Printf("  hash[%d]: %s\n", i, hex.EncodeToString(h))
	}
	fmt.Println()

	if ok {
		fmt.Println("[PASS] Merkle inclusion proof verified")
	} else {
		fmt.Println("[FAIL] Merkle inclusion proof verification FAILED")
	}

	if proof.Checkpoint != "" {
		fmt.Printf("[INFO] Checkpoint: %s\n", proof.Checkpoint)
	}

	if *bridgeURL != "" {
		fmt.Println()
		fmt.Println("--- Bridge Checkpoint ---")
		verifyCheckpoint(proof)
		checkRevocation(proof.LeafIndex)
	}
}

func checkRevocation(leafIndex int64) {
	fmt.Println()
	fmt.Println("--- Revocation ---")

	revoked, err := fetchRevocationStatus(leafIndex)
	if err != nil {
		fmt.Printf("[WARN] Could not check revocation status: %v\n", err)
		return
	}
	if revoked {
		fmt.Printf("[FAIL] Certificate revoked at log index %d\n", leafIndex)
		os.Exit(1)
	}
	fmt.Printf("[PASS] Certificate not revoked at log index %d\n", leafIndex)
}

func fetchRevocationStatus(leafIndex int64) (bool, error) {
	if leafIndex < 0 {
		return false, fmt.Errorf("invalid negative log index %d", leafIndex)
	}

	url := strings.TrimRight(*bridgeURL, "/") + "/revocation"
	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Get(url)
	if err != nil {
		return false, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return false, fmt.Errorf("bridge returned %d for /revocation", resp.StatusCode)
	}

	bitmap, err := io.ReadAll(resp.Body)
	if err != nil {
		return false, err
	}
	return revocationBitmapHasIndex(bitmap, leafIndex), nil
}

func revocationBitmapHasIndex(bitmap []byte, leafIndex int64) bool {
	if leafIndex < 0 {
		return false
	}
	byteIdx := leafIndex / 8
	if byteIdx < 0 || byteIdx >= int64(len(bitmap)) {
		return false
	}
	bitIdx := uint(7 - leafIndex%8)
	return bitmap[byteIdx]&(1<<bitIdx) != 0
}

func verifyCheckpoint(proof *localca.InclusionProofExt) {
	url := strings.TrimRight(*bridgeURL, "/") + "/checkpoint"
	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Get(url)
	if err != nil {
		fmt.Printf("[SKIP] Could not fetch checkpoint: %v\n", err)
		return
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		fmt.Printf("[SKIP] Could not read checkpoint: %v\n", err)
		return
	}

	if resp.StatusCode != http.StatusOK {
		fmt.Printf("[SKIP] Bridge returned %d for checkpoint\n", resp.StatusCode)
		return
	}

	// Parse checkpoint: origin\ntree_size\nroot_hash_base64\n...
	lines := strings.Split(string(body), "\n")
	if len(lines) < 3 {
		fmt.Printf("[SKIP] Invalid checkpoint format\n")
		return
	}

	liveTreeSize, err := strconv.ParseInt(lines[1], 10, 64)
	if err != nil {
		fmt.Printf("[SKIP] Invalid tree size in checkpoint: %v\n", err)
		return
	}

	// The proof's tree size should be <= live tree size.
	if proof.TreeSize <= liveTreeSize {
		fmt.Printf("[PASS] Proof tree size (%d) <= live tree size (%d)\n", proof.TreeSize, liveTreeSize)
	} else {
		fmt.Printf("[WARN] Proof tree size (%d) > live tree size (%d)\n", proof.TreeSize, liveTreeSize)
	}

	// Try to verify root hash via the inclusion proof API.
	proofURL := strings.TrimRight(*bridgeURL, "/") +
		fmt.Sprintf("/proof/inclusion?index=%d", proof.LeafIndex)
	presp, err := client.Get(proofURL)
	if err != nil {
		fmt.Printf("[SKIP] Could not fetch live proof: %v\n", err)
		return
	}
	defer presp.Body.Close()

	if presp.StatusCode == http.StatusOK {
		var liveProof struct {
			LeafHash string `json:"leaf_hash"`
			TreeSize int64  `json:"tree_size"`
		}
		if err := json.NewDecoder(presp.Body).Decode(&liveProof); err == nil {
			fmt.Printf("[PASS] Entry exists in live log at index %d (tree_size=%d)\n",
				proof.LeafIndex, liveProof.TreeSize)
		}
	}
}
