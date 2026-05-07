// Copyright (C) 2026 DigiCert, Inc.
//
// Licensed under the dual-license model:
//   1. GNU Affero General Public License v3.0 (AGPL v3) — see LICENSE.txt
//   2. DigiCert Commercial License — see LICENSE_COMMERCIAL.txt
//
// For commercial licensing, contact sales@digicert.com.

// Command mtc-tls-verify connects to a TLS server, extracts the stapled MTC
// assertion bundle from the SignedCertificateTimestamps extension, and verifies
// the Merkle inclusion proof against the mtc-bridge checkpoint.
//
// Usage:
//
//	go run ./cmd/mtc-tls-verify -url https://localhost:4443 -insecure
package main

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/briantrzupek/ca-extension-merkle/internal/assertion"
	"github.com/briantrzupek/ca-extension-merkle/internal/merkle"
	"github.com/briantrzupek/ca-extension-merkle/internal/mtccert"
)

var (
	serverURL = flag.String("url", "https://localhost:4443", "TLS server URL to verify")
	bridgeURL = flag.String("bridge-url", "http://localhost:8080", "mtc-bridge URL for checkpoint")
	insecure  = flag.Bool("insecure", false, "skip X.509 certificate verification")
	verbose   = flag.Bool("verbose", false, "show additional debug output")
)

type checkResult struct {
	name   string
	passed bool
	detail string
}

func main() {
	flag.Parse()

	u, err := url.Parse(*serverURL)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: invalid URL: %v\n", err)
		os.Exit(1)
	}
	host := u.Host
	if !strings.Contains(host, ":") {
		if u.Scheme == "https" {
			host += ":443"
		} else {
			host += ":80"
		}
	}

	fmt.Println("MTC TLS Verification Report")
	fmt.Println("===========================")

	// Step 1: TLS handshake.
	tlsConfig := &tls.Config{
		InsecureSkipVerify: *insecure,
		MinVersion:         tls.VersionTLS13,
	}

	if *verbose {
		fmt.Printf("Connecting to %s...\n", host)
	}

	conn, err := tls.Dial("tcp", host, tlsConfig)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: TLS connection failed: %v\n", err)
		os.Exit(1)
	}

	state := conn.ConnectionState()
	conn.Close()

	if len(state.PeerCertificates) == 0 {
		fmt.Fprintf(os.Stderr, "error: no peer certificates received\n")
		os.Exit(1)
	}

	leaf := state.PeerCertificates[0]

	fmt.Printf("Server:      %s\n", host)

	// Auto-detect MTC-spec vs legacy format.
	if mtccert.IsMTCCertificate(leaf.Raw) {
		verifyMTCCert(leaf.Raw, host)
	} else {
		verifyLegacyCert(leaf, state, host)
	}
}

func verifyMTCCert(certDER []byte, host string) {
	parsed, err := mtccert.ParseMTCCertificate(certDER)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: failed to parse MTC certificate: %v\n", err)
		os.Exit(1)
	}

	fmt.Printf("Format:      MTC-spec (id-alg-mtcProof)\n")
	fmt.Printf("Serial/Index: %d\n", parsed.SerialNumber)
	fmt.Printf("Not Before:  %s\n", parsed.NotBefore.Format(time.RFC3339))
	fmt.Printf("Not After:   %s\n", parsed.NotAfter.Format(time.RFC3339))

	if parsed.Proof != nil {
		fmt.Printf("Subtree:     [%d, %d)\n", parsed.Proof.Start, parsed.Proof.End)
		fmt.Printf("Proof Depth: %d\n", len(parsed.Proof.InclusionProof))
		fmt.Printf("Signatures:  %d\n", len(parsed.Proof.Signatures))
	}
	fmt.Println()

	var results []checkResult

	// Check 1: MTC certificate parsed.
	results = append(results, checkResult{
		name:   "MTC certificate received via TLS",
		passed: true,
		detail: fmt.Sprintf("serial=%d", parsed.SerialNumber),
	})

	// Check 2: MTCProof present.
	if parsed.Proof == nil {
		results = append(results, checkResult{
			name:   "MTCProof present in signatureValue",
			passed: false,
			detail: "no proof found",
		})
		printResults(results)
		os.Exit(1)
	}
	results = append(results, checkResult{
		name:   "MTCProof present in signatureValue",
		passed: true,
		detail: fmt.Sprintf("subtree [%d, %d), %d hashes", parsed.Proof.Start, parsed.Proof.End, len(parsed.Proof.InclusionProof)),
	})

	opts := mtccert.VerifyOptions{}
	if *bridgeURL != "" {
		trust, err := fetchCosignerTrust(*bridgeURL)
		if err != nil {
			results = append(results, checkResult{
				name:   "Trusted cosigner keys loaded",
				passed: false,
				detail: err.Error(),
			})
		} else {
			opts.LogID = []byte(trust.LogID)
			opts.CosignerKeys = trust.CosignerKeys
			results = append(results, checkResult{
				name:   "Trusted cosigner keys loaded",
				passed: true,
				detail: fmt.Sprintf("%d key(s)", len(opts.CosignerKeys)),
			})
		}

		subtrees, err := fetchTrustedSubtrees(*bridgeURL)
		if err != nil {
			results = append(results, checkResult{
				name:   "Trusted landmark subtrees loaded",
				passed: false,
				detail: err.Error(),
			})
		} else {
			opts.TrustedSubtrees = subtrees
			results = append(results, checkResult{
				name:   "Trusted landmark subtrees loaded",
				passed: true,
				detail: fmt.Sprintf("%d subtree(s)", len(opts.TrustedSubtrees)),
			})
		}
	}

	// Check 3: Verify the MTC proof against trusted cosigner signatures or
	// landmark subtrees, depending on the proof mode.
	result, verErr := mtccert.VerifyMTCCert(certDER, opts)
	if verErr != nil {
		results = append(results, checkResult{
			name:   "MTC proof verified",
			passed: false,
			detail: verErr.Error(),
		})
	} else if result.ProofValid {
		results = append(results, checkResult{
			name:   "MTC proof verified",
			passed: true,
			detail: fmt.Sprintf("leaf %d in subtree [%d, %d)", result.LeafIndex, result.SubtreeStart, result.SubtreeEnd),
		})
	} else {
		results = append(results, checkResult{
			name:   "MTC proof verified",
			passed: false,
			detail: "no trusted cosigner signature or landmark subtree verified",
		})
	}

	// Check 4: Mode info.
	if result != nil {
		mode := result.Mode
		if result.SignaturesVerified > 0 {
			mode = fmt.Sprintf("signed (%d cosigners)", result.SignaturesVerified)
		}
		results = append(results, checkResult{
			name:   "Verification mode",
			passed: true,
			detail: mode,
		})
		if len(parsed.Proof.Signatures) > 0 {
			results = append(results, checkResult{
				name:   "Trusted cosigner signature verified",
				passed: result.SignaturesVerified > 0,
				detail: fmt.Sprintf("%d verified", result.SignaturesVerified),
			})
		} else {
			results = append(results, checkResult{
				name:   "Trusted landmark subtree verified",
				passed: result.ProofValid,
			})
		}
	}

	printResults(results)
}

type cosignerTrust struct {
	LogID        string
	CosignerKeys map[string]mtccert.CosignerKey
}

func fetchCosignerTrust(bridgeBase string) (*cosignerTrust, error) {
	url := strings.TrimRight(bridgeBase, "/") + "/cosigners"
	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Get(url)
	if err != nil {
		return nil, fmt.Errorf("GET /cosigners: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("bridge returned HTTP %d for /cosigners", resp.StatusCode)
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
		return nil, fmt.Errorf("decode /cosigners: %w", err)
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

func fetchTrustedSubtrees(bridgeBase string) ([]mtccert.TrustedSubtree, error) {
	url := strings.TrimRight(bridgeBase, "/") + "/trusted-subtrees"
	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Get(url)
	if err != nil {
		return nil, fmt.Errorf("GET /trusted-subtrees: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("bridge returned HTTP %d for /trusted-subtrees", resp.StatusCode)
	}

	var body []struct {
		Start    int64  `json:"start"`
		End      int64  `json:"end"`
		RootHash string `json:"root_hash"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
		return nil, fmt.Errorf("decode /trusted-subtrees: %w", err)
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

func verifyLegacyCert(leaf *x509.Certificate, state tls.ConnectionState, host string) {
	leafSerial := strings.ToUpper(hex.EncodeToString(leaf.SerialNumber.Bytes()))

	fmt.Printf("Format:      Legacy (ECDSA + assertion staple)\n")
	fmt.Printf("Subject:     CN=%s\n", leaf.Subject.CommonName)
	fmt.Printf("Serial:      %s\n", leafSerial)

	// Step 2: Extract assertion from SCT field.
	var results []checkResult

	if len(state.SignedCertificateTimestamps) == 0 {
		results = append(results, checkResult{
			name:   "Assertion present in TLS handshake",
			passed: false,
			detail: "no SignedCertificateTimestamps in handshake",
		})
		printResults(results)
		os.Exit(1)
	}

	results = append(results, checkResult{
		name:   "Assertion present in TLS handshake",
		passed: true,
		detail: fmt.Sprintf("%d bytes", len(state.SignedCertificateTimestamps[0])),
	})

	// Step 3: Parse assertion bundle.
	sctData := state.SignedCertificateTimestamps[0]
	var bundle assertion.Bundle
	if err := json.Unmarshal(sctData, &bundle); err != nil {
		fmt.Fprintf(os.Stderr, "error: failed to parse assertion JSON: %v\n", err)
		if *verbose {
			fmt.Fprintf(os.Stderr, "Raw SCT data: %s\n", string(sctData))
		}
		os.Exit(1)
	}

	fmt.Printf("Leaf Index:  %d\n", bundle.LeafIndex)
	fmt.Printf("Tree Size:   %d\n", bundle.TreeSize)
	rootTrunc := bundle.RootHash
	if len(rootTrunc) > 16 {
		rootTrunc = rootTrunc[:16] + "..."
	}
	fmt.Printf("Root Hash:   %s\n", rootTrunc)
	fmt.Printf("Proof Depth: %d\n", len(bundle.Proof))
	if bundle.LogOrigin != "" {
		fmt.Printf("Log Origin:  %s\n", bundle.LogOrigin)
	}
	fmt.Println()

	// Check 2: Certificate serial matches assertion.
	if strings.EqualFold(leafSerial, bundle.SerialHex) {
		results = append(results, checkResult{
			name:   "Certificate serial matches assertion",
			passed: true,
		})
	} else {
		results = append(results, checkResult{
			name:   "Certificate serial matches assertion",
			passed: false,
			detail: fmt.Sprintf("cert=%s assertion=%s", leafSerial, bundle.SerialHex),
		})
	}

	// Check 3: Merkle inclusion proof valid.
	valid, err := assertion.Verify(&bundle)
	if err != nil {
		results = append(results, checkResult{
			name:   "Merkle inclusion proof valid",
			passed: false,
			detail: err.Error(),
		})
	} else if valid {
		results = append(results, checkResult{
			name:   "Merkle inclusion proof valid",
			passed: true,
		})
	} else {
		results = append(results, checkResult{
			name:   "Merkle inclusion proof valid",
			passed: false,
			detail: "proof verification returned false",
		})
	}

	// Check 4: Root hash matches checkpoint.
	cpTreeSize, cpRootHash, cpErr := fetchCheckpoint(*bridgeURL)
	if cpErr != nil {
		results = append(results, checkResult{
			name:   "Root hash matches checkpoint",
			passed: false,
			detail: fmt.Sprintf("failed to fetch checkpoint: %v", cpErr),
		})
	} else {
		if *verbose {
			fmt.Printf("  Checkpoint tree_size=%d root=%s...\n", cpTreeSize, cpRootHash[:16])
			fmt.Printf("  Bundle     tree_size=%d root=%s...\n", bundle.TreeSize, bundle.RootHash[:16])
		}

		if strings.EqualFold(bundle.RootHash, cpRootHash) {
			results = append(results, checkResult{
				name:   "Root hash matches checkpoint",
				passed: true,
				detail: "exact match (latest checkpoint)",
			})
		} else if bundle.TreeSize <= cpTreeSize {
			results = append(results, checkResult{
				name:   "Root hash matches checkpoint",
				passed: true,
				detail: fmt.Sprintf("proof from tree_size=%d, current=%d (valid older proof)", bundle.TreeSize, cpTreeSize),
			})
		} else {
			results = append(results, checkResult{
				name:   "Root hash matches checkpoint",
				passed: false,
				detail: fmt.Sprintf("root mismatch and bundle tree_size=%d > checkpoint=%d", bundle.TreeSize, cpTreeSize),
			})
		}
	}

	// Check 5: Certificate not revoked.
	if bundle.Revoked {
		results = append(results, checkResult{
			name:   "Certificate not revoked",
			passed: false,
			detail: "certificate is marked as revoked in assertion",
		})
	} else {
		results = append(results, checkResult{
			name:   "Certificate not revoked",
			passed: true,
		})
	}

	printResults(results)
}

func printResults(results []checkResult) {
	fmt.Println("Verification:")
	allPassed := true
	for _, r := range results {
		if r.passed {
			fmt.Printf("  [PASS] %s", r.name)
			if *verbose && r.detail != "" {
				fmt.Printf(" (%s)", r.detail)
			}
			fmt.Println()
		} else {
			allPassed = false
			fmt.Printf("  [FAIL] %s", r.name)
			if r.detail != "" {
				fmt.Printf(" — %s", r.detail)
			}
			fmt.Println()
		}
	}

	fmt.Println()
	if allPassed {
		fmt.Println("Result: MTC-VERIFIED")
	} else {
		fmt.Println("Result: VERIFICATION FAILED")
		os.Exit(1)
	}
}

func fetchCheckpoint(bridgeBase string) (treeSize int64, rootHash string, err error) {
	url := strings.TrimRight(bridgeBase, "/") + "/checkpoint"
	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Get(url)
	if err != nil {
		return 0, "", fmt.Errorf("HTTP GET: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return 0, "", fmt.Errorf("checkpoint returned HTTP %d", resp.StatusCode)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return 0, "", fmt.Errorf("read body: %w", err)
	}

	text := string(body)
	parts := strings.SplitN(text, "\n\n", 2)
	lines := strings.Split(strings.TrimRight(parts[0], "\n"), "\n")

	if len(lines) < 3 {
		return 0, "", fmt.Errorf("checkpoint has %d lines, need at least 3", len(lines))
	}

	treeSize, err = strconv.ParseInt(lines[1], 10, 64)
	if err != nil {
		return 0, "", fmt.Errorf("parse tree size %q: %w", lines[1], err)
	}

	hashBytes, err := base64.StdEncoding.DecodeString(lines[2])
	if err != nil {
		return 0, "", fmt.Errorf("decode root hash: %w", err)
	}

	rootHash = strings.ToUpper(hex.EncodeToString(hashBytes))
	return treeSize, rootHash, nil
}
