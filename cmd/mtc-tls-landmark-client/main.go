// Copyright (C) 2026 DigiCert, Inc.
//
// Licensed under the dual-license model:
//   1. GNU Affero General Public License v3.0 (AGPL v3) — see LICENSE.txt
//   2. DigiCert Commercial License — see LICENSE_COMMERCIAL.txt
//
// For commercial licensing, contact sales@digicert.com.

// Command mtc-tls-landmark-client demonstrates a TLS client with a background
// landmark trust cache and ALPN-based landmark support advertisement.
package main

import (
	"context"
	"crypto/tls"
	"flag"
	"fmt"
	"net"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/briantrzupek/ca-extension-merkle/internal/mtccert"
	"github.com/briantrzupek/ca-extension-merkle/internal/tlslandmark"
)

var (
	serverURL          = flag.String("url", "https://localhost:4443", "TLS server URL")
	bridgeURL          = flag.String("bridge-url", "http://localhost:8080", "mtc-bridge URL")
	insecure           = flag.Bool("insecure", false, "skip normal X.509 certificate verification")
	refreshInterval    = flag.Duration("refresh", 30*time.Minute, "landmark trust refresh interval")
	cachePath          = flag.String("cache", "", "optional JSON trust cache path")
	advertiseLandmarks = flag.Bool("advertise-landmarks", true, "advertise trusted landmark ranges via ALPN")
	verbose            = flag.Bool("verbose", false, "show additional debug output")
)

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
	serverName := u.Hostname()
	if serverName == "" {
		if h, _, splitErr := net.SplitHostPort(host); splitErr == nil {
			serverName = h
		}
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	trustCache := tlslandmark.NewCache(*bridgeURL, *cachePath)
	refreshCtx, refreshCancel := context.WithTimeout(ctx, 10*time.Second)
	err = trustCache.Refresh(refreshCtx)
	refreshCancel()
	if err != nil {
		if *cachePath == "" {
			fmt.Fprintf(os.Stderr, "error: failed to refresh landmark trust from bridge: %v\n", err)
			os.Exit(1)
		}
		if loadErr := trustCache.Load(*cachePath); loadErr != nil {
			fmt.Fprintf(os.Stderr, "error: bridge refresh failed (%v) and cache load failed: %v\n", err, loadErr)
			os.Exit(1)
		}
		fmt.Printf("[WARN] using cached trust material from %s after bridge refresh failed: %v\n", *cachePath, err)
	}
	trustCache.StartRefreshLoop(ctx, *refreshInterval)

	cosignerCount, subtreeCount := trustCache.Counts()
	tokens := []string(nil)
	if *advertiseLandmarks {
		tokens = trustCache.LandmarkTokens()
	}
	nextProtos := append([]string(nil), tokens...)
	nextProtos = append(nextProtos, tlslandmark.HTTPALPN)

	fmt.Println("MTC Landmark-Aware TLS Client")
	fmt.Println("=============================")
	fmt.Printf("Server:             %s\n", host)
	fmt.Printf("Bridge:             %s\n", *bridgeURL)
	fmt.Printf("Trusted cosigners:  %d\n", cosignerCount)
	fmt.Printf("Trusted subtrees:   %d\n", subtreeCount)
	fmt.Printf("Advertised ranges:  %d\n", len(tokens))
	if *verbose && len(tokens) > 0 {
		for i, token := range tokens {
			fmt.Printf("  alpn[%d]: %s\n", i, token)
		}
	}
	fmt.Println()

	tlsConfig := &tls.Config{
		InsecureSkipVerify: *insecure,
		MinVersion:         tls.VersionTLS13,
		NextProtos:         nextProtos,
		ServerName:         serverName,
	}
	conn, err := tls.Dial("tcp", host, tlsConfig)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: TLS connection failed: %v\n", err)
		os.Exit(1)
	}
	state := conn.ConnectionState()
	_ = conn.Close()

	if len(state.PeerCertificates) == 0 {
		fmt.Fprintf(os.Stderr, "error: no peer certificates received\n")
		os.Exit(1)
	}
	leaf := state.PeerCertificates[0]
	if !mtccert.IsMTCCertificate(leaf.Raw) {
		fmt.Fprintf(os.Stderr, "error: peer certificate is not MTC-spec format\n")
		os.Exit(1)
	}

	parsed, err := mtccert.ParseMTCCertificate(leaf.Raw)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: failed to parse MTC certificate: %v\n", err)
		os.Exit(1)
	}
	if parsed.Proof == nil {
		fmt.Fprintf(os.Stderr, "error: MTC certificate has no proof\n")
		os.Exit(1)
	}

	mode := "signatureless"
	if len(parsed.Proof.Signatures) > 0 {
		mode = "signed"
	}

	fmt.Printf("Received certificate:\n")
	fmt.Printf("  Serial/Index: %d\n", parsed.SerialNumber)
	fmt.Printf("  Subtree:      [%d, %d)\n", parsed.Proof.Start, parsed.Proof.End)
	fmt.Printf("  Proof Depth:  %d\n", len(parsed.Proof.InclusionProof))
	fmt.Printf("  Signatures:   %d\n", len(parsed.Proof.Signatures))
	fmt.Printf("  Mode:         %s\n", mode)
	if state.NegotiatedProtocol != "" {
		fmt.Printf("  ALPN:         %s\n", state.NegotiatedProtocol)
	}
	fmt.Println()

	result, err := mtccert.VerifyMTCCert(leaf.Raw, trustCache.VerifyOptions())
	if err != nil {
		fmt.Fprintf(os.Stderr, "Verification:\n  [FAIL] %v\n\nResult: VERIFICATION FAILED\n", err)
		os.Exit(1)
	}

	fmt.Println("Verification:")
	fmt.Printf("  [PASS] MTC certificate received via TLS (serial=%d)\n", parsed.SerialNumber)
	fmt.Printf("  [PASS] MTCProof present in signatureValue (subtree [%d, %d), %d hashes)\n",
		parsed.Proof.Start, parsed.Proof.End, len(parsed.Proof.InclusionProof))
	if result.ProofValid {
		fmt.Printf("  [PASS] MTC proof verified (leaf %d in subtree [%d, %d))\n",
			result.LeafIndex, result.SubtreeStart, result.SubtreeEnd)
	} else {
		fmt.Println("  [FAIL] MTC proof verified — no trusted cosigner signature or landmark subtree verified")
		fmt.Println()
		fmt.Println("Result: VERIFICATION FAILED")
		os.Exit(1)
	}
	if mode == "signed" {
		if result.SignaturesVerified == 0 {
			fmt.Println("  [FAIL] Trusted cosigner signature verified — 0 verified")
			fmt.Println()
			fmt.Println("Result: VERIFICATION FAILED")
			os.Exit(1)
		}
		fmt.Printf("  [PASS] Verification mode: standalone signed (%d trusted cosigner signature(s))\n", result.SignaturesVerified)
	} else {
		fmt.Println("  [PASS] Verification mode: signatureless landmark")
	}
	fmt.Println()
	fmt.Println("Result: MTC-VERIFIED")
}
