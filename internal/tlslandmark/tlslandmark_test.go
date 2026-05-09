// Copyright (C) 2026 DigiCert, Inc.
//
// Licensed under the dual-license model:
//   1. GNU Affero General Public License v3.0 (AGPL v3) — see LICENSE.txt
//   2. DigiCert Commercial License — see LICENSE_COMMERCIAL.txt
//
// For commercial licensing, contact sales@digicert.com.

package tlslandmark

import (
	"context"
	"crypto/ed25519"
	"encoding/hex"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/briantrzupek/ca-extension-merkle/internal/merkle"
)

func TestEncodeDecodeToken(t *testing.T) {
	token, err := EncodeToken(12, 34)
	if err != nil {
		t.Fatalf("EncodeToken: %v", err)
	}
	if token != "mtc-lm-v1:12-34" {
		t.Fatalf("token = %q, want mtc-lm-v1:12-34", token)
	}
	iv, ok := DecodeToken(token)
	if !ok {
		t.Fatal("DecodeToken returned ok=false")
	}
	if iv.Start != 12 || iv.End != 34 {
		t.Fatalf("interval = [%d,%d), want [12,34)", iv.Start, iv.End)
	}
}

func TestDecodeTokensIgnoresInvalid(t *testing.T) {
	tokens := []string{
		"http/1.1",
		"mtc-lm-v1:0-10",
		"mtc-lm-v1:10-10",
		"mtc-lm-v1:-1-10",
		"mtc-lm-v1:nope",
	}
	intervals := DecodeTokens(tokens)
	if len(intervals) != 1 {
		t.Fatalf("len(intervals) = %d, want 1", len(intervals))
	}
	if intervals[0] != (Interval{Start: 0, End: 10}) {
		t.Fatalf("interval = %+v, want [0,10)", intervals[0])
	}
}

func TestClientSupportsProofRangeRequiresExactMatch(t *testing.T) {
	tokens := []string{
		"mtc-lm-v1:0-20",
		"mtc-lm-v1:20-21",
	}
	if !ClientSupportsProofRange(tokens, 20, 21, 20) {
		t.Fatal("exact interval support returned false")
	}
	if ClientSupportsProofRange(tokens, 0, 21, 20) {
		t.Fatal("containing but non-exact interval returned true")
	}
	if ClientSupportsProofRange(tokens, 20, 21, 21) {
		t.Fatal("serial outside interval returned true")
	}
}

func TestFetchTrustMapsToVerifyOptions(t *testing.T) {
	pub := make([]byte, ed25519.PublicKeySize)
	for i := range pub {
		pub[i] = byte(i)
	}
	root := merkle.LeafHash([]byte("trusted subtree"))

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/cosigners":
			fmt.Fprintf(w, `{"log_id":"test-log","cosigners":[{"cosigner_id":"test","algorithm":"ed25519","public_key":%q}]}`, hex.EncodeToString(pub))
		case "/trusted-subtrees":
			fmt.Fprintf(w, `[{"landmark_number":1,"start":3,"end":7,"root_hash":%q}]`, hex.EncodeToString(root[:]))
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()

	cache := NewCache(server.URL, "")
	if err := cache.Refresh(context.Background()); err != nil {
		t.Fatalf("Refresh: %v", err)
	}
	opts := cache.VerifyOptions()
	if string(opts.LogID) != "test-log" {
		t.Fatalf("LogID = %q, want test-log", string(opts.LogID))
	}
	if len(opts.CosignerKeys) != 1 {
		t.Fatalf("len(CosignerKeys) = %d, want 1", len(opts.CosignerKeys))
	}
	if opts.CosignerKeys["test"].Algorithm != "ed25519" {
		t.Fatalf("algorithm = %q, want ed25519", opts.CosignerKeys["test"].Algorithm)
	}
	if len(opts.TrustedSubtrees) != 1 {
		t.Fatalf("len(TrustedSubtrees) = %d, want 1", len(opts.TrustedSubtrees))
	}
	st := opts.TrustedSubtrees[0]
	if st.Start != 3 || st.End != 7 || st.Root != root {
		t.Fatalf("trusted subtree = [%d,%d) %x, want [3,7) %x", st.Start, st.End, st.Root, root)
	}
}
