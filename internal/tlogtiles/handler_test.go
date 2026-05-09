// Copyright (C) 2026 DigiCert, Inc.
//
// Licensed under the dual-license model:
//   1. GNU Affero General Public License v3.0 (AGPL v3) — see LICENSE.txt
//   2. DigiCert Commercial License — see LICENSE_COMMERCIAL.txt
//
// For commercial licensing, contact sales@digicert.com.

package tlogtiles

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestDecodeTileIndex(t *testing.T) {
	tests := []struct {
		path string
		want int64
		err  bool
	}{
		{"000", 0, false},
		{"001", 1, false},
		{"x001/234", 1234, false},
		{"x012/x345/678", 12345678, false},
		{"0", 0, false},
		{"x001/000", 1000, false},
	}

	for _, tt := range tests {
		got, err := decodeTileIndex(tt.path)
		if tt.err {
			if err == nil {
				t.Errorf("decodeTileIndex(%q) = %d, want error", tt.path, got)
			}
			continue
		}
		if err != nil {
			t.Errorf("decodeTileIndex(%q) error: %v", tt.path, err)
			continue
		}
		if got != tt.want {
			t.Errorf("decodeTileIndex(%q) = %d, want %d", tt.path, got, tt.want)
		}
	}
}

func TestParseRevokeRequestQuery(t *testing.T) {
	req, err := http.NewRequest(http.MethodPost, "/revocation?id=42&reason=1", nil)
	if err != nil {
		t.Fatal(err)
	}
	idx, reason, err := parseRevokeRequest(req)
	if err != nil {
		t.Fatalf("parseRevokeRequest: %v", err)
	}
	if idx != 42 {
		t.Fatalf("idx = %d, want 42", idx)
	}
	if reason != 1 {
		t.Fatalf("reason = %d, want 1", reason)
	}
}

func TestParseRevokeRequestJSON(t *testing.T) {
	req, err := http.NewRequest(http.MethodPost, "/revocation", strings.NewReader(`{"index":7,"reason":3}`))
	if err != nil {
		t.Fatal(err)
	}
	idx, reason, err := parseRevokeRequest(req)
	if err != nil {
		t.Fatalf("parseRevokeRequest: %v", err)
	}
	if idx != 7 {
		t.Fatalf("idx = %d, want 7", idx)
	}
	if reason != 3 {
		t.Fatalf("reason = %d, want 3", reason)
	}
}

func TestParseRevokeRequestRejectsMissingID(t *testing.T) {
	req, err := http.NewRequest(http.MethodPost, "/revocation", nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := parseRevokeRequest(req); err == nil {
		t.Fatal("parseRevokeRequest succeeded, want error")
	}
}

func TestParseRevokeRequestRejectsNegativeID(t *testing.T) {
	req, err := http.NewRequest(http.MethodPost, "/revocation?id=-1", nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := parseRevokeRequest(req); err == nil {
		t.Fatal("parseRevokeRequest succeeded, want error")
	}
}

func TestAuthorized(t *testing.T) {
	h := &Handler{adminToken: "secret"}
	req, err := http.NewRequest(http.MethodPost, "/revocation", nil)
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Authorization", "Bearer secret")
	if !h.authorized(req) {
		t.Fatal("authorized returned false, want true")
	}

	req.Header.Set("Authorization", "Bearer wrong")
	if h.authorized(req) {
		t.Fatal("authorized returned true for wrong token")
	}
}

func TestHandleRevokeDisabledWithoutToken(t *testing.T) {
	h := &Handler{}
	req := httptest.NewRequest(http.MethodPost, "/revocation?id=1", nil)
	rec := httptest.NewRecorder()

	h.handleRevoke(rec, req)

	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusServiceUnavailable)
	}
}

func TestHandleRevokeRejectsMissingBearerToken(t *testing.T) {
	h := &Handler{adminToken: "secret"}
	req := httptest.NewRequest(http.MethodPost, "/revocation?id=1", nil)
	rec := httptest.NewRecorder()

	h.handleRevoke(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusUnauthorized)
	}
}
