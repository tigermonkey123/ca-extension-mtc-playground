// Copyright (C) 2026 DigiCert, Inc.
//
// Licensed under the dual-license model:
//   1. GNU Affero General Public License v3.0 (AGPL v3) — see LICENSE.txt
//   2. DigiCert Commercial License — see LICENSE_COMMERCIAL.txt
//
// For commercial licensing, contact sales@digicert.com.

// Package tlslandmark contains helper code for the landmark-aware TLS demo.
package tlslandmark

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"net/http"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/briantrzupek/ca-extension-merkle/internal/merkle"
	"github.com/briantrzupek/ca-extension-merkle/internal/mtccert"
)

const (
	TokenPrefix = "mtc-lm-v1:"
	HTTPALPN    = "http/1.1"
)

type Interval struct {
	Start int64 `json:"start"`
	End   int64 `json:"end"`
}

func EncodeToken(start, end int64) (string, error) {
	if start < 0 || end <= start {
		return "", fmt.Errorf("invalid landmark interval [%d,%d)", start, end)
	}
	return fmt.Sprintf("%s%d-%d", TokenPrefix, start, end), nil
}

func DecodeToken(token string) (Interval, bool) {
	if !strings.HasPrefix(token, TokenPrefix) {
		return Interval{}, false
	}
	body := strings.TrimPrefix(token, TokenPrefix)
	parts := strings.SplitN(body, "-", 2)
	if len(parts) != 2 {
		return Interval{}, false
	}
	start, err := strconv.ParseInt(parts[0], 10, 64)
	if err != nil {
		return Interval{}, false
	}
	end, err := strconv.ParseInt(parts[1], 10, 64)
	if err != nil {
		return Interval{}, false
	}
	if start < 0 || end <= start {
		return Interval{}, false
	}
	return Interval{Start: start, End: end}, true
}

func DecodeTokens(tokens []string) []Interval {
	intervals := make([]Interval, 0, len(tokens))
	for _, token := range tokens {
		iv, ok := DecodeToken(token)
		if ok {
			intervals = append(intervals, iv)
		}
	}
	return intervals
}

func TokensForSubtrees(subtrees []mtccert.TrustedSubtree) []string {
	tokens := make([]string, 0, len(subtrees))
	for _, st := range subtrees {
		token, err := EncodeToken(st.Start, st.End)
		if err == nil {
			tokens = append(tokens, token)
		}
	}
	return tokens
}

func HasExactInterval(intervals []Interval, start, end uint64) bool {
	for _, iv := range intervals {
		if iv.Start == int64(start) && iv.End == int64(end) {
			return true
		}
	}
	return false
}

func ClientSupportsProofRange(tokens []string, proofStart, proofEnd uint64, serial int64) bool {
	if serial < int64(proofStart) || serial >= int64(proofEnd) {
		return false
	}
	return HasExactInterval(DecodeTokens(tokens), proofStart, proofEnd)
}

type CosignerTrust struct {
	LogID        string
	CosignerKeys map[string]mtccert.CosignerKey
}

type Cache struct {
	mu              sync.RWMutex
	BridgeURL       string
	CachePath       string
	LogID           string
	CosignerKeys    map[string]mtccert.CosignerKey
	TrustedSubtrees []mtccert.TrustedSubtree
	UpdatedAt       time.Time
	LastError       error
}

func NewCache(bridgeURL, cachePath string) *Cache {
	return &Cache{BridgeURL: strings.TrimRight(bridgeURL, "/"), CachePath: cachePath}
}

func (c *Cache) Refresh(ctx context.Context) error {
	trust, err := FetchCosignerTrust(ctx, c.BridgeURL)
	if err != nil {
		c.setError(err)
		return err
	}
	subtrees, err := FetchTrustedSubtrees(ctx, c.BridgeURL)
	if err != nil {
		c.setError(err)
		return err
	}

	c.mu.Lock()
	c.LogID = trust.LogID
	c.CosignerKeys = trust.CosignerKeys
	c.TrustedSubtrees = subtrees
	c.UpdatedAt = time.Now()
	c.LastError = nil
	c.mu.Unlock()

	if c.CachePath != "" {
		if err := c.Save(c.CachePath); err != nil {
			c.setError(err)
			return err
		}
	}
	return nil
}

func (c *Cache) StartRefreshLoop(ctx context.Context, interval time.Duration) {
	if interval <= 0 {
		return
	}
	ticker := time.NewTicker(interval)
	go func() {
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				_ = c.Refresh(ctx)
			}
		}
	}()
}

func (c *Cache) VerifyOptions() mtccert.VerifyOptions {
	c.mu.RLock()
	defer c.mu.RUnlock()
	keys := make(map[string]mtccert.CosignerKey, len(c.CosignerKeys))
	for id, key := range c.CosignerKeys {
		keys[id] = key
	}
	subtrees := make([]mtccert.TrustedSubtree, len(c.TrustedSubtrees))
	copy(subtrees, c.TrustedSubtrees)
	return mtccert.VerifyOptions{
		LogID:           []byte(c.LogID),
		CosignerKeys:    keys,
		TrustedSubtrees: subtrees,
	}
}

func (c *Cache) LandmarkTokens() []string {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return TokensForSubtrees(c.TrustedSubtrees)
}

func (c *Cache) Counts() (cosigners, subtrees int) {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return len(c.CosignerKeys), len(c.TrustedSubtrees)
}

func (c *Cache) setError(err error) {
	c.mu.Lock()
	c.LastError = err
	c.mu.Unlock()
}

func FetchCosignerTrust(ctx context.Context, bridgeBase string) (*CosignerTrust, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, strings.TrimRight(bridgeBase, "/")+"/cosigners", nil)
	if err != nil {
		return nil, err
	}
	resp, err := http.DefaultClient.Do(req)
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

	keys := make(map[string]mtccert.CosignerKey, len(body.Cosigners))
	for _, cosigner := range body.Cosigners {
		pub, err := hex.DecodeString(cosigner.PublicKey)
		if err != nil {
			return nil, fmt.Errorf("decode public key for %q: %w", cosigner.CosignerID, err)
		}
		keys[cosigner.CosignerID] = mtccert.CosignerKey{
			Algorithm: cosigner.Algorithm,
			PublicKey: pub,
		}
	}
	return &CosignerTrust{LogID: body.LogID, CosignerKeys: keys}, nil
}

func FetchTrustedSubtrees(ctx context.Context, bridgeBase string) ([]mtccert.TrustedSubtree, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, strings.TrimRight(bridgeBase, "/")+"/trusted-subtrees", nil)
	if err != nil {
		return nil, err
	}
	resp, err := http.DefaultClient.Do(req)
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

type cacheFile struct {
	LogID           string              `json:"log_id"`
	CosignerKeys    map[string]cacheKey `json:"cosigner_keys"`
	TrustedSubtrees []cacheSubtree      `json:"trusted_subtrees"`
	UpdatedAt       time.Time           `json:"updated_at"`
}

type cacheKey struct {
	Algorithm string `json:"algorithm"`
	PublicKey string `json:"public_key"`
}

type cacheSubtree struct {
	Start    int64  `json:"start"`
	End      int64  `json:"end"`
	RootHash string `json:"root_hash"`
}

func (c *Cache) Save(path string) error {
	c.mu.RLock()
	defer c.mu.RUnlock()

	file := cacheFile{
		LogID:           c.LogID,
		CosignerKeys:    make(map[string]cacheKey, len(c.CosignerKeys)),
		TrustedSubtrees: make([]cacheSubtree, 0, len(c.TrustedSubtrees)),
		UpdatedAt:       c.UpdatedAt,
	}
	for id, key := range c.CosignerKeys {
		file.CosignerKeys[id] = cacheKey{
			Algorithm: key.Algorithm,
			PublicKey: hex.EncodeToString(key.PublicKey),
		}
	}
	for _, st := range c.TrustedSubtrees {
		file.TrustedSubtrees = append(file.TrustedSubtrees, cacheSubtree{
			Start:    st.Start,
			End:      st.End,
			RootHash: hex.EncodeToString(st.Root[:]),
		})
	}

	data, err := json.MarshalIndent(file, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, data, 0o600)
}

func (c *Cache) Load(path string) error {
	data, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	var file cacheFile
	if err := json.Unmarshal(data, &file); err != nil {
		return err
	}

	keys := make(map[string]mtccert.CosignerKey, len(file.CosignerKeys))
	for id, key := range file.CosignerKeys {
		pub, err := hex.DecodeString(key.PublicKey)
		if err != nil {
			return fmt.Errorf("decode cached cosigner %q: %w", id, err)
		}
		keys[id] = mtccert.CosignerKey{Algorithm: key.Algorithm, PublicKey: pub}
	}

	subtrees := make([]mtccert.TrustedSubtree, 0, len(file.TrustedSubtrees))
	for _, st := range file.TrustedSubtrees {
		rootBytes, err := hex.DecodeString(st.RootHash)
		if err != nil {
			return fmt.Errorf("decode cached trusted subtree [%d,%d): %w", st.Start, st.End, err)
		}
		if len(rootBytes) != merkle.HashSize {
			return fmt.Errorf("cached trusted subtree [%d,%d) root has %d bytes", st.Start, st.End, len(rootBytes))
		}
		var root merkle.Hash
		copy(root[:], rootBytes)
		subtrees = append(subtrees, mtccert.TrustedSubtree{Start: st.Start, End: st.End, Root: root})
	}

	c.mu.Lock()
	c.LogID = file.LogID
	c.CosignerKeys = keys
	c.TrustedSubtrees = subtrees
	c.UpdatedAt = file.UpdatedAt
	c.LastError = nil
	c.mu.Unlock()
	return nil
}

type MTCCertBundle struct {
	Certificate tls.Certificate
	Parsed      *mtccert.ParsedMTCCert
	Mode        string
}

func LoadMTCCertBundle(certFile, keyFile string) (*MTCCertBundle, error) {
	certPEM, err := os.ReadFile(certFile)
	if err != nil {
		return nil, fmt.Errorf("read cert: %w", err)
	}
	certs := make([][]byte, 0, 2)
	rest := certPEM
	for {
		block, next := pem.Decode(rest)
		if block == nil {
			break
		}
		if block.Type == "CERTIFICATE" {
			certs = append(certs, block.Bytes)
		}
		rest = next
	}
	if len(certs) == 0 {
		return nil, fmt.Errorf("no CERTIFICATE PEM block in %s", certFile)
	}
	if !mtccert.IsMTCCertificate(certs[0]) {
		return nil, fmt.Errorf("%s is not an MTC certificate", certFile)
	}
	parsed, err := mtccert.ParseMTCCertificate(certs[0])
	if err != nil {
		return nil, fmt.Errorf("parse MTC certificate: %w", err)
	}
	if parsed.Proof == nil {
		return nil, fmt.Errorf("MTC certificate has no proof")
	}

	keyPEM, err := os.ReadFile(keyFile)
	if err != nil {
		return nil, fmt.Errorf("read key: %w", err)
	}
	keyBlock, _ := pem.Decode(keyPEM)
	if keyBlock == nil {
		return nil, fmt.Errorf("no private key PEM block in %s", keyFile)
	}
	privKey, err := ParsePrivateKey(keyBlock.Bytes)
	if err != nil {
		return nil, err
	}

	mode := "signatureless"
	if len(parsed.Proof.Signatures) > 0 {
		mode = "signed"
	}
	return &MTCCertBundle{
		Certificate: tls.Certificate{Certificate: certs, PrivateKey: privKey},
		Parsed:      parsed,
		Mode:        mode,
	}, nil
}

func ParsePrivateKey(der []byte) (interface{}, error) {
	if key, err := x509.ParsePKCS8PrivateKey(der); err == nil {
		return key, nil
	}
	if key, err := x509.ParseECPrivateKey(der); err == nil {
		return key, nil
	}
	if key, err := x509.ParsePKCS1PrivateKey(der); err == nil {
		return key, nil
	}
	return nil, fmt.Errorf("unsupported private key type")
}
