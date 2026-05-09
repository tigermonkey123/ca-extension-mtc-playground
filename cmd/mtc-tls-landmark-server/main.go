// Copyright (C) 2026 DigiCert, Inc.
//
// Licensed under the dual-license model:
//   1. GNU Affero General Public License v3.0 (AGPL v3) — see LICENSE.txt
//   2. DigiCert Commercial License — see LICENSE_COMMERCIAL.txt
//
// For commercial licensing, contact sales@digicert.com.

// Command mtc-tls-landmark-server demonstrates TLS certificate selection based
// on client-advertised landmark support.
package main

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/signal"
	"sync"
	"syscall"
	"time"

	"github.com/briantrzupek/ca-extension-merkle/internal/tlslandmark"
)

var (
	certFile         = flag.String("cert", "", "standalone signed MTC certificate PEM")
	landmarkCertFile = flag.String("landmark-cert", "", "optional signatureless landmark MTC certificate PEM; if missing, the server serves standalone until it appears")
	keyFile          = flag.String("key", "", "private key shared by both certificates")
	bridgeURL        = flag.String("bridge-url", "http://localhost:8080", "mtc-bridge base URL")
	listenAddr       = flag.String("addr", ":4443", "TLS listen address")
	landmarkRefresh  = flag.Duration("landmark-refresh", 30*time.Second, "landmark certificate file refresh interval (0 to disable)")
)

type serverState struct {
	mu           sync.RWMutex
	standalone   *tlslandmark.MTCCertBundle
	landmark     *tlslandmark.MTCCertBundle
	landmarkErr  string
	lastSelected string
	lastClient   []string
}

func (s *serverState) getCertificate(hello *tls.ClientHelloInfo) (*tls.Certificate, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	clientTokens := append([]string(nil), hello.SupportedProtos...)
	selected := "standalone"
	cert := s.standalone.Certificate
	if s.landmark != nil && s.landmark.Parsed.Proof != nil &&
		tlslandmark.ClientSupportsProofRange(
			clientTokens,
			s.landmark.Parsed.Proof.Start,
			s.landmark.Parsed.Proof.End,
			s.landmark.Parsed.SerialNumber,
		) {
		selected = "landmark"
		cert = s.landmark.Certificate
	}

	s.lastSelected = selected
	s.lastClient = clientTokens
	log.Printf("TLS certificate selected: mode=%s client_landmark_tokens=%d", selected, len(tlslandmark.DecodeTokens(clientTokens)))
	return &cert, nil
}

func main() {
	flag.Parse()

	if *certFile == "" || *keyFile == "" {
		fmt.Fprintf(os.Stderr, "usage: mtc-tls-landmark-server -cert standalone.crt -key key.pem [-landmark-cert landmark.crt] [-bridge-url url] [-addr :4443]\n")
		os.Exit(2)
	}

	standalone, err := tlslandmark.LoadMTCCertBundle(*certFile, *keyFile)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error loading standalone certificate: %v\n", err)
		os.Exit(1)
	}
	if standalone.Mode != "signed" {
		fmt.Fprintf(os.Stderr, "error: -cert must be a standalone signed MTC certificate; got %s\n", standalone.Mode)
		os.Exit(1)
	}

	state := &serverState{
		standalone:   standalone,
		lastSelected: "none",
	}
	if *landmarkCertFile != "" {
		if err := loadLandmarkCert(state, *landmarkCertFile, *keyFile); err != nil {
			state.landmarkErr = err.Error()
			log.Printf("landmark certificate not available yet: %v", err)
		}
	}

	fmt.Println("MTC Landmark-Aware TLS Server")
	fmt.Println("=============================")
	fmt.Printf("Serial/Index:       %d\n", standalone.Parsed.SerialNumber)
	fmt.Printf("Standalone subtree: [%d, %d), signatures=%d\n",
		standalone.Parsed.Proof.Start,
		standalone.Parsed.Proof.End,
		len(standalone.Parsed.Proof.Signatures),
	)
	printLandmarkStatus(state)
	fmt.Printf("Bridge:             %s\n", *bridgeURL)
	fmt.Printf("Listen:             %s\n", *listenAddr)
	fmt.Println()

	ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer cancel()

	if *landmarkCertFile != "" && *landmarkRefresh > 0 {
		go refreshLandmarkLoop(ctx, state, *landmarkCertFile, *keyFile, *landmarkRefresh)
	}

	mux := http.NewServeMux()
	mux.HandleFunc("GET /", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		state.mu.RLock()
		defer state.mu.RUnlock()
		fmt.Fprintf(w, `<!doctype html>
<html><head><meta charset="utf-8"><title>MTC Landmark TLS Demo</title></head>
<body style="font-family:sans-serif;max-width:720px;margin:40px auto;line-height:1.5">
<h1>MTC Landmark-Aware TLS Demo</h1>
<p><strong>Last selected certificate:</strong> %s</p>
<p><strong>Serial/index:</strong> %d</p>
<p><strong>Standalone subtree:</strong> [%d, %d)</p>
<p><strong>Landmark:</strong> %s</p>
<p>The server sends the landmark certificate only when the client advertises the exact landmark range via ALPN.</p>
</body></html>`,
			state.lastSelected,
			state.standalone.Parsed.SerialNumber,
			state.standalone.Parsed.Proof.Start,
			state.standalone.Parsed.Proof.End,
			landmarkHTML(state),
		)
	})
	mux.HandleFunc("GET /mtc-status", func(w http.ResponseWriter, r *http.Request) {
		state.mu.RLock()
		defer state.mu.RUnlock()
		status := map[string]interface{}{
			"serial":        state.standalone.Parsed.SerialNumber,
			"last_selected": state.lastSelected,
			"standalone": map[string]interface{}{
				"start":      state.standalone.Parsed.Proof.Start,
				"end":        state.standalone.Parsed.Proof.End,
				"signatures": len(state.standalone.Parsed.Proof.Signatures),
			},
			"client_alpn_tokens": state.lastClient,
		}
		if state.landmark != nil {
			status["landmark"] = map[string]interface{}{
				"available":  true,
				"start":      state.landmark.Parsed.Proof.Start,
				"end":        state.landmark.Parsed.Proof.End,
				"signatures": len(state.landmark.Parsed.Proof.Signatures),
			}
		} else {
			status["landmark"] = map[string]interface{}{
				"available": false,
				"error":     state.landmarkErr,
			}
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(status)
	})

	server := &http.Server{
		Addr: *listenAddr,
		TLSConfig: &tls.Config{
			GetCertificate: state.getCertificate,
			MinVersion:     tls.VersionTLS13,
			NextProtos:     []string{tlslandmark.HTTPALPN},
		},
		Handler:      mux,
		ReadTimeout:  10 * time.Second,
		WriteTimeout: 30 * time.Second,
		IdleTimeout:  120 * time.Second,
	}

	go func() {
		<-ctx.Done()
		shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer shutdownCancel()
		_ = server.Shutdown(shutdownCtx)
	}()

	fmt.Printf("Listening on https://localhost%s\n", *listenAddr)
	fmt.Printf("Status: https://localhost%s/mtc-status\n\n", *listenAddr)
	if err := server.ListenAndServeTLS("", ""); err != http.ErrServerClosed {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}
	fmt.Println("Shutdown complete.")
}

func loadLandmarkCert(state *serverState, certPath, keyPath string) error {
	landmark, err := tlslandmark.LoadMTCCertBundle(certPath, keyPath)
	if err != nil {
		return err
	}
	if state.standalone.Parsed.SerialNumber != landmark.Parsed.SerialNumber {
		return fmt.Errorf("certificate serial mismatch: standalone=%d landmark=%d",
			state.standalone.Parsed.SerialNumber, landmark.Parsed.SerialNumber)
	}
	if landmark.Mode != "signatureless" {
		return fmt.Errorf("-landmark-cert must be signatureless; got %s", landmark.Mode)
	}

	state.mu.Lock()
	state.landmark = landmark
	state.landmarkErr = ""
	state.mu.Unlock()
	return nil
}

func refreshLandmarkLoop(ctx context.Context, state *serverState, certPath, keyPath string, interval time.Duration) {
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	loaded := state.landmark != nil
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			err := loadLandmarkCert(state, certPath, keyPath)
			if err != nil {
				state.mu.Lock()
				state.landmarkErr = err.Error()
				state.mu.Unlock()
				continue
			}
			if !loaded {
				loaded = true
				log.Printf("landmark certificate loaded from %s", certPath)
			}
		}
	}
}

func printLandmarkStatus(state *serverState) {
	state.mu.RLock()
	defer state.mu.RUnlock()
	if state.landmark == nil {
		if state.landmarkErr != "" {
			fmt.Printf("Landmark subtree:   not available yet (%s)\n", state.landmarkErr)
		} else {
			fmt.Printf("Landmark subtree:   not configured\n")
		}
		return
	}
	fmt.Printf("Landmark subtree:   [%d, %d), signatures=%d\n",
		state.landmark.Parsed.Proof.Start,
		state.landmark.Parsed.Proof.End,
		len(state.landmark.Parsed.Proof.Signatures),
	)
}

func landmarkHTML(state *serverState) string {
	if state.landmark == nil {
		if state.landmarkErr != "" {
			return "not available yet: " + state.landmarkErr
		}
		return "not configured"
	}
	return fmt.Sprintf("[%d, %d)", state.landmark.Parsed.Proof.Start, state.landmark.Parsed.Proof.End)
}
