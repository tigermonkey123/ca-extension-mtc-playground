// Copyright (C) 2026 DigiCert, Inc.
//
// Licensed under the dual-license model:
//   1. GNU Affero General Public License v3.0 (AGPL v3) — see LICENSE.txt
//   2. DigiCert Commercial License — see LICENSE_COMMERCIAL.txt
//
// For commercial licensing, contact sales@digicert.com.

package mtccert

import (
	"crypto/ed25519"
	"encoding/hex"
	"fmt"
	"strings"

	"github.com/briantrzupek/ca-extension-merkle/internal/merkle"
	"github.com/briantrzupek/ca-extension-merkle/internal/mtcformat"
	"github.com/cloudflare/circl/sign/mldsa/mldsa44"
	"github.com/cloudflare/circl/sign/mldsa/mldsa65"
	"github.com/cloudflare/circl/sign/mldsa/mldsa87"
)

// CosignerKey holds a cosigner's public key for signature verification.
type CosignerKey struct {
	Algorithm string // "ed25519", "mldsa44", "mldsa65", "mldsa87"
	PublicKey []byte
}

// VerifyOptions configures how MTC certificate verification works.
type VerifyOptions struct {
	// CosignerKeys maps cosigner TrustAnchorID (ASCII or hex-encoded) to
	// public key for signed standalone mode verification.
	CosignerKeys map[string]CosignerKey

	// Landmarks maps tree_size → root hash for signatureless mode verification.
	Landmarks map[int64]merkle.Hash

	// LogID is the log identifier for subtree signature verification.
	LogID []byte
}

// VerifyResult contains the result of MTC certificate verification.
type VerifyResult struct {
	LeafIndex          int64  `json:"leaf_index"`
	SubtreeStart       uint64 `json:"subtree_start"`
	SubtreeEnd         uint64 `json:"subtree_end"`
	ProofValid         bool   `json:"proof_valid"`
	SignaturesVerified int    `json:"signatures_verified"`
	Mode               string `json:"mode"` // "signed" or "signatureless"
}

// VerifyMTCCert verifies a spec-compliant MTC certificate:
// 1. Parse cert → extract MTCProof from signatureValue
// 2. Reconstruct TBSCertificateLogEntry (SPKI → SHA-256 hash)
// 3. Wrap in MerkleTreeCertEntry
// 4. Compute leaf hash
// 5. Verify inclusion proof against subtree [start, end)
// 6. Verify cosigner signatures (signed mode) OR verify against landmark (signatureless mode)
func VerifyMTCCert(certDER []byte, opts VerifyOptions) (*VerifyResult, error) {
	// Step 1: Parse the MTC certificate.
	parsed, err := ParseMTCCertificate(certDER)
	if err != nil {
		return nil, fmt.Errorf("verify: parse cert: %w", err)
	}

	// Step 2: Reconstruct TBSCertificateLogEntry.
	logEntryDER, err := ReconstructLogEntry(
		parsed.RawIssuer, parsed.RawSubject,
		parsed.NotBefore, parsed.NotAfter,
		parsed.SubjectPubKeyInfo, parsed.Extensions,
	)
	if err != nil {
		return nil, fmt.Errorf("verify: reconstruct log entry: %w", err)
	}

	// Step 3: Strip outer SEQUENCE envelope (contents octets per §5.3) and wrap in MerkleTreeCertEntry.
	contentsOctets, err := mtcformat.DERContentsOctets(logEntryDER)
	if err != nil {
		return nil, fmt.Errorf("verify: strip DER envelope: %w", err)
	}
	mtcEntry := &mtcformat.MerkleTreeCertEntry{
		Type: mtcformat.EntryTypeTBSCert,
		Data: contentsOctets,
	}
	entryBytes, err := mtcformat.MarshalEntry(mtcEntry)
	if err != nil {
		return nil, fmt.Errorf("verify: marshal entry: %w", err)
	}

	// Step 4: Compute leaf hash.
	leafHash := merkle.LeafHash(entryBytes)

	// Step 5: Verify inclusion proof.
	// In MTC, serial = leaf index within the tree.
	// The subtree covers [start, end), so relative index = serial - start.
	proof := parsed.Proof
	proofHashes := make([]merkle.Hash, len(proof.InclusionProof))
	for i, h := range proof.InclusionProof {
		copy(proofHashes[i][:], h)
	}

	subtreeSize := int64(proof.End) - int64(proof.Start)
	relativeIndex := parsed.SerialNumber - int64(proof.Start)

	// Compute the subtree root from the inclusion proof.
	subtreeRoot := merkle.RootFromInclusionProof(relativeIndex, subtreeSize, leafHash, proofHashes)

	// The proof is structurally valid if we can compute a root.
	// Full verification requires checking the root against cosigner signatures
	// (signed mode) or landmarks (signatureless mode).
	proofValid := subtreeSize > 0 && relativeIndex >= 0 && relativeIndex < subtreeSize
	_ = subtreeRoot // used by landmark/signature verification below

	result := &VerifyResult{
		LeafIndex:    parsed.SerialNumber,
		SubtreeStart: proof.Start,
		SubtreeEnd:   proof.End,
		ProofValid:   proofValid,
	}

	// Step 6: Determine mode and verify accordingly.
	if len(proof.Signatures) > 0 {
		result.Mode = "signed"
		if proofValid {
			for _, sig := range proof.Signatures {
				key, ok := lookupCosignerKey(opts.CosignerKeys, sig.CosignerID)
				if !ok {
					continue
				}
				if verifyMTCSignature(key, opts.LogID, proof.Start, proof.End, subtreeRoot, sig) {
					result.SignaturesVerified++
				}
			}
			result.ProofValid = result.SignaturesVerified > 0
		}
	} else {
		result.Mode = "signatureless"
		// In signatureless mode, verify the subtree root against a known landmark.
		if opts.Landmarks != nil {
			if expectedRoot, ok := opts.Landmarks[int64(proof.End)]; ok {
				result.ProofValid = proofValid && subtreeRoot == expectedRoot
			}
		}
	}

	return result, nil
}

func lookupCosignerKey(keys map[string]CosignerKey, id []byte) (CosignerKey, bool) {
	if len(keys) == 0 {
		return CosignerKey{}, false
	}
	if key, ok := keys[string(id)]; ok {
		return key, true
	}
	key, ok := keys[hex.EncodeToString(id)]
	return key, ok
}

func verifyMTCSignature(key CosignerKey, logID []byte, start, end uint64, subtreeRoot merkle.Hash, sig mtcformat.MTCSignature) bool {
	input, err := mtcformat.BuildSubtreeSignatureInput(sig.CosignerID, logID, start, end, subtreeRoot[:])
	if err != nil {
		return false
	}
	switch normalizeAlgorithm(key.Algorithm) {
	case "ed25519":
		if len(key.PublicKey) != ed25519.PublicKeySize {
			return false
		}
		return ed25519.Verify(ed25519.PublicKey(key.PublicKey), input, sig.Signature)
	case "mldsa44":
		pk := new(mldsa44.PublicKey)
		if err := pk.UnmarshalBinary(key.PublicKey); err != nil {
			return false
		}
		return mldsa44.Verify(pk, input, nil, sig.Signature)
	case "mldsa65":
		pk := new(mldsa65.PublicKey)
		if err := pk.UnmarshalBinary(key.PublicKey); err != nil {
			return false
		}
		return mldsa65.Verify(pk, input, nil, sig.Signature)
	case "mldsa87":
		pk := new(mldsa87.PublicKey)
		if err := pk.UnmarshalBinary(key.PublicKey); err != nil {
			return false
		}
		return mldsa87.Verify(pk, input, nil, sig.Signature)
	default:
		return false
	}
}

func normalizeAlgorithm(alg string) string {
	switch strings.ToLower(strings.TrimSpace(alg)) {
	case "ed25519":
		return "ed25519"
	case "mldsa44", "ml-dsa-44":
		return "mldsa44"
	case "mldsa65", "ml-dsa-65":
		return "mldsa65"
	case "mldsa87", "ml-dsa-87":
		return "mldsa87"
	default:
		return ""
	}
}
