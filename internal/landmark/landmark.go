// Copyright (C) 2026 DigiCert, Inc.
//
// Licensed under the dual-license model:
//   1. GNU Affero General Public License v3.0 (AGPL v3) — see LICENSE.txt
//   2. DigiCert Commercial License — see LICENSE_COMMERCIAL.txt
//
// For commercial licensing, contact sales@digicert.com.

// Package landmark contains shared landmark allocation and trusted subtree
// helpers for MTC landmark-relative certificates.
package landmark

import (
	"context"
	"fmt"
	"log/slog"
	"time"

	"github.com/briantrzupek/ca-extension-merkle/internal/merkle"
	"github.com/briantrzupek/ca-extension-merkle/internal/store"
)

// Point is a landmark tree size with a stable ordinal number. Number 0 is the
// synthetic empty-tree landmark at tree size 0.
type Point struct {
	Number   int64
	TreeSize int64
}

// TrustedSubtree is the hash range clients trust for signatureless
// landmark-relative certificates.
type TrustedSubtree struct {
	LandmarkNumber int64
	Start          int64
	End            int64
	RootHash       merkle.Hash
}

// ActivePoints returns active landmarks in ascending landmark-number order.
// Stored landmarks are numbered by tree-size order starting at 1.
func ActivePoints(landmarks []*store.Landmark, maxActive int) []Point {
	points := make([]Point, 0, len(landmarks)+1)
	points = append(points, Point{Number: 0, TreeSize: 0})
	for i, lm := range landmarks {
		points = append(points, Point{Number: int64(i + 1), TreeSize: lm.TreeSize})
	}
	if maxActive <= 0 || len(points) <= maxActive {
		return points
	}
	return points[len(points)-maxActive:]
}

// AllPoints returns all landmarks including the synthetic empty-tree landmark.
func AllPoints(landmarks []*store.Landmark) []Point {
	return ActivePoints(landmarks, 0)
}

// FindContainingInterval finds the first landmark interval [previous, current)
// that contains leafIndex.
func FindContainingInterval(points []Point, leafIndex int64) (Point, Point, bool) {
	for i := 1; i < len(points); i++ {
		prev := points[i-1]
		current := points[i]
		if leafIndex >= prev.TreeSize && leafIndex < current.TreeSize {
			return prev, current, true
		}
	}
	return Point{}, Point{}, false
}

// TrustedSubtrees computes trusted subtree ranges between consecutive active
// landmarks.
func TrustedSubtrees(ctx context.Context, s *store.Store, maxActive int) ([]TrustedSubtree, error) {
	landmarks, err := s.ListLandmarks(ctx)
	if err != nil {
		return nil, err
	}
	points := AllPoints(landmarks)
	if maxActive > 0 && len(points) > maxActive {
		points = points[len(points)-maxActive:]
	}
	nodeAt := func(level int, idx int64) merkle.Hash {
		h, _ := s.GetTreeNode(ctx, level, idx)
		return h
	}
	result := make([]TrustedSubtree, 0, len(points))
	for i := 1; i < len(points); i++ {
		start := points[i-1].TreeSize
		end := points[i].TreeSize
		if end <= start {
			continue
		}
		result = append(result, TrustedSubtree{
			LandmarkNumber: points[i].Number,
			Start:          start,
			End:            end,
			RootHash:       merkle.SubtreeHashFromNodes(start, end, nodeAt),
		})
	}
	return result, nil
}

// Allocator periodically designates the latest checkpoint as a landmark when
// the tree has advanced beyond the latest existing landmark.
type Allocator struct {
	store    *store.Store
	interval time.Duration
	logger   *slog.Logger
}

// NewAllocator creates a landmark allocator.
func NewAllocator(s *store.Store, interval time.Duration, logger *slog.Logger) *Allocator {
	if interval <= 0 {
		interval = time.Hour
	}
	return &Allocator{store: s, interval: interval, logger: logger}
}

// Run starts allocation until ctx is cancelled. It performs an initial
// allocation attempt immediately.
func (a *Allocator) Run(ctx context.Context) {
	a.allocate(ctx)
	ticker := time.NewTicker(a.interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			a.allocate(ctx)
		}
	}
}

func (a *Allocator) allocate(ctx context.Context) {
	lm, err := DesignateLatest(ctx, a.store)
	if err != nil {
		a.logger.Warn("landmark allocation skipped", "error", err)
		return
	}
	if lm != nil {
		a.logger.Info("landmark allocated", "tree_size", lm.TreeSize, "checkpoint_id", lm.CheckpointID)
	}
}

// DesignateLatest stores the latest checkpoint as a landmark if it advances the
// current landmark frontier. It returns nil when no new landmark is needed.
func DesignateLatest(ctx context.Context, s *store.Store) (*store.Landmark, error) {
	cp, err := s.LatestCheckpoint(ctx)
	if err != nil {
		return nil, fmt.Errorf("latest checkpoint: %w", err)
	}
	if cp.TreeSize <= 0 {
		return nil, nil
	}
	landmarks, err := s.ListLandmarks(ctx)
	if err != nil {
		return nil, fmt.Errorf("list landmarks: %w", err)
	}
	if len(landmarks) > 0 && landmarks[len(landmarks)-1].TreeSize >= cp.TreeSize {
		return nil, nil
	}
	lm := &store.Landmark{
		TreeSize:     cp.TreeSize,
		RootHash:     cp.RootHash,
		CheckpointID: cp.ID,
	}
	if err := s.SaveLandmark(ctx, lm); err != nil {
		return nil, fmt.Errorf("save landmark: %w", err)
	}
	return lm, nil
}
