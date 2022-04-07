// Copyright 2021 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

// Package stats provides various statistical operations and algorithms.
package stats

import (
	"math"
	"sort"
)

// Sample represents a single sample - set of data points collected during an experiment.
type Sample struct {
	Xs     []float64
	Sorted bool
}

func (s *Sample) Percentile(p float64) float64 {
	s.Sort()
	// The code below is taken from golang.org/x/perf/internal/stats
	// Unfortunately, that package is internal and we cannot just import and use it.
	N := float64(len(s.Xs))
	n := 1/3.0 + p*(N+1/3.0) // R8
	kf, frac := math.Modf(n)
	k := int(kf)
	if k <= 0 {
		return s.Xs[0]
	} else if k >= len(s.Xs) {
		return s.Xs[len(s.Xs)-1]
	}
	return s.Xs[k-1] + frac*(s.Xs[k]-s.Xs[k-1])
}

func (s *Sample) Median() float64 {
	return s.Percentile(0.5)
}

// Remove outliers by the Tukey's fences method.
func (s *Sample) RemoveOutliers() *Sample {
	if len(s.Xs) < 4 {
		// If the data set is too small, we cannot reliably detect outliers anyway.
		return s.Copy()
	}
	s.Sort()
	Q1 := s.Percentile(0.25)
	Q3 := s.Percentile(0.75)
	minValue := Q1 - 1.5*(Q3-Q1)
	maxValue := Q3 + 1.5*(Q3-Q1)
	xs := []float64{}
	for _, value := range s.Xs {
		if value >= minValue && value <= maxValue {
			xs = append(xs, value)
		}
	}
	return &Sample{
		Xs:     xs,
		Sorted: s.Sorted,
	}
}

func (s *Sample) Copy() *Sample {
	return &Sample{
		Xs:     append([]float64{}, s.Xs...),
		Sorted: s.Sorted,
	}
}

func (s *Sample) Sort() {
	if !s.Sorted {
		sort.Slice(s.Xs, func(i, j int) bool { return s.Xs[i] < s.Xs[j] })
		s.Sorted = true
	}
}
