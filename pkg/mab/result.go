// Copyright 2015 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package mab

import (
	"github.com/google/syzkaller/pkg/hash"
)

type ExecResult struct {
	Cov       int     // Coverage gained
	TimeExec  float64 // Executing time (s)
	TimeTotal float64 // Total time (s)
	Pidx      int     // If mutation, the idx of the seed program
}

type TriageResult struct {
	CorpusCov        int
	VerifyTime       float64
	MinimizeCov      int
	MinimizeTime     float64
	MinimizeTimeSave float64
	Source           int // 0: Gen, 1: Mut, 2: Tri
	SourceExecTime   float64
	SourceSig        hash.Sig
	Pidx             int     // Index of the program in the corpus
	Success          bool    // Whether triage produces a seed
	TimeTotal        float64 // Total time spent
}
