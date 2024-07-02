// Copyright 2024 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package fuzzer

import "github.com/google/syzkaller/pkg/stats"

type Stats struct {
	statCandidates          *stats.Val
	statNewInputs           *stats.Val
	statJobs                *stats.Val
	statJobsTriage          *stats.Val
	statJobsTriageCandidate *stats.Val
	statJobsSmash           *stats.Val
	statJobsFaultInjection  *stats.Val
	statJobsHints           *stats.Val
	statExecTime            *stats.Val
	statExecGenerate        *stats.Val
	statExecFuzz            *stats.Val
	statExecCandidate       *stats.Val
	statExecTriage          *stats.Val
	statExecMinimize        *stats.Val
	statExecSmash           *stats.Val
	statExecFaultInject     *stats.Val
	statExecHint            *stats.Val
	statExecSeed            *stats.Val
	statExecCollide         *stats.Val
}

func newStats() Stats {
	return Stats{
		statCandidates: stats.Create("candidates", "Number of candidate programs in triage queue",
			stats.Console, stats.Graph("corpus")),
		statNewInputs: stats.Create("new inputs", "Potential untriaged corpus candidates",
			stats.Graph("corpus")),
		statJobs:       stats.Create("fuzzer jobs", "Total running fuzzer jobs", stats.NoGraph),
		statJobsTriage: stats.Create("triage jobs", "Running triage jobs", stats.StackedGraph("jobs")),
		statJobsTriageCandidate: stats.Create("candidate triage jobs", "Running candidate triage jobs",
			stats.StackedGraph("jobs")),
		statJobsSmash:          stats.Create("smash jobs", "Running smash jobs", stats.StackedGraph("jobs")),
		statJobsFaultInjection: stats.Create("fault jobs", "Running fault injection jobs", stats.StackedGraph("jobs")),
		statJobsHints:          stats.Create("hints jobs", "Running hints jobs", stats.StackedGraph("jobs")),
		statExecTime:           stats.Create("prog exec time", "Test program execution time (ms)", stats.Distribution{}),
		statExecGenerate: stats.Create("exec gen", "Executions of generated programs", stats.Rate{},
			stats.StackedGraph("exec")),
		statExecFuzz: stats.Create("exec fuzz", "Executions of mutated programs",
			stats.Rate{}, stats.StackedGraph("exec")),
		statExecCandidate: stats.Create("exec candidate", "Executions of candidate programs",
			stats.Rate{}, stats.StackedGraph("exec")),
		statExecTriage: stats.Create("exec triage", "Executions of corpus triage programs",
			stats.Rate{}, stats.StackedGraph("exec")),
		statExecMinimize: stats.Create("exec minimize", "Executions of programs during minimization",
			stats.Rate{}, stats.StackedGraph("exec")),
		statExecSmash: stats.Create("exec smash", "Executions of smashed programs",
			stats.Rate{}, stats.StackedGraph("exec")),
		statExecFaultInject: stats.Create("exec inject", "Executions of fault injection",
			stats.Rate{}, stats.StackedGraph("exec")),
		statExecHint: stats.Create("exec hints", "Executions of programs generated using hints",
			stats.Rate{}, stats.StackedGraph("exec")),
		statExecSeed: stats.Create("exec seeds", "Executions of programs for hints extraction",
			stats.Rate{}, stats.StackedGraph("exec")),
		statExecCollide: stats.Create("exec collide", "Executions of programs in collide mode",
			stats.Rate{}, stats.StackedGraph("exec")),
	}
}
