// Copyright 2015 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package main

import (
	"math/rand"
	"time"

	"github.com/google/syzkaller/pkg/log"
	"github.com/google/syzkaller/pkg/mab"
	"github.com/google/syzkaller/prog"
)

func (proc *Proc) DoGenerate() *mab.ExecResult {
	ts0 := time.Now().UnixNano()
	ct := proc.fuzzer.choiceTable
	p := proc.fuzzer.target.Generate(proc.rnd, prog.RecommendedCalls, ct)
	_, ret := proc.execute(proc.execOpts, p, ProgNormal, StatSmash)
	ret.TimeTotal = float64(time.Now().UnixNano()-ts0) / MABTimeUnit
	return &ret
}

func (proc *Proc) DoMutate() *mab.ExecResult {
	ts0 := time.Now().UnixNano()
	fuzzerSnapshot := proc.fuzzer.snapshot()
	ct := proc.fuzzer.choiceTable
	// MAB seed selection is integrated with chooseProgram
	pidx, _p := fuzzerSnapshot.chooseProgram(proc.rnd)
	p := _p.Clone()
	p.ResetReward()
	p.Mutate(proc.rnd, prog.RecommendedCalls, ct, fuzzerSnapshot.corpus)
	_, ret := proc.execute(proc.execOpts, p, ProgNormal, StatFuzz)
	ret.Pidx = pidx
	ret.TimeTotal = float64(time.Now().UnixNano()-ts0) / MABTimeUnit
	return &ret
}

func (proc *Proc) DoTriage() *mab.TriageResult {
	ts0 := time.Now().UnixNano()
	item := proc.fuzzer.workQueue.dequeue(DequeueOptionTriageOnly)
	switch item := item.(type) {
	case *WorkTriage:
		{
			ret := proc.ProcessItem(item)
			ret.TimeTotal = float64(time.Now().UnixNano()-ts0) / MABTimeUnit
			return ret
		}
	default:
		{
			return nil
		}
	}
}

func (proc *Proc) clearQueue() {
	// Clear the work queue for all non-Triage items
	count := 0
	for {
		item := proc.fuzzer.workQueue.dequeue(DequeueOptionNoTriage)
		if item != nil {
			count++
			log.Logf(0, "Clearing candidate %v from work queue.\n", count)
			proc.ProcessItem(item)
		} else {
			return
		}
	}
}

func (proc *Proc) MABLoop() {
	// Compute weight and proba
	weight := proc.fuzzer.MABStatus.GetTSWeight(true)
	fuzzerSnapshot := proc.fuzzer.snapshot()
	triageCount := 1
	mutateCount := 1
	if len(fuzzerSnapshot.corpus) == 0 { // Check whether mutation is an option
		mutateCount = 0
	}
	proc.fuzzer.workQueue.mu.Lock() // Check whether triage is an option
	triageQueueLen := len(proc.fuzzer.workQueue.triage)
	triageQueueLenCandidate := len(proc.fuzzer.workQueue.triageCandidate)
	proc.fuzzer.workQueue.mu.Unlock()
	if triageQueueLen+triageQueueLenCandidate == 0 {
		triageCount = 0
	}
	W := weight[0] + float64(mutateCount)*weight[1] + float64(triageCount)*weight[2]
	if W == 0.0 {
		log.Fatalf("Error total weight W = 0")
	}
	prGenerate := weight[0] / W
	prMutate := weight[1] / W
	prTriage := weight[2] / W
	prMutateActual := float64(mutateCount) * prMutate
	prTriageActual := float64(triageCount) * prTriage
	// Use real weight as pr. Consider cases where triage/mutation might be unavailable
	prTasks := []float64{prGenerate, prMutateActual, prTriageActual}
	log.Logf(0, "MAB Probability: [%v, %v, %v]\n", prTasks[0], prTasks[1], prTasks[2])
	// Choose
	randNum := rand.Float64() * (prGenerate + prMutateActual + prTriageActual)
	choice := -1
	if randNum <= prGenerate {
		choice = 0
	} else if randNum > prGenerate && randNum <= prGenerate+prMutateActual {
		choice = 1
	} else {
		choice = 2
	}
	// Handle choices
	var r interface{}
	if choice == 0 {
		r = *proc.DoGenerate()
	} else if choice == 1 {
		r = *proc.DoMutate()
	} else if choice == 2 {
		r = *proc.DoTriage()
	}
	if r != nil {
		log.Logf(0, "MAB Choice: %v, Result: %+v\n", choice, r)
	}
	// Update Weight
	proc.fuzzer.MABStatus.UpdateWeight(choice, r, prTasks)
}
