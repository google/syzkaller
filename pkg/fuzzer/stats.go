// Copyright 2024 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package fuzzer

const (
	statGenerate       = "exec gen"
	statFuzz           = "exec fuzz"
	statCandidate      = "exec candidate"
	statTriage         = "exec triage"
	statMinimize       = "exec minimize"
	statSmash          = "exec smash"
	statHint           = "exec hints"
	statSeed           = "exec seeds"
	statCollide        = "exec collide"
	statExecTotal      = "exec total"
	statBufferTooSmall = "buffer too small"
)

func (fuzzer *Fuzzer) GrabStats() map[string]uint64 {
	fuzzer.mu.Lock()
	defer fuzzer.mu.Unlock()
	ret := fuzzer.stats
	fuzzer.stats = map[string]uint64{}
	return ret
}
