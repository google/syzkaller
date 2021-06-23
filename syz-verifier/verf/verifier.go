// Copyright 2021 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

// Package verf contains utilities for verifying the execution of the same
// program on different kernels yield the same results.
package verf

import (
	"github.com/google/syzkaller/pkg/ipc"
	"github.com/google/syzkaller/prog"
)

// Result stores the results of executing a program.
type Result struct {
	// Pool is the index of the pool.
	Pool int
	// Hanged is set to true when a program was killed due to hanging.
	Hanged bool
	// Info contains information about the execution of each system call
	// in the generated programs.
	Info ipc.ProgInfo
}

// Verify checks whether the Results of the same program, executed on different
// kernels are the same. If that's the case, it returns true, otherwise it
// returns false.
func Verify(res []*Result, prog *prog.Prog) bool {
	for i := 1; i < len(res); i++ {
		if !VerifyErrnos(res[0].Info.Calls, res[i].Info.Calls) {
			return false
		}
	}
	return true
}

// VerifyErrnos checks whether the returned system call errnos of the same
// program, executed on two different kernels, are the same.
func VerifyErrnos(c1, c2 []ipc.CallInfo) bool {
	for idx, c := range c1 {
		if c.Errno != c2[idx].Errno {
			return false
		}
	}
	return true
}
