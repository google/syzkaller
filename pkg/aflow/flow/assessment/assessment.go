// Copyright 2025 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package assessmenet

// Common inputs for bug assessment when we don't have a reproducer.
type Inputs struct {
	CrashReport       string
	KernelRepo        string
	KernelCommit      string
	KernelConfig      string
	CodesearchToolBin string
}
