// Copyright 2022 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package subsystem

import (
	"regexp"

	"github.com/google/syzkaller/prog"
	"github.com/google/syzkaller/sys/targets"
)

type SubsystemExtractor struct {
	CallToSubsystems func(call string) []string
}

// Crash contains the subset of Crash fields relevant for subsystem extraction.
type Crash struct {
	OS          string
	GuiltyFiles []string
	SyzRepro    string
}

func (se *SubsystemExtractor) Extract(crash *Crash) []string {
	retMap := map[string]bool{}
	// Currently we only have the dumbest possible implementation of subsystem detection.
	if crash.OS == targets.Linux {
		for _, guiltyPath := range crash.GuiltyFiles {
			if vfsPathRegexp.MatchString(guiltyPath) {
				retMap["vfs"] = true
				break
			}
		}
	}
	if se.CallToSubsystems != nil {
		callSet, _, _ := prog.CallSet([]byte(crash.SyzRepro))
		for call := range callSet {
			for _, subsystem := range se.CallToSubsystems(call) {
				retMap[subsystem] = true
			}
		}
	}
	retSlice := []string{}
	for name := range retMap {
		retSlice = append(retSlice, name)
	}
	return retSlice
}

var (
	vfsPathRegexp = regexp.MustCompile(`^fs/[^/]+\.c`)
)
