// Copyright 2022 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package subsystem

import (
	"regexp"

	"github.com/google/syzkaller/prog"
)

type SubsystemExtractor struct {
	pathToSubsystems func(path string) []string
	callToSubsystems func(call string) []string
}

// Crash contains the subset of Crash fields relevant for subsystem extraction.
type Crash struct {
	OS          string
	GuiltyFiles []string
	SyzRepro    string
}

func MakeLinuxSubsystemExtractor() *SubsystemExtractor {
	return &SubsystemExtractor{
		pathToSubsystems: linuxPathToSubsystems,
	}
}

func (se *SubsystemExtractor) Extract(crash *Crash) []string {
	retMap := map[string]bool{}
	// Currently we only have the dumbest possible implementation of subsystem detection.
	if se.pathToSubsystems != nil {
		for _, path := range crash.GuiltyFiles {
			for _, value := range se.pathToSubsystems(path) {
				retMap[value] = true
			}
		}
	}
	if se.callToSubsystems != nil {
		callSet, _, _ := prog.CallSet([]byte(crash.SyzRepro))
		for call := range callSet {
			for _, subsystem := range se.callToSubsystems(call) {
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

func linuxPathToSubsystems(path string) []string {
	ret := []string{}
	if vfsPathRegexp.MatchString(path) {
		ret = append(ret, "vfs")
	}
	return ret
}

var (
	vfsPathRegexp = regexp.MustCompile(`^fs/[^/]+\.c`)
)
