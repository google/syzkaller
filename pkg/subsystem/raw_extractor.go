// Copyright 2023 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package subsystem

import (
	"github.com/google/syzkaller/prog"
)

// rawExtractor performs low-level subsystem matching (directly by a path or a syscall).
type rawExtractor struct {
	matcher *PathMatcher
	perCall map[string][]*Subsystem
}

func makeRawExtractor(list []*Subsystem) *rawExtractor {
	ret := &rawExtractor{
		matcher: MakePathMatcher(list),
		perCall: make(map[string][]*Subsystem),
	}
	for _, subsystem := range list {
		for _, call := range subsystem.Syscalls {
			ret.perCall[call] = append(ret.perCall[call], subsystem)
		}
	}
	return ret
}

func (e *rawExtractor) FromPath(path string) []*Subsystem {
	return e.matcher.Match(path)
}

func (e *rawExtractor) FromProg(progBytes []byte) []*Subsystem {
	calls := make(map[*Subsystem]struct{})
	progCalls, _, _ := prog.CallSet(progBytes)
	for call := range progCalls {
		for _, subsystem := range e.perCall[call] {
			calls[subsystem] = struct{}{}
		}
	}
	list := []*Subsystem{}
	for key := range calls {
		list = append(list, key)
	}
	return list
}
