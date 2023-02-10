// Copyright 2023 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package subsystem

// In general, it's not correct to assume that subsystems are only determined by target.OS,
// because subsystems are related not to the user interface of the OS kernel, but rather to
// the OS kernel implementation.
//
// For example, during fuzzing we can treat gVisor in the same way as any other Linux kernel.
// In reality, however, not a single MAINTAINERS-based rule will work on the gVisor codebase.
//
// Therefore, subsystem lists have to be a completely different entity.

var (
	lists = make(map[string][]*Subsystem)
)

func RegisterList(name string, list []*Subsystem) {
	if _, ok := lists[name]; ok {
		panic(name + " subsystem list already exists!")
	}
	lists[name] = list
}

func GetList(name string) []*Subsystem {
	return lists[name]
}
