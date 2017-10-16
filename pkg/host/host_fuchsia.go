// Copyright 2017 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

// +build fuchsia

package host

import (
	"github.com/google/syzkaller/prog"
)

// DetectSupportedSyscalls returns list on supported syscalls on host.
func DetectSupportedSyscalls(target *prog.Target) (map[*prog.Syscall]bool, error) {
	supported := make(map[*prog.Syscall]bool)
	for _, c := range target.Syscalls {
		supported[c] = true
	}
	return supported, nil
}

func EnableFaultInjection() error {
	return nil
}
