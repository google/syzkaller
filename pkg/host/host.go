// Copyright 2018 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package host

import (
	"github.com/google/syzkaller/prog"
)

// DetectSupportedSyscalls returns list on supported and unsupported syscalls on the host.
// For unsupported syscalls it also returns reason as to why it is unsupported.
func DetectSupportedSyscalls(target *prog.Target, sandbox string) (
	map[*prog.Syscall]bool, map[*prog.Syscall]string, error) {
	supported := make(map[*prog.Syscall]bool)
	unsupported := make(map[*prog.Syscall]string)
	for _, c := range target.Syscalls {
		ok, reason := isSupported(c, sandbox)
		if ok {
			supported[c] = true
		} else {
			if reason == "" {
				reason = "unknown"
			}
			unsupported[c] = reason
		}
	}
	return supported, unsupported, nil
}
