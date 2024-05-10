// Copyright 2018 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package host

import (
	"github.com/google/syzkaller/pkg/log"
	"github.com/google/syzkaller/prog"
)

// DetectSupportedSyscalls returns list on supported and unsupported syscalls on the host.
// For unsupported syscalls it also returns reason as to why it is unsupported.
func DetectSupportedSyscalls(target *prog.Target, sandbox string, enabled map[*prog.Syscall]bool) (
	map[*prog.Syscall]bool, map[*prog.Syscall]string, error) {
	log.Logf(1, "detecting supported syscalls")
	supported := make(map[*prog.Syscall]bool)
	unsupported := make(map[*prog.Syscall]string)
	// These do not have own host and parasitize on some other OS.
	if noHostChecks(target) {
		for _, c := range target.Syscalls {
			if c.Attrs.Disabled || !enabled[c] {
				continue
			}
			supported[c] = true
		}
	} else {
		for _, c := range target.Syscalls {
			if c.Attrs.Disabled || !enabled[c] {
				continue
			}
			ok, reason := isSupported(c, target, sandbox)
			if ok {
				supported[c] = true
			} else {
				if reason == "" {
					reason = "unknown"
				}
				unsupported[c] = reason
			}
		}
	}
	return supported, unsupported, nil
}

var testFallback = false
