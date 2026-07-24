// Copyright 2024 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package vminfo

import (
	"fmt"
	"regexp"
	"strconv"
	"strings"
)

type freebsd struct {
	nopChecker
}

func (freebsd) RequiredCommands() []string {
	return []string{"kldstat"}
}

var kldstatRE = regexp.MustCompile(`\s*\d+\s+\d+\s+(0x[0-9a-fA-F]+)\s+([0-9a-fA-F]+)\s+(\S+)`)

func (freebsd) parseModules(files filesystem, cmdResults map[string][]byte) ([]*KernelModule, error) {
	data := cmdResults["kldstat"]
	if len(data) == 0 {
		return nil, nil
	}
	// Parse kldstat output, e.g.:
	// Id Refs Address                Size Name
	//  1    6 0xffffffff80200000  2603a68 kernel
	//  2    1 0xffffffff82804000    3baa8 zfs.ko
	var modules []*KernelModule
	for _, match := range kldstatRE.FindAllSubmatch(data, -1) {
		addr, err := strconv.ParseUint(string(match[1]), 0, 64)
		if err != nil {
			return nil, fmt.Errorf("module address parsing error: %w", err)
		}
		size, err := strconv.ParseUint(string(match[2]), 16, 64)
		if err != nil {
			return nil, fmt.Errorf("module size parsing error: %w", err)
		}
		name := string(match[3])
		name = strings.TrimSuffix(name, ".ko")
		// The "kernel" entry is the base kernel.
		if name == "kernel" {
			name = ""
		}
		modules = append(modules, &KernelModule{
			Name: name,
			Addr: addr,
			Size: size,
		})
	}
	return modules, nil
}
