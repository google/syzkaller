// Copyright 2020 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package host

import (
	"bytes"
	"fmt"
	"os"
	"strings"
)

func CollectMachineInfo() ([]byte, error) {
	buf := new(bytes.Buffer)
	for _, pair := range machineInfoFuncs {
		pos0 := buf.Len()
		fmt.Fprintf(buf, "[%s]\n", pair.name)
		pos1 := buf.Len()
		err := pair.fn(buf)
		if err != nil {
			if !os.IsNotExist(err) {
				return nil, err
			}
		}
		if buf.Len() == pos1 {
			buf.Truncate(pos0)
			continue
		}
		fmt.Fprintf(buf, "\n%v\n\n", strings.Repeat("-", 80))
	}
	return buf.Bytes(), nil
}

func CollectModulesInfo() ([]KernelModule, error) {
	if machineModulesInfo == nil {
		return nil, nil
	}
	return machineModulesInfo()
}

func CollectGlobsInfo(globs map[string]bool) (map[string][]string, error) {
	if machineGlobsInfo == nil {
		return nil, nil
	}
	return machineGlobsInfo(globs)
}

func ParseModulesText(modulesText []byte) ([]KernelModule, error) {
	if machineParseModules == nil {
		return nil, nil
	}
	return machineParseModules(modulesText)
}

var machineInfoFuncs []machineInfoFunc
var machineModulesInfo func() ([]KernelModule, error)
var machineGlobsInfo func(map[string]bool) (map[string][]string, error)
var machineParseModules func([]byte) ([]KernelModule, error)

type machineInfoFunc struct {
	name string
	fn   func(*bytes.Buffer) error
}

type KernelModule struct {
	Name string `json:"Name"`
	Addr uint64 `json:"Addr"`
	Size uint64 `json:"Size"`
}
