// Copyright 2024 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package vminfo

import (
	"bufio"
	"bytes"
	"fmt"
	"io"
	"path"
	"regexp"
	"strconv"
	"strings"

	"github.com/google/syzkaller/pkg/cover"
)

type linux int

func (linux) RequiredFiles() []string {
	return []string{
		"/proc/cpuinfo",
		"/proc/modules",
		"/sys/module/*/sections/.text",
		"/sys/module/kvm*/parameters/*",
	}
}

func (linux) checkFiles() []string {
	return []string{
		"/proc/version",
		"/proc/filesystems",
		"/sys/kernel/security/lsm",
		"/dev/raw-gadget",
	}
}

func (linux) machineInfos() []machineInfoFunc {
	return []machineInfoFunc{
		linuxReadCPUInfo,
		linuxReadKVMInfo,
	}
}

func (linux) parseModules(files filesystem) ([]cover.KernelModule, error) {
	var modules []cover.KernelModule
	re := regexp.MustCompile(`(\w+) ([0-9]+) .*(0[x|X][a-fA-F0-9]+)[^\n]*`)
	modulesText, _ := files.ReadFile("/proc/modules")
	for _, match := range re.FindAllSubmatch(modulesText, -1) {
		name := string(match[1])
		modAddr, err := strconv.ParseUint(string(match[3]), 0, 64)
		if err != nil {
			// /proc/modules is broken, bail out.
			return nil, fmt.Errorf("module %v address parsing error: %w", name, err)
		}
		textAddr, err := linuxModuleTextAddr(files, name)
		if err != nil {
			// Module address unavailable, .text is probably 0. Skip this module.
			continue
		}
		modSize, err := strconv.ParseUint(string(match[2]), 0, 64)
		if err != nil {
			// /proc/modules is broken, bail out.
			return nil, fmt.Errorf("module %v size parsing error: %w", name, err)
		}
		offset := modAddr - textAddr
		modules = append(modules, cover.KernelModule{
			Name: name,
			Addr: textAddr,
			Size: modSize - offset,
		})
	}
	return modules, nil
}

func linuxModuleTextAddr(files filesystem, module string) (uint64, error) {
	data, err := files.ReadFile("/sys/module/" + module + "/sections/.text")
	if err != nil {
		return 0, fmt.Errorf("could not read module %v .text address file: %w", module, err)
	}
	addrString := strings.TrimSpace(string(data))
	addr, err := strconv.ParseUint(addrString, 0, 64)
	if err != nil {
		return 0, fmt.Errorf("address parsing error in %v: %w", module, err)
	}
	return addr, nil
}

func linuxReadCPUInfo(files filesystem, w io.Writer) (string, error) {
	data, err := files.ReadFile("/proc/cpuinfo")
	if err != nil {
		return "", fmt.Errorf("error reading CPU info:: %w", err)
	}

	keyIndices := make(map[string]int)
	type keyValues struct {
		key    string
		values []string
	}
	var info []keyValues
	for s := bufio.NewScanner(bytes.NewReader(data)); s.Scan(); {
		splitted := strings.Split(s.Text(), ":")
		if len(splitted) != 2 {
			continue
		}
		key := strings.TrimSpace(splitted[0])
		val := strings.TrimSpace(splitted[1])
		if idx, ok := keyIndices[key]; !ok {
			idx = len(keyIndices)
			keyIndices[key] = idx
			info = append(info, keyValues{key, []string{val}})
		} else {
			info[idx].values = append(info[idx].values, val)
		}
	}

	for _, kv := range info {
		// It is guaranteed that len(vals) >= 1
		key := kv.key
		vals := kv.values
		if allEqual(vals) {
			fmt.Fprintf(w, "%-20s: %s\n", key, vals[0])
		} else {
			fmt.Fprintf(w, "%-20s: %s\n", key, strings.Join(vals, ", "))
		}
	}
	return "CPU Info", nil
}

func allEqual(slice []string) bool {
	for i := 1; i < len(slice); i++ {
		if slice[i] != slice[0] {
			return false
		}
	}
	return true
}

func linuxReadKVMInfo(files filesystem, w io.Writer) (string, error) {
	for _, module := range files.ReadDir("/sys/module") {
		if !strings.HasPrefix(module, "kvm") {
			continue
		}
		paramPath := path.Join("/sys", "module", module, "parameters")
		fmt.Fprintf(w, "/sys/module/%s:\n", module)
		for _, param := range files.ReadDir(paramPath) {
			data, err := files.ReadFile(path.Join(paramPath, param))
			if err != nil {
				return "", fmt.Errorf("error reading KVM info: %w", err)
			}
			fmt.Fprintf(w, "\t%s: %s", param, data)
		}
		w.Write([]byte{'\n'})
	}
	return "KVM", nil
}
