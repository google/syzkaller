// Copyright 2020 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package host

import (
	"bufio"
	"bytes"
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
)

func init() {
	machineInfoFuncs = []machineInfoFunc{
		{"CPU Info", readCPUInfo},
		{"KVM", readKVMInfo},
	}
	machineModulesInfo = getModulesInfo
	machineGlobsInfo = getGlobsInfo
}

func readCPUInfo(buffer *bytes.Buffer) error {
	file, err := os.Open("/proc/cpuinfo")
	if err != nil {
		return err
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	scanCPUInfo(buffer, scanner)
	return nil
}

func scanCPUInfo(buffer *bytes.Buffer, scanner *bufio.Scanner) {
	keyIndices := make(map[string]int)
	type keyValues struct {
		key    string
		values []string
	}
	var info []keyValues

	for scanner.Scan() {
		splitted := strings.Split(scanner.Text(), ":")
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
			fmt.Fprintf(buffer, "%-20s: %s\n", key, vals[0])
		} else {
			fmt.Fprintf(buffer, "%-20s: %s\n", key, strings.Join(vals, ", "))
		}
	}
}

func allEqual(slice []string) bool {
	if len(slice) == 0 {
		return true
	}
	for i := 1; i < len(slice); i++ {
		if slice[i] != slice[0] {
			return false
		}
	}
	return true
}

func readKVMInfo(buffer *bytes.Buffer) error {
	files, err := ioutil.ReadDir("/sys/module/")
	if err != nil {
		return err
	}

	for _, file := range files {
		name := file.Name()
		if !strings.HasPrefix(name, "kvm") {
			continue
		}

		paramPath := filepath.Join("/sys", "module", name, "parameters")
		params, err := ioutil.ReadDir(paramPath)
		if err != nil {
			if os.IsNotExist(err) {
				continue
			}
			return err
		}

		if len(params) == 0 {
			continue
		}

		fmt.Fprintf(buffer, "/sys/module/%s:\n", name)
		for _, key := range params {
			keyName := key.Name()
			data, err := ioutil.ReadFile(filepath.Join(paramPath, keyName))
			if err != nil {
				return err
			}
			fmt.Fprintf(buffer, "\t%s: ", keyName)
			buffer.Write(data)
		}
		buffer.WriteByte('\n')
	}
	return nil
}

func getModulesInfo() ([]*KernelModule, int, error) {
	var modules []*KernelModule
	modulesText, _ := ioutil.ReadFile("/proc/modules")
	re := regexp.MustCompile(`(\w+) .*(0[x|X][a-fA-F0-9]+)[^\n]*`)
	for _, m := range re.FindAllSubmatch(modulesText, -1) {
		addr, err := strconv.ParseUint(string(m[2]), 0, 64)
		if err != nil {
			return nil, 0, fmt.Errorf("address parsing error in /proc/modules: %v", err)
		}
		modules = append(modules, &KernelModule{
			Name: string(m[1]),
			Addr: addr,
		})
	}
	sort.Slice(modules, func(i, j int) bool {
		return modules[i].Addr < modules[j].Addr
	})
	moduleLoadOffset, err := getModuleLoadOffset(modules[0])
	if err != nil {
		return nil, 0, fmt.Errorf("failed to get module load offset: %v", err)
	}
	return modules, moduleLoadOffset, nil
}

func getModuleLoadOffset(module *KernelModule) (int, error) {
	moduleLoadOffset := 0
	var addresses []uint64
	moduleSymbolText, _ := ioutil.ReadFile("/proc/kallsyms")
	re := regexp.MustCompile(fmt.Sprintf(`([a-fA-F0-9]+) .*\[%s\]`, module.Name))
	for _, m := range re.FindAllSubmatch(moduleSymbolText, -1) {
		addr, err := strconv.ParseUint("0x"+string(m[1]), 0, 64)
		if err != nil {
			return 0, fmt.Errorf("address parsing error in /proc/kallsyms: %v", err)
		}
		addresses = append(addresses, addr)
	}
	sort.Slice(addresses, func(i, j int) bool {
		return addresses[i] < addresses[j]
	})
	moduleLoadOffset = int(addresses[0] - module.Addr)
	return moduleLoadOffset, nil
}

func getGlobsInfo(globs map[string]bool) (map[string][]string, error) {
	var err error
	files := make(map[string][]string, len(globs))
	for glob := range globs {
		var (
			addglobs []string
			subglobs []string
			matches  []string
		)
		tokens := strings.Split(glob, ":")
		for _, tok := range tokens {
			if strings.HasPrefix(tok, "-") {
				subglobs = append(subglobs, tok[1:])
			} else {
				addglobs = append(addglobs, tok)
			}
		}
		for _, g := range addglobs {
			m, err := filepath.Glob(g)
			if err != nil {
				return nil, err
			}
			matches = append(matches, m...)
		}
		files[glob], err = excludeGlobs(removeDupValues(matches), subglobs)
		if err != nil {
			return nil, err
		}
	}
	return files, nil
}

func excludeGlobs(items, subglobs []string) ([]string, error) {
	var results []string
	excludes := make(map[string]bool)
	for _, glob := range subglobs {
		matches, err := filepath.Glob(glob)
		if err != nil {
			return nil, err
		}
		for _, m := range matches {
			excludes[m] = true
		}
	}

	for _, item := range items {
		if !excludes[item] {
			results = append(results, item)
		}
	}
	return results, nil
}

func removeDupValues(slice []string) []string {
	keys := make(map[string]bool)
	list := []string{}
	for _, entry := range slice {
		if !keys[entry] {
			keys[entry] = true
			list = append(list, entry)
		}
	}
	return list
}
