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

func getModulesInfo() ([]KernelModule, error) {
	var modules []KernelModule
	modulesText, _ := ioutil.ReadFile("/proc/modules")
	re := regexp.MustCompile(`(\w+) .*(0[x|X][a-fA-F0-9]+)[^\n]*`)
	for _, m := range re.FindAllSubmatch(modulesText, -1) {
		addr, err := strconv.ParseUint(string(m[2]), 0, 64)
		if err != nil {
			return nil, fmt.Errorf("address parsing error in /proc/modules: %v", err)
		}
		modules = append(modules, KernelModule{
			Name: string(m[1]),
			Addr: addr,
		})
	}
	text, _ := ioutil.ReadFile("/proc/kallsyms")
	re = regexp.MustCompile(`([a-fA-F0-9]+) T _text\n`)
	for _, m := range re.FindAllSubmatch(text, -1) {
		addr, err := strconv.ParseUint("0x" + string(m[1]), 0, 64)
		if err != nil {
			return nil, fmt.Errorf("address parsing error in /proc/kallsyms: %v", err)
		}
		modules = append(modules, KernelModule{
			Name: "",
			Addr: addr,
		})
	}
	sort.Slice(modules, func(i, j int) bool {
		return modules[i].Addr < modules[j].Addr
	})
	return modules, nil
}

func getGlobsInfo(globs map[string]bool) (map[string][]string, error) {
	files := make(map[string][]string, len(globs))
	for glob := range globs {
		matches, err := filepath.Glob(glob)
		if err != nil {
			return nil, err
		}
		files[glob] = matches
	}
	return files, nil
}
