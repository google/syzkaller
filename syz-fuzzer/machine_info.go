// Copyright 2020 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package main

import (
	"bufio"
	"bytes"
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
)

func CollectMachineInfo() ([]byte, error) {
	if runtime.GOOS != "linux" {
		return nil, nil
	}

	type machineInfoFunc struct {
		name string
		fn   func() ([]byte, error)
	}

	allMachineInfo := []machineInfoFunc{
		{"CPU Info", readCPUInfo},
		{"KVM", readKVMInfo},
	}

	buffer := new(bytes.Buffer)

	for _, pair := range allMachineInfo {
		fmt.Fprintf(buffer, "[%s]\n", pair.name)
		data, err := pair.fn()
		if err != nil {
			if os.IsNotExist(err) {
				buffer.WriteString(err.Error() + "\n")
			}
			return nil, err
		}
		buffer.Write(data)
		fmt.Fprintf(buffer, "-----------------------------------\n\n")
	}

	return buffer.Bytes(), nil
}

func readCPUInfo() ([]byte, error) {
	file, err := os.Open("/proc/cpuinfo")
	if err != nil {
		return nil, err
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	keyOrder := make(map[string]int)
	info := make(map[string][]string)
	for scanner.Scan() {
		splitted := strings.Split(scanner.Text(), ":")
		if len(splitted) != 2 {
			continue
		}
		key := strings.TrimSpace(splitted[0])
		val := strings.TrimSpace(splitted[1])
		if _, ok := keyOrder[key]; !ok {
			keyIdx := len(keyOrder)
			keyOrder[key] = keyIdx
		}
		info[key] = append(info[key], val)
	}
	keys := make([]string, 0, len(keyOrder))
	for key := range keyOrder {
		keys = append(keys, key)
	}
	sort.Slice(keys, func(i, j int) bool {
		return keyOrder[keys[i]] < keyOrder[keys[j]]
	})

	buffer := new(bytes.Buffer)
	for _, key := range keys {
		// It is guaranteed that len(vals) >= 1
		vals := info[key]
		if allEqual(vals) {
			fmt.Fprintf(buffer, "%-20s:\t\t%s\n", key, vals[0])
		} else {
			fmt.Fprintf(buffer, "%-20s:\t\t%s\n", key, strings.Join(vals, ", "))
		}
	}

	return buffer.Bytes(), nil
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

func readKVMInfo() ([]byte, error) {
	files, err := ioutil.ReadDir("/sys/module/")
	if err != nil {
		return nil, err
	}

	buffer := new(bytes.Buffer)

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
			return nil, err
		}

		if len(params) == 0 {
			continue
		}

		fmt.Fprintf(buffer, "/sys/module/%s:\n", name)
		for _, key := range params {
			keyName := key.Name()
			data, err := ioutil.ReadFile(filepath.Join(paramPath, keyName))
			if err != nil {
				return nil, err
			}
			fmt.Fprintf(buffer, "\t%s: ", keyName)
			buffer.Write(data)
		}
		buffer.WriteString("\n")
	}
	return buffer.Bytes(), nil
}
