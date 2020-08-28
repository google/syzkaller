// Copyright 2020 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package main

import (
	"bytes"
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"
	"runtime"
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
		} else {
			buffer.Write(data)
		}
		fmt.Fprintf(buffer, "-------------------------\n", pair.name)
	}

	return buffer.Bytes(), nil
}

func readCPUInfo() (result []byte, err error) {
	result, err = ioutil.ReadFile("/proc/cpuinfo")
	if err != nil {
		return nil, err
	}
	return result, nil
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
	}
	return buffer.Bytes(), nil
}
