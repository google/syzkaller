// Copyright 2020 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package main

import (
	"bytes"
	"fmt"
	"io/ioutil"
	"os"
	"path"
	"runtime"
	"strings"
)

func CollectMachineInfo() ([]byte, error) {
	if runtime.GOOS != "linux" {
		return []byte{}, nil
	}

	type machineInfoFunc struct {
		name string
		fn   func() ([]byte, error)
	}

	allMachineInfo := []machineInfoFunc{
		{"CPU Info", readCPUInfo},
		{"KVM", readKVMInfo},
	}

	var buffer bytes.Buffer

	for _, pair := range allMachineInfo {
		buffer.WriteString(fmt.Sprintf("[%s]\n", pair.name))
		data, err := pair.fn()
		if err != nil {
			if os.IsNotExist(err) {
				buffer.WriteString(err.Error() + "\n")
			} else {
				return nil, err
			}
		} else {
			buffer.Write(data)
		}
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

	var buffer bytes.Buffer

	for _, file := range files {
		name := file.Name()
		if strings.HasPrefix(name, "kvm") {
			paramPath := path.Join("/sys/module", name, "parameters")

			params, err := ioutil.ReadDir(paramPath)
			if err != nil {
				if os.IsNotExist(err) {
					continue
				} else {
					return nil, err
				}
			}

			if len(params) > 0 {
				buffer.WriteString(fmt.Sprintf("/sys/module/%s:\n", name))
				for _, key := range params {
					keyName := key.Name()
					data, err := ioutil.ReadFile(path.Join(paramPath, keyName))
					if err != nil {
						return nil, err
					}

					buffer.WriteString(fmt.Sprintf("\t%s: ", keyName))
					buffer.Write(data)
				}
			}
		}
	}

	return buffer.Bytes(), nil
}
