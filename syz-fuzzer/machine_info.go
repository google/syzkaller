package main

import (
	"bytes"
	"fmt"
	"io/ioutil"
	"path"
	"runtime"
	"strings"
)

func CollectMachineInfo() string {

	if runtime.GOOS != "linux" {
		return ""
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
		buffer.WriteString(fmt.Sprintf("-------------------- %s ---------------------", pair.name))
		data, err := pair.fn()
		if err == nil {
			buffer.WriteString("\n")
			buffer.Write(data)
			buffer.WriteString("\n")
		} else {
			buffer.WriteString(" error while reading data\n")
		}
	}

	return buffer.String()
}

func readCPUInfo() (result []byte, err error) {
	result, err = ioutil.ReadFile("/proc/cpuinfo")
	if err != nil {
		return nil, err
	}

	return result, nil
}

func readKVMInfo() (result []byte, err error) {
	files, err := ioutil.ReadDir("/sys/module/")
	if err != nil {
		return result, err
	}

	for _, file := range files {
		name := file.Name()
		if strings.HasPrefix(name, "kvm") {
			param_path := path.Join("/sys/module", name, "parameters")

			params, err := ioutil.ReadDir(param_path)
			if err != nil {
				continue
			}

			for _, key := range params {
				keyName := key.Name()
				data, err := ioutil.ReadFile(path.Join(param_path, keyName))
				if err != nil {
					continue
				}

				result = append(result, fmt.Sprintf("%s: %s", keyName, data)...)
			}
		}
	}

	return result, nil
}
