// Copyright 2020 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package host

import (
	"os"
	"path/filepath"
	"strings"
)

type KernelModule struct {
	Name string `json:"Name"`
	Addr uint64 `json:"Addr"`
	Size uint64 `json:"Size"`
}

type FileInfo struct {
	Name   string
	Exists bool
	Error  string
	Data   []byte
}

func ReadFiles(files []string) []FileInfo {
	var res []FileInfo
	for _, glob := range files {
		glob = filepath.FromSlash(glob)
		if !strings.Contains(glob, "*") {
			res = append(res, readFile(glob))
			continue
		}
		matches, err := filepath.Glob(glob)
		if err != nil {
			res = append(res, FileInfo{
				Name:  glob,
				Error: err.Error(),
			})
			continue
		}
		for _, file := range matches {
			res = append(res, readFile(file))
		}
	}
	return res
}

func readFile(file string) FileInfo {
	data, err := os.ReadFile(file)
	exists, errStr := true, ""
	if err != nil {
		exists, errStr = !os.IsNotExist(err), err.Error()
	}
	return FileInfo{
		Name:   file,
		Exists: exists,
		Error:  errStr,
		Data:   data,
	}
}
