// Copyright 2020 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package host

import (
	"os"
	"path/filepath"
	"strings"

	"github.com/google/syzkaller/pkg/flatrpc"
)

func ReadFiles(files []string) []flatrpc.FileInfoT {
	var res []flatrpc.FileInfoT
	for _, glob := range files {
		glob = filepath.FromSlash(glob)
		if !strings.Contains(glob, "*") {
			res = append(res, readFile(glob))
			continue
		}
		matches, err := filepath.Glob(glob)
		if err != nil {
			res = append(res, flatrpc.FileInfoT{
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

func readFile(file string) flatrpc.FileInfoT {
	data, err := os.ReadFile(file)
	exists, errStr := true, ""
	if err != nil {
		exists, errStr = !os.IsNotExist(err), err.Error()
	}
	return flatrpc.FileInfoT{
		Name:   file,
		Exists: exists,
		Error:  errStr,
		Data:   data,
	}
}
