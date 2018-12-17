// Copyright 2017 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

// syz-fmt re-formats sys files into standard form.
package main

import (
	"bytes"
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"
	"strings"

	"github.com/google/syzkaller/pkg/ast"
	"github.com/google/syzkaller/pkg/osutil"
	"github.com/google/syzkaller/sys/targets"
)

func main() {
	if len(os.Args) < 2 {
		fmt.Fprintf(os.Stderr, "usage: syz-fmt files... or dirs... or all\n")
		os.Exit(1)
	}
	args := os.Args[1:]
	if len(args) == 1 && args[0] == "all" {
		args = nil
		for os := range targets.List {
			args = append(args, filepath.Join("sys", os))
		}
	}
	for _, arg := range args {
		st, err := os.Stat(arg)
		if err != nil {
			fmt.Fprintf(os.Stderr, "failed to stat %v: %v\n", arg, err)
			os.Exit(1)
		}
		if st.IsDir() {
			files, err := ioutil.ReadDir(arg)
			if err != nil {
				fmt.Fprintf(os.Stderr, "failed to read dir %v: %v\n", arg, err)
				os.Exit(1)
			}
			for _, file := range files {
				if !strings.HasSuffix(file.Name(), ".txt") {
					continue
				}
				processFile(filepath.Join(arg, file.Name()), file.Mode())
			}
		} else {
			processFile(arg, st.Mode())
		}
	}
}

func processFile(file string, mode os.FileMode) {
	data, err := ioutil.ReadFile(file)
	if err != nil {
		fmt.Fprintf(os.Stderr, "failed to read file %v: %v\n", file, err)
		os.Exit(1)
	}
	desc := ast.Parse(data, filepath.Base(file), nil)
	if desc == nil {
		os.Exit(1)
	}
	formatted := ast.Format(desc)
	if bytes.Equal(data, formatted) {
		return
	}
	fmt.Printf("reformatting %v\n", file)
	if err := osutil.Rename(file, file+"~"); err != nil {
		fmt.Fprintf(os.Stderr, "%v\n", err)
		os.Exit(1)
	}
	if err := ioutil.WriteFile(file, formatted, mode); err != nil {
		fmt.Fprintf(os.Stderr, "%v\n", err)
		os.Exit(1)
	}
}
