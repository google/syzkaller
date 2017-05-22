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
)

func main() {
	if len(os.Args) < 2 {
		fmt.Fprintf(os.Stderr, "usage: syz-fmt files... or dirs...\n")
		os.Exit(1)
	}
	for _, arg := range os.Args[1:] {
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
	errorHandler := func(pos ast.Pos, msg string) {
		fmt.Fprintf(os.Stderr, "%v:%v:%v: %v", pos.File, pos.Line, pos.Col, msg)
	}
	top, ok := ast.Parse(data, filepath.Base(file), errorHandler)
	if !ok {
		os.Exit(1)
	}
	formatted := ast.Format(top)
	if bytes.Equal(data, formatted) {
		return
	}
	if err := os.Rename(file, file+"~"); err != nil {
		fmt.Fprintf(os.Stderr, "%v\n", err)
		os.Exit(1)
	}
	if err := ioutil.WriteFile(file, formatted, mode); err != nil {
		fmt.Fprintf(os.Stderr, "%v\n", err)
		os.Exit(1)
	}
}
