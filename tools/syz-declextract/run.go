// Copyright 2024 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package main

import (
	"encoding/json"
	"errors"
	"flag"
	"os"
	"os/exec"
	"runtime"
	"strings"

	"github.com/google/syzkaller/pkg/tool"
)

type compileCommand struct {
	Arguments []string
	Directory string
	File      string
	Output    string
}

type output struct {
	stdout []byte
	stderr []byte
}

func main() {
	compilationDatabase := flag.String("p", "compile_commands.json", "path to compilation database")
	binary := flag.String("b", "syz-declextract", "path to binary")
	flag.Parse()

	fileData, err := os.ReadFile(*compilationDatabase)
	if err != nil {
		tool.Fail(err)
	}

	var cmds []compileCommand
	if err := json.Unmarshal(fileData, &cmds); err != nil {
		tool.Fail(err)
	}

	outputs := make(chan output, len(cmds))
	files := make(chan string, len(cmds))

	for w := 0; w < runtime.NumCPU(); w++ {
		go worker(outputs, files, *binary, *compilationDatabase)
	}

	for _, v := range cmds {
		files <- v.File
	}
	close(files)

	for range cmds {
		out := <-outputs
		if out.stderr != nil {
			tool.Failf("%s", out.stderr)
		}
		os.Stdout.Write(out.stdout) // To avoid converting to a string.
	}
}

func worker(outputs chan output, files chan string, binary, compilationDatabase string) {
	for file := range files {
		if !strings.HasSuffix(file, ".c") {
			outputs <- output{}
			return
		}

		cmd := exec.Command(binary, "-p", compilationDatabase, file)
		stdout, err := cmd.Output()
		var stderr []byte
		if err != nil {
			var error *exec.ExitError
			if errors.As(err, &error) {
				stderr = error.Stderr
			} else {
				stderr = []byte(err.Error())
			}
		}
		outputs <- output{stdout, stderr}
	}
}
