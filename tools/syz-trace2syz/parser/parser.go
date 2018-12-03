// Copyright 2018 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package parser

import (
	"bufio"
	"io/ioutil"
	"strings"

	"github.com/google/syzkaller/pkg/log"
)

const (
	maxBufferSize = 64 * 1024 * 1024                    // maxBufferSize is maximum size for buffer
	sysrestart    = "ERESTART"                          // SYSRESTART corresponds to the error code of ERESTART.
	signalPlus    = "+++"                               // SignalPlus marks +++
	signalMinus   = "---"                               // SignalPlus marks ---
	noSuchProcess = "<ptrace(SYSCALL):No such process>" // No such process error. Nothing worth parsing
)

func parseSyscall(scanner *bufio.Scanner) (int, *Syscall) {
	lex := newStraceLexer(scanner.Bytes())
	ret := StraceParse(lex)
	return ret, lex.result
}

func shouldSkip(line string) bool {
	restart := strings.Contains(line, sysrestart)
	signalPlus := strings.Contains(line, signalPlus)
	signalMinus := strings.Contains(line, signalMinus)
	noProcess := strings.Contains(line, noSuchProcess)
	return restart || signalPlus || signalMinus || noProcess
}

// ParseLoop parses each line of a strace file in a loop
func ParseLoop(data string) (tree *TraceTree) {
	tree = NewTraceTree()
	// Creating the process tree
	buf := make([]byte, maxBufferSize)
	scanner := bufio.NewScanner(strings.NewReader(data))
	scanner.Buffer(buf, maxBufferSize)

	for scanner.Scan() {
		line := scanner.Text()
		if shouldSkip(line) {
			continue
		}
		log.Logf(4, "scanning call: %s", line)
		ret, call := parseSyscall(scanner)
		if call == nil || ret != 0 {
			log.Fatalf("failed to parse line: %s", line)
		}
		tree.add(call)
	}
	if len(tree.Ptree) == 0 {
		return nil
	}
	return
}

// Parse parses a trace of system calls and returns an intermediate representation
func Parse(filename string) *TraceTree {
	data, err := ioutil.ReadFile(filename)
	if err != nil {
		log.Fatalf("error reading file: %s", err.Error())
	}
	tree := ParseLoop(string(data))
	if tree != nil {
		tree.Filename = filename
	}
	return tree
}
