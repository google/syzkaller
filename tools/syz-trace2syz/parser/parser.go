// Copyright 2018 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

// +build !codeanalysis

package parser

import (
	"bufio"
	"bytes"
	"fmt"
	"strings"

	"github.com/google/syzkaller/pkg/log"
)

func parseSyscall(scanner *bufio.Scanner) (int, *Syscall) {
	lex := newStraceLexer(scanner.Bytes())
	ret := StraceParse(lex)
	return ret, lex.result
}

func shouldSkip(line string) bool {
	return strings.Contains(line, "ERESTART") ||
		strings.Contains(line, "+++") ||
		strings.Contains(line, "---") ||
		strings.Contains(line, "<ptrace(SYSCALL):No such process>")
}

// ParseLoop parses each line of a strace file in a loop.
func ParseData(data []byte) (*TraceTree, error) {
	tree := NewTraceTree()
	// Creating the process tree
	scanner := bufio.NewScanner(bytes.NewReader(data))
	scanner.Buffer(nil, 64<<20)
	for scanner.Scan() {
		line := scanner.Text()
		if shouldSkip(line) {
			continue
		}
		log.Logf(4, "scanning call: %s", line)
		ret, call := parseSyscall(scanner)
		if call == nil || ret != 0 {
			return nil, fmt.Errorf("failed to parse line: %v", line)
		}
		tree.add(call)
	}
	if err := scanner.Err(); err != nil {
		return nil, err
	}
	if len(tree.TraceMap) == 0 {
		return nil, nil
	}
	return tree, nil
}
