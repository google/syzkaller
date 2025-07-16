// Copyright 2025 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
package csource

import (
	"bufio"
	"flag"
	"fmt"
	"os"
	"path"
	"strings"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/google/syzkaller/prog"
	"github.com/google/syzkaller/sys/targets"
	"github.com/stretchr/testify/assert"
)

var flagUpdate = flag.Bool("update", false, "update test files accordingly to current results")

type testData struct {
	filepath string
	// The input syscall description, e.g. bind$netlink(r0, &(0x7f0000514ff4)={0x10, 0x0, 0x0, 0x2ffffffff}, 0xc).
	input string
	calls []annotatedCall
}

type annotatedCall struct {
	comment string
	syscall string
}

func TestGenerateSyscalls(t *testing.T) {
	flag.Parse()

	testCases, err := readTestCases("./testdata")
	assert.NoError(t, err)

	target, err := prog.GetTarget(targets.Linux, targets.AMD64)
	if err != nil {
		t.Fatal(err)
	}

	for _, tc := range testCases {
		newData, equal := testGenerationImpl(t, tc, target)
		if *flagUpdate && !equal {
			t.Logf("writing updated contents to %s", tc.filepath)
			err = os.WriteFile(tc.filepath, []byte(newData), 0640)
			assert.NoError(t, err)
		}
	}
}

func readTestCases(dir string) ([]testData, error) {
	var testCases []testData

	testFiles, err := os.ReadDir(dir)
	if err != nil {
		return nil, err
	}

	for _, testFile := range testFiles {
		if testFile.IsDir() {
			continue
		}

		testCase, err := readTestData(path.Join(dir, testFile.Name()))
		if err != nil {
			return nil, err
		}
		testCases = append(testCases, testCase)
	}

	return testCases, nil
}

func readTestData(filepath string) (testData, error) {
	var td testData
	td.filepath = filepath

	file, err := os.Open(filepath)
	if err != nil {
		return testData{}, err
	}

	scanner := bufio.NewScanner(file)

	var inputBuilder strings.Builder
	for scanner.Scan() {
		line := scanner.Text()
		if line == "" {
			break
		}
		inputBuilder.WriteString(line + "\n")
	}
	td.input = inputBuilder.String()

	var commentBuilder strings.Builder
	for scanner.Scan() {
		line := scanner.Text()
		if strings.HasPrefix(line, commentPrefix) {
			if commentBuilder.Len() > 0 {
				commentBuilder.WriteString("\n")
			}
			commentBuilder.WriteString(line)
		} else {
			td.calls = append(td.calls, annotatedCall{
				comment: commentBuilder.String(),
				syscall: line,
			})
			commentBuilder.Reset()
		}
	}

	if err := scanner.Err(); err != nil {
		return testData{}, err
	}

	if commentBuilder.Len() != 0 {
		return testData{}, fmt.Errorf("expected a syscall expression but got EOF")
	}
	return td, nil
}

// Returns the generated content, and whether or not they were equal.
func testGenerationImpl(t *testing.T, test testData, target *prog.Target) (string, bool) {
	p, err := target.Deserialize([]byte(test.input), prog.Strict)
	if err != nil {
		t.Fatal(err)
	}

	// Generate the actual comments.
	var actualComments []string
	for _, call := range p.Calls {
		comment := generateComment(call)
		// Formatted comments make comparison easier.
		formatted, err := Format([]byte(comment))
		if err != nil {
			t.Fatal(err)
		}
		actualComments = append(actualComments, string(formatted))
	}

	// Minimal options as we are just testing syscall output.
	opts := Options{
		Slowdown: 1,
	}
	ctx := &context{
		p:         p,
		opts:      opts,
		target:    p.Target,
		sysTarget: targets.Get(p.Target.OS, p.Target.Arch),
		calls:     make(map[string]uint64),
	}

	// Partially replicate the flow from csource.go.
	exec, err := p.SerializeForExec()
	if err != nil {
		t.Fatal(err)
	}
	decoded, err := ctx.target.DeserializeExec(exec, nil)
	if err != nil {
		t.Fatal(err)
	}
	var actualSyscalls []string
	for _, execCall := range decoded.Calls {
		actualSyscalls = append(actualSyscalls, ctx.fmtCallBody(execCall))
	}

	if len(actualSyscalls) != len(test.calls) || len(actualSyscalls) != len(actualComments) {
		t.Fatal("Generated inconsistent syscalls or comments.")
	}

	areEqual := true
	for i := range actualSyscalls {
		if diffSyscalls := cmp.Diff(actualSyscalls[i], test.calls[i].syscall); diffSyscalls != "" {
			fmt.Print(diffSyscalls)
			t.Fail()
			areEqual = false
		}
		if diffComments := cmp.Diff(actualComments[i], test.calls[i].comment); diffComments != "" {
			fmt.Print(diffComments)
			t.Fail()
			areEqual = false
		}
	}

	var outputBuilder strings.Builder
	outputBuilder.WriteString(test.input + "\n")
	for i := range actualSyscalls {
		outputBuilder.WriteString(actualComments[i] + "\n")
		outputBuilder.WriteString(actualSyscalls[i])
		// Avoid trailing newline.
		if i != len(test.calls)-1 {
			outputBuilder.WriteString("\n")
		}
	}

	return outputBuilder.String(), areEqual
}
