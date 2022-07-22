// Copyright 2022 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package backend

import (
	"bufio"
	"os"
	"testing"
)

func TestGvisorParseLine(t *testing.T) {
	inputDataFiles := []string{
		"test_data/symbolize_all_gvisor_be6ffa78e4df78df13d004a17f2a8833305285c4.txt",
		"test_data/symbolize_all_gvisor_release-20211026.0.txt",
	}

	for _, inputDataFile := range inputDataFiles {
		file, err := os.Open(inputDataFile)
		if err != nil {
			t.Fatal(err)
		}
		defer file.Close()

		lineNum := 0
		s := bufio.NewScanner(file)
		for s.Scan() {
			lineNum++
			_, err := gvisorParseLine(s)
			if err != nil {
				t.Fatal(err)
			}
		}
	}
}

func TestGvisorLineRe(t *testing.T) {
	type Test struct {
		line string
		want string
	}

	tests := []Test{
		{
			"gvisor.dev/gvisor/pkg/abi/abi.go:38.10,39.34",
			"pkg/abi/abi.go",
		},
		{
			"bazel-out/k8-fastbuild-ST-246649c541f7/bin/pkg/abi/linux/linux_abi_autogen_unsafe.go:165.38,167.2",
			"pkg/abi/linux/linux_abi_autogen_unsafe.go",
		},
		{
			"pkg/waiter/waiter.go:301.47,302.2",
			"pkg/waiter/waiter.go",
		},
	}

	for _, test := range tests {
		match := gvisorLineRe.FindStringSubmatch(test.line)
		if match == nil {
			t.Fatalf("FindStringSubmatch error on %v", test.line)
		}
		got := match[2]
		if got != test.want {
			t.Fatalf("wanted %v, got %v", test.want, got)
		}
	}
}
