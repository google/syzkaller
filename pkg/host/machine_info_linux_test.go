// Copyright 2020 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package host

import (
	"bufio"
	"bytes"
	"runtime"
	"strings"
	"testing"
)

func TestMachineInfoLinux(t *testing.T) {
	result, err := CollectMachineInfo()
	if err != nil {
		t.Fatal(err)
	}

	scanner := bufio.NewScanner(bytes.NewReader(result))

	for scanner.Scan() {
		line := scanner.Text()

		if line == "[CPU Info]" {
			checkCPUInfo(t, scanner)
		}
		if line == "[KVM]" {
			checkKVMInfo(t, scanner)
		}
	}
}

func checkCPUInfo(t *testing.T, scanner *bufio.Scanner) {
	keys := make(map[string]bool)
	for scanner.Scan() {
		line := scanner.Text()
		// End of CPU Info section.
		if strings.HasPrefix(line, "-----") {
			break
		}
		splitted := strings.Split(line, ":")
		if len(splitted) != 2 {
			t.Fatalf("the format of line \"%s\" is not correct", line)
		}
		key := strings.TrimSpace(splitted[0])
		keys[key] = true
	}

	importantKeys := map[string][]string{
		"ppc64le":  {"cpu", "revision", "platform", "model", "machine"},
		"amd64":    {"vendor_id", "model", "flags"},
		"s390x":    {"vendor_id", "processor 0", "features"},
		"386":      {"vendor_id", "model", "flags"},
		"arm64":    {"CPU implementer", "CPU part", "Features"},
		"arm":      {"CPU implementer", "CPU part", "Features"},
		"mips64le": {"system type", "cpu model", "ASEs implemented"},
		"riscv64":  {"processor", "isa", "mmu"},
	}
	archKeys := importantKeys[runtime.GOARCH]
	for _, name := range archKeys {
		if !keys[name] {
			t.Fatalf("key '%s' not found", name)
		}
	}
}

func checkKVMInfo(t *testing.T, scanner *bufio.Scanner) {
	for scanner.Scan() {
		line := scanner.Text()
		if line == "" {
			continue
		}
		if strings.HasPrefix(line, "-----") {
			break
		}
		splitted := strings.Split(line, ":")
		if len(splitted) != 2 {
			t.Fatalf("the format of line \"%s\" is not correct", line)
		}
		key := strings.TrimSpace(splitted[0])
		if key == "" {
			t.Fatalf("empty key")
		}
		if key[0] != '/' {
			continue
		}

		if !strings.HasPrefix(key, "/sys/module/kvm") {
			t.Fatalf("the directory does not match /sys/module/kvm*")
		}
	}
}

func TestScanCPUInfo(t *testing.T) {
	input := `A:	a
B:	b

C:	c1
D:	d
C:	c1
D:	d
C:	c2
D:	d
`

	output := []struct {
		key, val string
	}{
		{"A", "a"},
		{"B", "b"},
		{"C", "c1, c1, c2"},
		{"D", "d"},
	}
	scanner := bufio.NewScanner(strings.NewReader(input))
	buffer := new(bytes.Buffer)
	scanCPUInfo(buffer, scanner)
	result := bufio.NewScanner(buffer)

	idx := 0
	for result.Scan() {
		line := result.Text()
		splitted := strings.Split(line, ":")
		if len(splitted) != 2 {
			t.Fatalf("the format of line \"%s\" is not correct", line)
		}
		key := strings.TrimSpace(splitted[0])
		val := strings.TrimSpace(splitted[1])
		if idx >= len(output) {
			t.Fatalf("additional line \"%s: %s\"", key, val)
		}
		expected := output[idx]
		if key != expected.key || val != expected.val {
			t.Fatalf("expected \"%s: %s\", got \"%s: %s\"",
				expected.key, expected.val, key, val)
		}
		idx++
	}
	if idx < len(output) {
		expected := output[idx]
		t.Fatalf("expected \"%s: %s\", got end of output",
			expected.key, expected.val)
	}
}
