// Copyright 2020 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package host

import (
	"bufio"
	"bytes"
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

	importantKeys := [][]string{
		{"vendor", "vendor_id", "CPU implementer"},
		{"model", "CPU part", "cpu model", "machine"},
		{"flags", "features", "Features", "ASEs implemented", "type"},
	}
	for _, possibleNames := range importantKeys {
		exists := false
		for _, name := range possibleNames {
			if keys[name] {
				exists = true
				break
			}
		}
		if !exists {
			t.Fatalf("one of {%s} should exists in the output, but not found",
				strings.Join(possibleNames, ", "))
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
