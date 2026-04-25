// Copyright 2026 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package toolkit

import (
	"os/exec"
	"path/filepath"
	"testing"
)

func TestToolkitsInTestData(t *testing.T) {
	compiler := "gcc"
	if _, err := exec.LookPath(compiler); err != nil {
		compiler = "clang"
		if _, err := exec.LookPath(compiler); err != nil {
			t.Skip("neither gcc nor clang found, skipping C tests")
		}
	}

	files, err := filepath.Glob("testdata/*.c")
	if err != nil {
		t.Fatal(err)
	}

	for _, cFile := range files {
		t.Run(filepath.Base(cFile), func(t *testing.T) {
			tmpDir := t.TempDir()
			outputExe := filepath.Join(tmpDir, "test_bin")

			cmd := exec.Command(compiler, cFile, "-o", outputExe, "-I", ".", "-pthread")
			if output, err := cmd.CombinedOutput(); err != nil {
				t.Fatalf("compilation failed: %v\n%s", err, output)
			}

			cmd = exec.Command(outputExe)
			if output, err := cmd.CombinedOutput(); err != nil {
				t.Errorf("execution failed: %v\n%s", err, output)
			} else {
				t.Logf("execution output:\n%s", output)
			}
		})
	}
}
