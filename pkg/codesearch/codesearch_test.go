// Copyright 2025 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package codesearch

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/google/syzkaller/pkg/clangtool/tooltest"
	"github.com/google/syzkaller/pkg/osutil"
)

func TestClangTool(t *testing.T) {
	tooltest.TestClangTool[Database](t)
}

func TestCommands(t *testing.T) {
	db := tooltest.LoadOutput[Database](t)
	index := &Index{db, []string{"testdata"}}
	files, err := filepath.Glob(filepath.Join(osutil.Abs("testdata"), "query*"))
	if err != nil {
		t.Fatal(err)
	}
	if len(files) == 0 {
		t.Fatal("found no qeury files")
	}
	covered := make(map[string]bool)
	for _, file := range files {
		t.Run(filepath.Base(file), func(t *testing.T) {
			testCommand(t, index, covered, file)
		})
	}
	for _, cmd := range Commands {
		if !covered[cmd.Name] {
			t.Errorf("command %v is not covered, add at least one test", cmd.Name)
		}
	}
}

func testCommand(t *testing.T, index *Index, covered map[string]bool, file string) {
	data, err := os.ReadFile(file)
	if err != nil {
		t.Fatal(err)
	}
	query, _, _ := bytes.Cut(data, []byte{'\n'})
	args := strings.Fields(string(query))
	if len(args) == 0 {
		t.Fatal("no command found")
	}
	result, err := index.Command(args[0], args[1:])
	if err != nil {
		t.Fatal(err)
	}
	got := append([]byte(strings.Join(args, " ")+"\n\n"), result...)
	tooltest.CompareGoldenData(t, file, got)
	covered[args[0]] = true
}
