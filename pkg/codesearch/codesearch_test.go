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
	"github.com/google/syzkaller/tools/clang/codesearch"
)

func TestClangTool(t *testing.T) {
	tooltest.TestClangTool[Database](t, clangtoolimpl.Tool)
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
	fields := strings.Fields(string(query))
	if len(fields) == 0 {
		t.Fatal("no command found")
	}
	cmd := fields[0]
	var args []string
	for _, arg := range fields[1:] {
		if len(arg) >= 2 && arg[0] == '"' && arg[len(arg)-1] == '"' {
			arg = arg[1 : len(arg)-1]
		}
		args = append(args, arg)
	}
	result, err := index.Command(cmd, args)
	if err != nil {
		// This is supposed to test aflow.BadCallError messages.
		result = err.Error() + "\n"
	}
	got := append([]byte(strings.Join(fields, " ")+"\n\n"), result...)
	tooltest.CompareGoldenData(t, file, got)
	covered[cmd] = true
}
