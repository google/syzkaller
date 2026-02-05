// Copyright 2025 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package tooltest

import (
	"encoding/json"
	"flag"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/google/syzkaller/pkg/clangtool"
	"github.com/google/syzkaller/pkg/osutil"
	"github.com/google/syzkaller/pkg/testutil"
)

var FlagUpdate = flag.Bool("update", false, "update golden files")

func TestClangTool[Output any, OutputPtr clangtool.OutputDataPtr[Output]](t *testing.T, tool string) {
	ForEachTestFile(t, tool, func(t *testing.T, cfg *clangtool.Config, file string) {
		out, err := clangtool.Run[Output, OutputPtr](cfg)
		if err != nil {
			t.Fatal(err)
		}
		got, err := json.MarshalIndent(out, "", "\t")
		if err != nil {
			t.Fatal(err)
		}
		CompareGoldenData(t, file+".json", got)
	})
}

func LoadOutput[Output any, OutputPtr clangtool.OutputDataPtr[Output]](t *testing.T) OutputPtr {
	out := OutputPtr(new(Output))
	v := clangtool.NewVerifier("testdata")
	forEachTestFile(t, func(t *testing.T, file string) {
		tmp, err := osutil.ReadJSON[OutputPtr](file + ".json")
		if err != nil {
			t.Fatal(err)
		}
		out.Merge(tmp, v)
	})
	out.Finalize(v)
	if err := v.Error(); err != nil {
		t.Fatal(err)
	}
	return out
}

func ForEachTestFile(t *testing.T, tool string, fn func(t *testing.T, cfg *clangtool.Config, file string)) {
	forEachTestFile(t, func(t *testing.T, file string) {
		t.Run(filepath.Base(file), func(t *testing.T) {
			t.Parallel()
			buildDir := t.TempDir()
			commands := fmt.Sprintf(`[{
					"file": "%s",
					"directory": "%s",
					"command": "clang -c %s -DKBUILD_BASENAME=foo"
				}]`,
				file, buildDir, file)
			dbFile := filepath.Join(buildDir, "compile_commands.json")
			if err := os.WriteFile(dbFile, []byte(commands), 0600); err != nil {
				t.Fatal(err)
			}
			cfg := &clangtool.Config{
				Tool:       tool,
				KernelSrc:  osutil.Abs("testdata"),
				KernelObj:  buildDir,
				CacheFile:  filepath.Join(buildDir, filepath.Base(file)+".json"),
				DebugTrace: &testutil.Writer{TB: t},
			}
			fn(t, cfg, file)
		})
	})
}

func forEachTestFile(t *testing.T, fn func(t *testing.T, file string)) {
	var files []string
	err := filepath.WalkDir(osutil.Abs("testdata"), func(path string, d fs.DirEntry, err error) error {
		if d.Name()[0] != '.' && filepath.Ext(d.Name()) == ".c" {
			files = append(files, path)
		}
		return err
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(files) == 0 {
		t.Fatal("found no source files")
	}
	for _, file := range files {
		fn(t, file)
	}
}

func CompareGoldenFile(t *testing.T, goldenFile, gotFile string) {
	got, err := os.ReadFile(gotFile)
	if err != nil {
		t.Fatal(err)
	}
	CompareGoldenData(t, goldenFile, got)
}

func CompareGoldenData(t *testing.T, goldenFile string, got []byte) {
	if *FlagUpdate {
		if err := os.WriteFile(goldenFile, got, 0644); err != nil {
			t.Fatal(err)
		}
	}
	want, err := os.ReadFile(goldenFile)
	if err != nil {
		t.Fatal(err)
	}
	if diff := cmp.Diff(want, got); diff != "" {
		t.Fatal(diff)
	}
}
