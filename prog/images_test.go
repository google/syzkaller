// Copyright 2022 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package prog_test

import (
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"strings"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/google/syzkaller/pkg/osutil"
	. "github.com/google/syzkaller/prog"
	"github.com/google/syzkaller/sys/targets"
)

var flagUpdate = flag.Bool("update", false, "update test files accordingly to current results")

func TestForEachAsset(t *testing.T) {
	target, err := GetTarget(targets.Linux, targets.AMD64)
	if err != nil {
		t.Fatal(err)
	}
	files, err := filepath.Glob(filepath.Join("testdata", "fs_images", "*.in"))
	if err != nil {
		t.Fatalf("directory read failed: %v", err)
	}
	allOutFiles, err := filepath.Glob(filepath.Join("testdata", "fs_images", "*.out*"))
	if err != nil {
		t.Fatalf("directory read failed: %v", err)
	}
	testedOutFiles := []string{}
	for _, file := range files {
		sourceProg, err := os.ReadFile(file)
		if err != nil {
			t.Fatal(err)
		}
		p, err := target.Deserialize(sourceProg, NonStrict)
		if err != nil {
			t.Fatalf("failed to deserialize %s: %s", file, err)
		}
		base := strings.TrimSuffix(file, ".in")
		p.ForEachAsset(func(name string, typ AssetType, r io.Reader) {
			if typ != MountInRepro {
				t.Fatalf("unknown asset type %v", typ)
			}
			testResult, err := io.ReadAll(r)
			if err != nil {
				t.Fatal(err)
			}
			outFilePath := fmt.Sprintf("%v.out_%v", base, name)
			if *flagUpdate {
				if err := osutil.WriteFile(outFilePath, testResult); err != nil {
					t.Fatal(err)
				}
			}
			if !osutil.IsExist(outFilePath) {
				t.Fatalf("asset %v does not exist", outFilePath)
			}
			testedOutFiles = append(testedOutFiles, outFilePath)
			outFile, err := os.ReadFile(outFilePath)
			if err != nil {
				t.Fatal(err)
			}
			if !reflect.DeepEqual(testResult, outFile) {
				t.Fatalf("output not equal:\nWant: %x\nGot: %x", outFile, testResult)
			}
		})
	}
	sort.Strings(testedOutFiles)
	sort.Strings(allOutFiles)
	if diff := cmp.Diff(allOutFiles, testedOutFiles); diff != "" {
		t.Fatalf("not all output files used: %v", diff)
	}
}
