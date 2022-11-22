// Copyright 2022 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package linux_test

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

	"github.com/google/syzkaller/pkg/osutil"
	"github.com/google/syzkaller/prog"
	"github.com/google/syzkaller/sys/targets"
)

// nolint: lll

func TestSyzMountImageNeutralize(t *testing.T) {
	prog.TestDeserializeHelper(t, targets.Linux, targets.AMD64, nil, []prog.DeserializeTest{
		{
			// A valid call, nothing should change.
			In: `syz_mount_image$bfs(&(0x7f0000000000)='bfs\x00', &(0x7f0000000100)='./file0\x00', ` +
				`0xdeadbeef, 0x15, 0x0, &(0x7f00000100a0)={[], [], 0x0}, 0x0, ` +
				`&(0x7f0000000200)="$eJwqrqzKTszJSS0CBAAA//8TyQPi")`,
		},
		{
			// Invalid compressed size.
			In: `syz_mount_image$bfs(&(0x7f0000000000)='bfs\x00', &(0x7f0000000100)='./file0\x00', ` +
				`0xdeadbeef, 0xdeadbeef, 0x0, &(0x7f00000100a0)={[], [], 0x0}, 0x0, ` +
				`&(0x7f0000000200)="$eJwqrqzKTszJSS0CBAAA//8TyQPi")`,
			// It should be able to fix up the size.
			Out: `syz_mount_image$bfs(&(0x7f0000000000)='bfs\x00', &(0x7f0000000100)='./file0\x00', ` +
				`0xdeadbeef, 0x15, 0x0, &(0x7f00000100a0)={[], [], 0x0}, 0x0, ` +
				`&(0x7f0000000200)="$eJwqrqzKTszJSS0CBAAA//8TyQPi")`,
		},
	})
}

var flagUpdate = flag.Bool("update", false, "update test files accordingly to current results")

func TestExtractSyzMountImage(t *testing.T) {
	target, err := prog.GetTarget(targets.Linux, targets.AMD64)
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
		if !strings.HasSuffix(file, ".in") {
			continue
		}
		sourceProg, err := os.ReadFile(file)
		if err != nil {
			t.Fatal(err)
		}
		p, err := target.Deserialize(sourceProg, prog.NonStrict)
		if err != nil {
			t.Fatalf("failed to deserialize %s: %s", file, err)
		}
		base := strings.TrimSuffix(file, ".in")
		for _, asset := range p.ExtractAssets() {
			if asset.Type != prog.MountInRepro {
				continue
			}
			outFilePath := fmt.Sprintf("%s.out%d", base, asset.Call)
			var testResult []byte
			if asset.Reader != nil {
				var err error
				testResult, err = io.ReadAll(asset.Reader)
				if err != nil {
					t.Fatal(err)
				}
			}
			if *flagUpdate && asset.Reader != nil {
				err := osutil.WriteFile(outFilePath, testResult)
				if err != nil {
					t.Fatal(err)
				}
			}
			outExists := osutil.IsExist(outFilePath)
			if !outExists && asset.Reader != nil {
				t.Fatalf("#%d: mount found, but does not exist in the answer", asset.Call)
			}
			if testResult != nil {
				testedOutFiles = append(testedOutFiles, outFilePath)
				outFile, err := os.ReadFile(outFilePath)
				if err != nil {
					t.Fatal(err)
				}
				if !reflect.DeepEqual(testResult, outFile) {
					t.Fatalf("output not equal:\nWant: %x\nGot: %x", outFile, testResult)
				}
			}
		}
	}
	sort.Strings(testedOutFiles)
	sort.Strings(allOutFiles)
	if !reflect.DeepEqual(testedOutFiles, allOutFiles) {
		t.Fatalf("all out files: %v\ntested files: %v", allOutFiles, testedOutFiles)
	}
}
