// Copyright 2022 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package linux

import (
	"flag"
	"fmt"
	"io"
	"math/rand"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/google/syzkaller/pkg/osutil"
	"github.com/google/syzkaller/prog"
	"github.com/google/syzkaller/sys/targets"
)

// nolint: lll
func TestSyzMountImageNeutralize(t *testing.T) {
	prog.TestDeserializeHelper(t, targets.Linux, targets.AMD64, nil, []prog.DeserializeTest{
		{
			// A valid call, nothing should change.
			In: `syz_mount_image$bfs(&(0x7f0000000000)='bfs\x00', &(0x7f0000000100)='./file0\x00', 0x2220, 0x2, &(0x7f0000000200)=[{&(0x7f0000010000)="cefaad1bc0210000ff0f0000ffffffffffffffffffffffffffffffff73797a6b616c73797a6b616c00"/64, 0x40, 0x0}, {&(0x7f0000010040)="0200000011000000140000001f22000002000000ed4100000000000001000000020000005ffb19635ffb19635ffb196300"/64, 0x40, 0x200}], 0x0, &(0x7f00000100a0)={[], [], 0x0}, 0x0)`,
		},
		{
			// Invalid total size.
			In: `syz_mount_image$bfs(&(0x7f0000000000)='bfs\x00', &(0x7f0000000100)='./file1\x00', 0x20, 0x2, &(0x7f0000000200)=[{&(0x7f0000010000)="cefaad1bc0210000ff0f0000ffffffffffffffffffffffffffffffff73797a6b616c73797a6b616c00"/64, 0x40, 0x0}, {&(0x7f0000010040)="0200000011000000140000001f22000002000000ed4100000000000001000000020000005ffb19635ffb19635ffb196300"/64, 0x40, 0x200}], 0x0, &(0x7f00000100a0)={[], [], 0x0}, 0x0)`,
			// It should be able to fix up the size.
			Out: `syz_mount_image$bfs(&(0x7f0000000000)='bfs\x00', &(0x7f0000000100)='./file1\x00', 0x240, 0x2, &(0x7f0000000200)=[{&(0x7f0000010000)="cefaad1bc0210000ff0f0000ffffffffffffffffffffffffffffffff73797a6b616c73797a6b616c00"/64, 0x40, 0x0}, {&(0x7f0000010040)="0200000011000000140000001f22000002000000ed4100000000000001000000020000005ffb19635ffb19635ffb196300"/64, 0x40, 0x200}], 0x0, &(0x7f00000100a0)={[], [], 0x0}, 0x0)`,
		},
		{
			// Invalid offset.
			In: `syz_mount_image$bfs(&(0x7f0000000000)='bfs\x00', &(0x7f0000000100)='./file1\x00', 0x20, 0x2, &(0x7f0000000200)=[{&(0x7f0000010000)="cefaad1bc0210000ff0f0000ffffffffffffffffffffffffffffffff73797a6b616c73797a6b616c00"/64, 0x40, 0x0}, {&(0x7f0000010040)="0200000011000000140000001f22000002000000ed4100000000000001000000020000005ffb19635ffb19635ffb196300"/64, 0x40, 0x9100000}], 0x0, &(0x7f00000100a0)={[], [], 0x0}, 0x0)`,
			// The segment is deleted.
			Out:       `syz_mount_image$bfs(&(0x7f0000000000)='bfs\x00', &(0x7f0000000100)='./file1\x00', 0x40, 0x1, &(0x7f0000000200)=[{&(0x7f0000010000)="cefaad1bc0210000ff0f0000ffffffffffffffffffffffffffffffff73797a6b616c73797a6b616c00"/64, 0x40, 0x0}], 0x0, &(0x7f00000100a0)={[], [], 0x0}, 0x0)`,
			StrictErr: `got filtered out`,
		},
		{
			// Overlapping and unsorted segments.
			In:        `syz_mount_image$bfs(&(0x7f0000000000)='bfs\x00', &(0x7f0000000100)='./file0\x00', 0x2220, 0x3, &(0x7f0000000200)=[{&(0x7f0000010000)="cafef00d"/64, 0x50, 0x20}, {&(0x7f0000010040)="deadbeef"/64, 0x30, 0x10}, {&(0x7f0000010080)="abcdef"/64, 0x40, 0x20}], 0x0, &(0x7f00000100a0)={[], [], 0x0}, 0x0)`,
			Out:       `syz_mount_image$bfs(&(0x7f0000000000)='bfs\x00', &(0x7f0000000100)='./file0\x00', 0x2220, 0x2, &(0x7f0000000200)=[{&(0x7f0000010040)="deadbeef00"/16, 0x10, 0x10}, {&(0x7f0000010000)="cafef00d00"/64, 0x40, 0x20}], 0x0, &(0x7f00000100a0)={[], [], 0x0}, 0x0)`,
			StrictErr: `segments are not sorted`,
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

// nolint: lll
func TestSyzMountImageMutation(t *testing.T) {
	// We cannot unfortunately just import InitTest from prog.
	rs := rand.NewSource(time.Now().UnixNano())
	iters := 100
	target, err := prog.GetTarget("linux", "amd64")
	if err != nil {
		t.Fatal(err)
	}

	var p *prog.Prog
	var ct *prog.ChoiceTable

	const mutateCount = 1000
	const baseProg = `syz_mount_image$bfs(&(0x7f0000000000)='bfs\x00', &(0x7f0000000100)='./file0\x00', 0x2220, 0x2, &(0x7f0000000200)=[{&(0x7f0000010040)="deadbeef00"/16, 0x10, 0x10}, {&(0x7f0000010000)="cafef00d00"/64, 0x40, 0x20}], 0x0, &(0x7f00000100a0)={[], [], 0x0}, 0x0)`

	for i := 0; i < iters; i++ {
		if i%mutateCount == 0 {
			var err error
			p, err = target.Deserialize([]byte(baseProg), prog.NonStrict)
			if err != nil {
				t.Fatal(err)
			}
			ct = target.DefaultChoiceTable()
		}
		p.Mutate(rs, 1, ct, nil, nil)
		// We only call the extraction code and do mutations to catch possible panics.
		// It is absolutely normal for syzkaller to mutate the call to the level when the image can no longer be extracted.
		p.Target.ExtractMountedImage(p.Calls[0])
	}
}
