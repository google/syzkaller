// Copyright 2024 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package manager

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/google/syzkaller/pkg/mgrconfig"
	"github.com/google/syzkaller/pkg/osutil"
	"github.com/google/syzkaller/pkg/report"
	"github.com/google/syzkaller/pkg/repro"
	"github.com/google/syzkaller/pkg/subsystem"
	"github.com/google/syzkaller/prog"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestCrashList(t *testing.T) {
	crashStore := &CrashStore{
		BaseDir:      t.TempDir(),
		MaxCrashLogs: 10,
	}

	first, err := crashStore.SaveCrash(&Crash{Report: &report.Report{
		Title:  "Title A",
		Output: []byte("ABCD"),
	}})
	assert.NoError(t, err)
	assert.True(t, first)
	for i := range 2 {
		first, err := crashStore.SaveCrash(&Crash{Report: &report.Report{
			Title:  "Title B",
			Output: []byte("ABCD"),
		}})
		assert.NoError(t, err)
		assert.Equal(t, i == 0, first)
	}
	for i := range 3 {
		first, err := crashStore.SaveCrash(&Crash{Report: &report.Report{
			Title:  "Title C",
			Output: []byte("ABCD"),
		}})
		assert.NoError(t, err)
		assert.Equal(t, i == 0, first)
	}

	list, err := crashStore.BugList()
	assert.NoError(t, err)
	assert.Len(t, list, 3)

	assert.Equal(t, "Title A", list[0].Title)
	assert.Len(t, list[0].Crashes, 1)
	assert.Equal(t, "Title B", list[1].Title)
	assert.Len(t, list[1].Crashes, 2)
	assert.Equal(t, "Title C", list[2].Title)
	assert.Len(t, list[2].Crashes, 3)
}

func TestEmptyCrashList(t *testing.T) {
	crashStore := &CrashStore{
		BaseDir:      t.TempDir(),
		MaxCrashLogs: 10,
	}
	_, err := crashStore.BugList()
	assert.NoError(t, err)
}

func TestMaxCrashLogs(t *testing.T) {
	crashStore := &CrashStore{
		BaseDir:      t.TempDir(),
		MaxCrashLogs: 5,
	}

	for range 20 {
		_, err := crashStore.SaveCrash(&Crash{Report: &report.Report{
			Title:  "Title A",
			Output: []byte("ABCD"),
		}})
		assert.NoError(t, err)
	}

	info, err := crashStore.BugInfo(crashHash("Title A"), false)
	assert.NoError(t, err)
	assert.Len(t, info.Crashes, 5)
}

func TestCrashRepro(t *testing.T) {
	crashStore := &CrashStore{
		Tag:          "abcd",
		BaseDir:      t.TempDir(),
		MaxCrashLogs: 5,
	}

	_, err := crashStore.SaveCrash(&Crash{Report: &report.Report{
		Title:  "Some title",
		Output: []byte("Some output"),
	}})
	assert.NoError(t, err)

	err = crashStore.SaveRepro(&ReproResult{
		Repro: &repro.Result{
			Report: &report.Report{
				Title:  "Some title",
				Report: []byte("Some report"),
			},
			Prog: &prog.Prog{},
		},
	}, []byte("prog text"), []byte("c prog text"))
	assert.NoError(t, err)

	report, err := crashStore.Report(crashHash("Some title"))
	assert.NoError(t, err)
	assert.Equal(t, "Some title", report.Title)
	assert.Equal(t, "abcd", report.Tag)
	assert.Equal(t, []byte("prog text"), report.Prog)
	assert.Equal(t, []byte("c prog text"), report.CProg)
	assert.Equal(t, []byte("Some report"), report.Report)
}

func TestCrashMemoryDump(t *testing.T) {
	crashStore := &CrashStore{
		BaseDir:      t.TempDir(),
		MaxCrashLogs: 5,
	}

	tmpDir := t.TempDir()
	sourceDump := filepath.Join(tmpDir, "vmcore_source")
	osutil.WriteFile(sourceDump, []byte("VMCORE"))

	_, err := crashStore.SaveCrash(&Crash{
		Report: &report.Report{
			Title:  "Title With Dump",
			Output: []byte("Output"),
		},
		MemoryDump: sourceDump,
	})
	assert.NoError(t, err)

	info, err := crashStore.BugInfo(crashHash("Title With Dump"), false)
	assert.NoError(t, err)

	assert.NotEmpty(t, info.MemoryDumpFile)
	assert.Contains(t, info.MemoryDumpFile, "vmcore")
	assert.FileExists(t, filepath.Join(crashStore.BaseDir, info.MemoryDumpFile))
}

func TestGetSubsystems(t *testing.T) {
	tests := []struct {
		testFile string
		want     []string
	}{
		{testFile: "0", want: []string{"block"}},
		{testFile: "1", want: nil},
		{testFile: "2", want: []string{"input", "usb"}},
		{testFile: "3", want: []string{"mm"}},
	}

	reproter, err := report.NewReporter(&mgrconfig.Config{
		Derived: mgrconfig.Derived{TargetOS: "linux", TargetArch: "amd64"},
	})
	if err != nil {
		t.Fatal(err)
	}

	subsystems := []*subsystem.Subsystem{
		{
			Name:      "block",
			PathRules: []subsystem.PathRule{{IncludeRegexp: "^block/"}},
		},
		{
			Name:      "mm",
			PathRules: []subsystem.PathRule{{IncludeRegexp: "^mm/"}},
		},
		{
			Name:      "input",
			PathRules: []subsystem.PathRule{{IncludeRegexp: "^drivers/hid/"}},
		},
		{
			Name:      "usb",
			PathRules: []subsystem.PathRule{{IncludeRegexp: "^drivers/usb/"}, {IncludeRegexp: "^drivers/hid/usbhid/"}},
		},
	}

	for _, tt := range tests {
		t.Run(tt.testFile, func(t *testing.T) {
			reportBytes, err := os.ReadFile(filepath.Join("testdata", tt.testFile))
			if err != nil {
				t.Fatal(err)
			}

			crashStore := &CrashStore{
				BaseDir:      t.TempDir(),
				MaxCrashLogs: 10,
				subsystems:   make(map[string][]string),
				Extractor:    subsystem.MakeExtractor(subsystems),
				Reporter:     reproter,
			}

			title := "Some Title"
			_, err = crashStore.SaveCrash(&Crash{
				Report: &report.Report{
					Title:  title,
					Report: reportBytes,
				},
			})
			if err != nil {
				t.Fatal(err)
			}

			id := crashHash(title)
			dir := crashStore.path(title)
			got, err := crashStore.getSubsystems(id, dir, title)
			if err != nil {
				t.Fatal(err)
			}
			require.Equal(t, tt.want, got)
		})
	}
}
