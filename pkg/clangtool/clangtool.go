// Copyright 2024 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package clangtool

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/rand"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"time"

	"github.com/google/syzkaller/pkg/declextract"
	"github.com/google/syzkaller/pkg/osutil"
)

type Config struct {
	ToolBin    string
	KernelSrc  string
	KernelObj  string
	CacheFile  string
	DebugTrace io.Writer
}

// Run runs the clang tool on all files in the compilation database
// in the kernel build dir and returns combined output for all files.
// It always caches results, and optionally reuses previously cached results.
func Run(cfg *Config) (*declextract.Output, error) {
	if cfg.CacheFile != "" {
		data, err := os.ReadFile(cfg.CacheFile)
		if err == nil {
			out, err := unmarshal(data)
			if err == nil {
				return out, nil
			}
		}
	}

	dbFile := filepath.Join(cfg.KernelObj, "compile_commands.json")
	cmds, err := loadCompileCommands(dbFile)
	if err != nil {
		return nil, fmt.Errorf("failed to load compile commands: %w", err)
	}

	type result struct {
		out *declextract.Output
		err error
	}
	results := make(chan *result, 10)
	files := make(chan string, len(cmds))
	for w := 0; w < runtime.NumCPU(); w++ {
		go func() {
			for file := range files {
				out, err := runTool(cfg, dbFile, file)
				results <- &result{out, err}
			}
		}()
	}
	for _, cmd := range cmds {
		files <- cmd.File
	}
	close(files)

	out := new(declextract.Output)
	for range cmds {
		res := <-results
		if res.err != nil {
			return nil, res.err
		}
		out.Merge(res.out)
	}
	out.SortAndDedup()
	if cfg.CacheFile != "" {
		osutil.MkdirAll(filepath.Dir(cfg.CacheFile))
		data, err := json.MarshalIndent(out, "", "\t")
		if err != nil {
			return nil, fmt.Errorf("failed to marshal output data: %w", err)
		}
		if err := osutil.WriteFile(cfg.CacheFile, data); err != nil {
			return nil, err
		}
	}
	return out, nil
}

func runTool(cfg *Config, dbFile, file string) (*declextract.Output, error) {
	relFile := strings.TrimPrefix(strings.TrimPrefix(strings.TrimPrefix(filepath.Clean(file),
		cfg.KernelSrc), cfg.KernelObj), "/")
	// Suppress warning since we may build the tool on a different clang
	// version that produces more warnings.
	data, err := exec.Command(cfg.ToolBin, "-p", dbFile, "--extra-arg=-w", file).Output()
	if err != nil {
		var exitErr *exec.ExitError
		if errors.As(err, &exitErr) {
			err = fmt.Errorf("%v: %w\n%s", relFile, err, exitErr.Stderr)
		}
		return nil, err
	}
	out, err := unmarshal(data)
	if err != nil {
		return nil, err
	}
	fixupFileNames(cfg, out, relFile)
	return out, nil
}

func unmarshal(data []byte) (*declextract.Output, error) {
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	out := new(declextract.Output)
	if err := dec.Decode(out); err != nil {
		return nil, fmt.Errorf("failed to unmarshal clang tool output: %w\n%s", err, data)
	}
	return out, nil
}

func fixupFileNames(cfg *Config, out *declextract.Output, file string) {
	// All includes in the tool output are relative to the build dir.
	// Make them relative to the source dir.
	out.SetSourceFile(file, func(filename string) string {
		if res, err := filepath.Rel(cfg.KernelSrc, filepath.Join(cfg.KernelObj, filename)); err == nil {
			return res
		}
		return filename
	})
}

type compileCommand struct {
	Command   string
	Directory string
	File      string
}

func loadCompileCommands(dbFile string) ([]compileCommand, error) {
	data, err := os.ReadFile(dbFile)
	if err != nil {
		return nil, err
	}
	var cmds []compileCommand
	if err := json.Unmarshal(data, &cmds); err != nil {
		return nil, err
	}
	// Remove commands that don't relate to the kernel build
	// (probably some host tools, etc).
	cmds = slices.DeleteFunc(cmds, func(cmd compileCommand) bool {
		return !strings.HasSuffix(cmd.File, ".c") ||
			// Files compiled with gcc are not a part of the kernel
			// (assuming compile commands were generated with make CC=clang).
			// They are probably a part of some host tool.
			strings.HasPrefix(cmd.Command, "gcc") ||
			// KBUILD should add this define all kernel files.
			!strings.Contains(cmd.Command, "-DKBUILD_BASENAME")
	})
	// Shuffle the order to detect any non-determinism caused by the order early.
	// The result should be the same regardless.
	rand.New(rand.NewSource(time.Now().UnixNano())).Shuffle(len(cmds), func(i, j int) {
		cmds[i], cmds[j] = cmds[j], cmds[i]
	})
	if len(cmds) == 0 {
		return nil, fmt.Errorf("no kernel compile commands in compile_commands.json" +
			" (was the kernel compiled with gcc?)")
	}
	return cmds, nil
}
