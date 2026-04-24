// Copyright 2024 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package clangtool

import (
	"bytes"
	"crypto/sha256"
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

	"github.com/google/syzkaller/pkg/osutil"
)

type Config struct {
	Tool       string // one of compiled-in tool names
	KernelSrc  string
	KernelObj  string
	CacheFile  string
	Files      []string // optional list of files to run the tool on
	// If Fallback is true, the tool will try to generate a compile command for files
	// that are missing from the compilation database, using the first available command as a template.
	Fallback   bool
	DebugTrace io.Writer
}


type OutputDataPtr[T any] interface {
	*T
	Merge(*T, *Verifier)
	SetSourceFile(string, func(filename string) string)
	Finalize(*Verifier)
}

// Run runs the clang tool on all files in the compilation database
// in the kernel build dir and returns combined output for all files.
// It always caches results, and optionally reuses previously cached results.
// It also returns a list of files that were requested but not found in the compilation database.
func Run[Output any, OutputPtr OutputDataPtr[Output]](cfg *Config) (OutputPtr, []string, error) {
	if cfg.CacheFile != "" {
		out, err := osutil.ReadJSON[OutputPtr](cfg.CacheFile)
		if err == nil {
			return out, nil, nil
		}
	}

	dbFile := filepath.Join(cfg.KernelObj, "compile_commands.json")
	cmds, err := loadCompileCommands(dbFile)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to load compile commands: %w", err)
	}

	// User requested to remove relocation logic and rely on correct paths.


	// Find a template command for fallback (if enabled).
	// We use the first valid command as a template.
	var templateCmd *compileCommand
	if len(cmds) > 0 {
		templateCmd = &cmds[0]
	}



	// If files lists is empty, we process all commands.
	var missingFiles []string
	cmdsModified := false

	if len(cfg.Files) != 0 {
		cmdsModified = true

		filesMap := make(map[string]bool)
		for _, f := range cfg.Files {
			abs, err := filepath.Abs(filepath.Join(cfg.KernelSrc, f))
			if err == nil {
				filesMap[abs] = true
			} else {
				filesMap[filepath.Clean(f)] = true
			}
		}
		if cfg.DebugTrace != nil {
			fmt.Fprintf(cfg.DebugTrace, "Filtering for files: %+v\n", cfg.Files)
			fmt.Fprintf(cfg.DebugTrace, "Absolute filesMap: %+v\n", filesMap)
		}
		cmds = slices.DeleteFunc(cmds, func(cmd compileCommand) bool {
			absFile := cmd.File
			if !filepath.IsAbs(absFile) {
				absFile = filepath.Join(cmd.Directory, absFile)
			}
			absFile = filepath.Clean(absFile)
			if filesMap[absFile] {
				return false
			}
			// Try matching against KernelSrc too if relative
			if !filepath.IsAbs(cmd.File) {
				absFile = filepath.Clean(filepath.Join(cfg.KernelSrc, cmd.File))
				if filesMap[absFile] {
					return false
				}
			}
			// Fallback for container mounts: try matching the suffix.
			// If absFile ends with / + relative path of any of our target files, it's a match.
			for relF := range filesMap {
				// Extract the relative part if it was absolute
				rf := relF
				if rel, err := filepath.Rel(cfg.KernelSrc, relF); err == nil {
					rf = rel
				}
				suffix := "/" + filepath.Clean(rf)
				if strings.HasSuffix(absFile, suffix) {
					return false
				}
			}
			return true
		})

		// Check if any requested files were filtered out (not in the DB).
		// We still want to run the tool on them (it might have fallback logic).
		found := make(map[string]bool)
		for _, cmd := range cmds {
			absFile := cmd.File
			if !filepath.IsAbs(absFile) {
				absFile = filepath.Join(cmd.Directory, absFile)
			}
			found[filepath.Clean(absFile)] = true
		}

		for _, f := range cfg.Files {
			abs, err := filepath.Abs(filepath.Join(cfg.KernelSrc, f))
			if err != nil {
				continue
			}
			abs = filepath.Clean(abs)
			if !found[abs] {
				if cfg.DebugTrace != nil {
					fmt.Fprintf(cfg.DebugTrace, "Force adding missing file: %s\n", f)
				}
				missingFiles = append(missingFiles, f)

				// Create a dummy command to force execution.
				// Heuristic: Use the first available command as a template if possible,
				// assuming flags are somewhat compatible.
				if cfg.Fallback && templateCmd != nil {
					if cfg.DebugTrace != nil {
						fmt.Fprintf(cfg.DebugTrace,
							"File %s is missing from compile_commands.json, creating fallback command.\n", f)
					}
					fallback := *templateCmd
					fallback.File = f
					cmds = append(cmds, fallback)
				} else {
					if cfg.DebugTrace != nil {
						fmt.Fprintf(cfg.DebugTrace, "File %s is missing from compile_commands.json, skipping static analysis.\n", f)
					}
				}



			}
		}

		if cfg.DebugTrace != nil {
			fmt.Fprintf(cfg.DebugTrace, "Found %d matching commands (after forcing)\n", len(cmds))
		}
	}

	// ALWAYS write the (potentially modified/filtered) commands to a temp directory,
	// UNLESS we are processing the original DB as-is (no filtering, no fallback additions).
	if cmdsModified {
		tmpDir, err := os.MkdirTemp("", "compile_commands_*")
		if err == nil {
			defer os.RemoveAll(tmpDir)
			tmpDb := filepath.Join(tmpDir, "compile_commands.json")
			data, err := json.Marshal(cmds)
			if err == nil {
				if err := os.WriteFile(tmpDb, data, 0644); err == nil {
					dbFile = tmpDir // -p expects directory
					if cfg.DebugTrace != nil {
						fmt.Fprintf(cfg.DebugTrace, "Using temporary compilation database: %s\n", dbFile)
					}
				}
			}
		}
	} else {
		// Use the directory containing the original compile_commands.json
		dbFile = filepath.Dir(dbFile)
		if cfg.DebugTrace != nil {
			fmt.Fprintf(cfg.DebugTrace, "Using original compilation database: %s\n", dbFile)
		}
	}


	type result struct {
		out OutputPtr
		err error
	}
	results := make(chan *result, 10)
	files := make(chan string, len(cmds))
	for range runtime.NumCPU() {
		go func() {
			for file := range files {
				out, err := runTool[Output, OutputPtr](cfg, dbFile, file)
				results <- &result{out, err}
			}
		}()
	}
	for _, cmd := range cmds {
		files <- cmd.File
	}
	close(files)

	v := NewVerifier(cfg.KernelSrc, cfg.KernelObj)
	out := OutputPtr(new(Output))
	for range cmds {
		res := <-results
		if res.err != nil {
			return nil, nil, res.err
		}
		out.Merge(res.out, v)
	}
	// Finalize the output (sort, dedup, etc), and let the output verify
	// that all source file names, line numbers, etc are valid/present.
	// If there are any bogus entries, it's better to detect them early,
	// than to crash/error much later when the info is used.
	// Some of the source files (generated) may be in the obj dir.
	out.Finalize(v)
	if err := v.Error(); err != nil {
		return nil, nil, err
	}
	if cfg.CacheFile != "" {
		osutil.MkdirAll(filepath.Dir(cfg.CacheFile))
		data, err := json.MarshalIndent(out, "", "\t")
		if err != nil {
			return nil, nil, fmt.Errorf("failed to marshal output data: %w", err)
		}
		if err := osutil.WriteFile(cfg.CacheFile, data); err != nil {
			return nil, nil, err
		}
	}
	return out, missingFiles, nil
}

type Verifier struct {
	srcDirs   []string
	fileCache map[string]int // file->line count (-1 is cached for missing files)
	err       strings.Builder
}

func NewVerifier(src ...string) *Verifier {
	return &Verifier{
		srcDirs:   src,
		fileCache: make(map[string]int),
	}
}

func (v *Verifier) Error() error {
	if v.err.Len() == 0 {
		return nil
	}
	return errors.New(v.err.String())
}

func (v *Verifier) Filename(file string) {
	if _, ok := v.fileCache[file]; ok {
		return
	}
	for _, srcDir := range v.srcDirs {
		data, err := os.ReadFile(filepath.Join(srcDir, file))
		if err != nil {
			continue
		}
		v.fileCache[file] = len(bytes.Split(data, []byte{'\n'}))
		return
	}
	v.fileCache[file] = -1
	fmt.Fprintf(&v.err, "missing file: %v (src dirs %+v)\n", file, v.srcDirs)
}

func (v *Verifier) LineRange(file string, start, end int) {
	v.Filename(file)
	lines, ok := v.fileCache[file]
	if !ok || lines < 0 {
		return
	}
	// Line numbers produced by clang are 1-based.
	if start <= 0 || end < start || end > lines {
		fmt.Fprintf(&v.err, "bad line range [%v-%v] for file %v with %v lines\n",
			start, end, file, lines)
	}
}

func runTool[Output any, OutputPtr OutputDataPtr[Output]](cfg *Config, dbFile, file string) (OutputPtr, error) {
	relFile := strings.TrimPrefix(strings.TrimPrefix(strings.TrimPrefix(filepath.Clean(file),
		cfg.KernelSrc), cfg.KernelObj), "/")
	// Suppress warning since we may build the tool on a different clang
	// version that produces more warnings.
	// Comments are needed for codesearch tool, but may be useful for declextract
	// in the future if we try to parse them with LLMs.
	absToolFile := file
	if !filepath.IsAbs(absToolFile) {
		absToolFile = filepath.Join(cfg.KernelSrc, file)
	}

	cmd := exec.Command(osutil.Abs(os.Args[0]), "-p", dbFile,
		"--extra-arg=-w", "--extra-arg=-fparse-all-comments", absToolFile)
	cmd.Dir = cfg.KernelObj
	// This tells the C++ clang tool to execute in a constructor.
	cmd.Env = append([]string{fmt.Sprintf("%v=%v", runToolEnv, cfg.Tool)}, os.Environ()...)
	cmd.Stderr = os.Stderr
	data, err := cmd.Output()
	if err != nil {
		var exitErr *exec.ExitError
		if errors.As(err, &exitErr) {
			err = fmt.Errorf("%v: %w\n%s", relFile, err, exitErr.Stderr)
		}
		return nil, err
	}
	out, err := osutil.ParseJSON[OutputPtr](data)
	if err != nil {
		return nil, err
	}
	// All includes in the tool output are relative to the build dir.
	// Make them relative to the source dir.
	out.SetSourceFile(relFile, func(filename string) string {
		rel, err := filepath.Rel(cfg.KernelSrc, filepath.Join(cfg.KernelObj, filename))
		if err == nil && filename != "" {
			return rel
		}
		return filename
	})
	return out, nil
}

const runToolEnv = "SYZ_RUN_CLANGTOOL"

func init() {
	// The C++ clang tool was supposed to intercept execution in a constructor,
	// execute and exit. If we got here with the env var set, something is wrong.
	if name := os.Getenv(runToolEnv); name != "" {
		panic(fmt.Sprintf("clang tool %q is not compiled in", name))
	}
}

type compileCommand struct {
	Command   string `json:"command"`
	Directory string `json:"directory"`
	File      string `json:"file"`
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

func SortAndDedupSlice[Slice ~[]E, E comparable](s Slice) Slice {
	dedup := make(map[[sha256.Size]byte]E)
	text := make(map[E][]byte)
	for _, e := range s {
		t, _ := json.Marshal(e)
		dedup[sha256.Sum256(t)] = e
		text[e] = t
	}
	s = make([]E, 0, len(dedup))
	for _, e := range dedup {
		s = append(s, e)
	}
	slices.SortFunc(s, func(a, b E) int {
		return bytes.Compare(text[a], text[b])
	})
	return s
}
