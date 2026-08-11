// Copyright 2026 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

// Package syzspec provides virtual filesystem abstractions and seed program
// utilities for syzkaller files.
package syzspec

import (
	"errors"
	"io/fs"
	"os"
	"path"
	"path/filepath"
	"slices"
	"strings"
)

const autoTxt = "auto.txt"

// IsAutoTxt reports whether name or its base filename is an auto-generated description file
// ("auto.txt" or "auto.txt.const").
func IsAutoTxt(name string) bool {
	base := filepath.Base(filepath.ToSlash(name))
	return base == autoTxt || base == autoTxt+".const"
}

// SyzFS provides a filesystem view of syzkaller files for a specific OS target
// from local repository directories.
type SyzFS struct {
	syzkallerDir string
	osTarget     string
}

// OSTarget returns the OS target for which syzkaller files are scoped in this SyzFS instance.
func (s *SyzFS) OSTarget() string {
	return s.osTarget
}

// SyzkallerPath returns the root syzkaller directory for this SyzFS instance.
func (s *SyzFS) SyzkallerPath() string {
	return s.syzkallerDir
}

// NewSyzFS creates a SyzFS instance for the given syzkaller directory and OS target.
// Files are loaded from disk under executor/, docs/, and sys/<osTarget>/.
func NewSyzFS(syzkallerDir, osTarget string) *SyzFS {
	normalizedOS := strings.ToLower(osTarget)
	if normalizedOS == "" {
		panic("syzspec: osTarget cannot be empty")
	}

	return &SyzFS{
		syzkallerDir: syzkallerDir,
		osTarget:     normalizedOS,
	}
}

func (s *SyzFS) resolvePath(name string) string {
	name = filepath.ToSlash(filepath.Clean(name))
	if isLocalSyzFile(name) {
		return filepath.Join(s.syzkallerDir, name)
	}
	return filepath.Join(s.syzkallerDir, "sys", s.osTarget, name)
}

func withResolvedPath[T any](s *SyzFS, name, op string, fn func(string) (T, error)) (T, error) {
	if !fs.ValidPath(name) {
		var zero T
		return zero, &fs.PathError{Op: op, Path: name, Err: errors.New("invalid file path")}
	}
	resolved := s.resolvePath(name)
	if IsAutoTxt(resolved) {
		var zero T
		return zero, &fs.PathError{
			Op:   op,
			Path: name,
			Err:  errors.New("access to auto.txt or auto.txt.const is disallowed"),
		}
	}
	res, err := fn(resolved)
	if pathErr, ok := errors.AsType[*os.PathError](err); ok {
		pathErr.Path = name
	}
	return res, err
}

// Open opens the named file from the SyzFS filesystem.
func (s *SyzFS) Open(name string) (fs.File, error) {
	return withResolvedPath(s, name, "open", func(p string) (fs.File, error) {
		return os.Open(p)
	})
}

// ReadFile reads and returns the contents of the file at the specified path from the SyzFS filesystem.
// It validates and cleans the path before reading.
func (s *SyzFS) ReadFile(file string) ([]byte, error) {
	return withResolvedPath[[]byte](s, s.CleanPath(file), "readfile", os.ReadFile)
}

// ReadDir reads the named directory from the SyzFS filesystem, returning all
// its directory entries.
func (s *SyzFS) ReadDir(name string) ([]fs.DirEntry, error) {
	return withResolvedPath[[]fs.DirEntry](s, name, "readdir", os.ReadDir)
}

// CleanPath normalizes the given file path by removing redundant elements,
// stripping any syzkaller prefix or OS target prefix, and converting path
// separators to forward slashes.
func (s *SyzFS) CleanPath(file string) string {
	if file == "" {
		return ""
	}
	cleaned := filepath.Clean(file)
	if filepath.IsAbs(cleaned) && s.syzkallerDir != "" {
		rel, err := filepath.Rel(s.syzkallerDir, cleaned)
		if err == nil && !strings.HasPrefix(rel, "..") {
			cleaned = rel
		}
	}
	cleaned = filepath.ToSlash(cleaned)
	if isLocalSyzFile(cleaned) {
		return cleaned
	}
	for _, prefix := range []string{"sys/" + s.osTarget, s.osTarget, "sys"} {
		if suffix, ok := strings.CutPrefix(cleaned, prefix+"/"); ok {
			cleaned = suffix
			break
		} else if cleaned == prefix {
			cleaned = ""
			break
		}
	}
	return cleaned
}

// DescriptionFiles returns the list of syzlang description files (e.g. sys.txt)
// for this SyzFS instance.
func (s *SyzFS) DescriptionFiles() []string {
	entries, err := s.ReadDir(".")
	if err != nil {
		return nil
	}
	var files []string
	for _, ent := range entries {
		if ent.IsDir() || IsAutoTxt(ent.Name()) {
			continue
		}
		files = append(files, ent.Name())
	}
	slices.Sort(files)
	return files
}

// TestSeeds returns the list of test seed files (e.g. test/syz_mount_...) for
// this SyzFS instance.
func (s *SyzFS) TestSeeds() []string {
	entries, err := s.ReadDir("test")
	if err != nil {
		return nil
	}
	var files []string
	for _, ent := range entries {
		if !ent.IsDir() {
			files = append(files, path.Join("test", ent.Name()))
		}
	}
	slices.Sort(files)
	return files
}

var localSyzDirs = []string{"executor", "docs"}

func isLocalSyzFile(file string) bool {
	for _, dir := range localSyzDirs {
		if file == dir || strings.HasPrefix(file, dir+"/") {
			return true
		}
	}
	return false
}
