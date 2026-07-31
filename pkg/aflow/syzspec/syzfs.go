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

	"github.com/google/syzkaller/pkg/aflow"
)

const autoTxt = "auto.txt"

// IsAutoTxt reports whether name is an auto-generated description file ("auto.txt" or "auto.txt.const").
func IsAutoTxt(name string) bool {
	return name == autoTxt || name == autoTxt+".const"
}

// SyzFS provides a filesystem view of syzkaller files for a specific OS target
// from local repository directories.
type SyzFS struct {
	fs.FS
	osTarget      string
	syzkallerPath string
}

// OSTarget returns the OS target for which syzkaller files are scoped in this SyzFS instance.
func (s *SyzFS) OSTarget() string {
	return s.osTarget
}

// SyzkallerPath returns the root syzkaller directory for this SyzFS instance.
func (s *SyzFS) SyzkallerPath() string {
	return s.syzkallerPath
}

// ReadDir reads the named directory from the SyzFS filesystem, returning all
// its directory entries.
func (s *SyzFS) ReadDir(dir string) ([]fs.DirEntry, error) {
	return fs.ReadDir(s.FS, dir)
}

// NewSyzFS creates a SyzFS instance for the given syzkaller directory and OS target.
// Files are loaded from disk under executor/, docs/, and sys/<osTarget>/.
func NewSyzFS(syzkallerDir, osTarget string) *SyzFS {
	normalizedOS := strings.ToLower(osTarget)
	if normalizedOS == "" {
		panic("syzspec: osTarget cannot be empty")
	}

	return &SyzFS{
		FS: sysDirFS{
			syzkallerDir: syzkallerDir,
			osTarget:     normalizedOS,
		},
		osTarget:      normalizedOS,
		syzkallerPath: syzkallerDir,
	}
}

type sysDirFS struct {
	syzkallerDir string
	osTarget     string
}

func (s sysDirFS) resolvePath(name string) string {
	name = filepath.ToSlash(filepath.Clean(name))
	if isLocalSyzFile(name) {
		return filepath.Join(s.syzkallerDir, name)
	}
	return filepath.Join(s.syzkallerDir, "sys", s.osTarget, name)
}

func (s sysDirFS) Open(name string) (fs.File, error) {
	return withResolvedPath(s, name, "open", func(p string) (fs.File, error) {
		return os.Open(p)
	})
}

func (s sysDirFS) ReadFile(name string) ([]byte, error) {
	return withResolvedPath[[]byte](s, name, "readfile", os.ReadFile)
}

func (s sysDirFS) ReadDir(name string) ([]fs.DirEntry, error) {
	return withResolvedPath[[]fs.DirEntry](s, name, "readdir", os.ReadDir)
}

func withResolvedPath[T any](s sysDirFS, name, op string, fn func(string) (T, error)) (T, error) {
	if !fs.ValidPath(name) {
		var zero T
		return zero, &fs.PathError{Op: op, Path: name, Err: fs.ErrInvalid}
	}
	res, err := fn(s.resolvePath(name))
	if pathErr, ok := errors.AsType[*os.PathError](err); ok {
		pathErr.Path = name
	}
	return res, err
}

// CleanPath normalizes the given file path by removing redundant elements,
// stripping any syzkaller prefix or OS target prefix, and converting path
// separators to forward slashes.
func (s *SyzFS) CleanPath(file string) string {
	if file == "" {
		return ""
	}
	cleaned := filepath.Clean(file)
	if filepath.IsAbs(cleaned) && s.syzkallerPath != "" {
		rel, err := filepath.Rel(s.syzkallerPath, cleaned)
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

// ReadFile reads and returns the contents of the file at the specified path from the SyzFS filesystem.
// It validates and cleans the path before reading.
func (s *SyzFS) ReadFile(file string) ([]byte, error) {
	cleanedFile := s.CleanPath(file)

	if strings.HasPrefix(cleanedFile, "..") || filepath.IsAbs(cleanedFile) {
		return nil, aflow.BadCallError("invalid file path %q", file)
	}

	// Disallow auto.txt or auto.txt.const.
	if IsAutoTxt(cleanedFile) {
		return nil, aflow.BadCallError("access to auto.txt or auto.txt.const is disallowed")
	}

	if cleanedFile == "" {
		return nil, nil
	}
	return fs.ReadFile(s.FS, cleanedFile)
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

func isLocalSyzFile(file string) bool {
	return file == "executor" || strings.HasPrefix(file, "executor/") ||
		file == "docs" || strings.HasPrefix(file, "docs/")
}
