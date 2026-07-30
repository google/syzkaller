// Copyright 2026 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

// Package syzspec provides virtual filesystem abstractions and seed program
// utilities for syzkaller files.
package syzspec

import (
	"bufio"
	"bytes"
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
	if name == "skills" || strings.HasPrefix(name, "skills/") {
		suffix := strings.TrimPrefix(name, "skills")
		return filepath.Join(s.syzkallerDir, "docs", s.osTarget, "skills", suffix)
	}
	if isLocalSyzFile(name) {
		return filepath.Join(s.syzkallerDir, name)
	}
	return filepath.Join(s.syzkallerDir, "sys", s.osTarget, name)
}

func (s sysDirFS) Open(name string) (fs.File, error) {
	if !fs.ValidPath(name) {
		return nil, &fs.PathError{Op: "open", Path: name, Err: fs.ErrInvalid}
	}
	fullPath := s.resolvePath(name)
	return os.Open(fullPath)
}

func (s sysDirFS) ReadFile(name string) ([]byte, error) {
	if !fs.ValidPath(name) {
		return nil, &fs.PathError{Op: "readfile", Path: name, Err: fs.ErrInvalid}
	}
	fullPath := s.resolvePath(name)
	return os.ReadFile(fullPath)
}

func (s sysDirFS) ReadDir(name string) ([]fs.DirEntry, error) {
	if !fs.ValidPath(name) {
		return nil, &fs.PathError{Op: "readdir", Path: name, Err: fs.ErrInvalid}
	}
	fullPath := s.resolvePath(name)
	return os.ReadDir(fullPath)
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
	if suffix, ok := strings.CutPrefix(cleaned, "sys/"+s.osTarget+"/"); ok {
		cleaned = suffix
	} else if suffix, ok := strings.CutPrefix(cleaned, s.osTarget+"/"); ok {
		cleaned = suffix
	} else if suffix, ok := strings.CutPrefix(cleaned, "sys/"); ok {
		cleaned = suffix
	}
	return cleaned
}

func (s *SyzFS) resolveSkillPath(file string) (string, bool) {
	cleaned := filepath.ToSlash(filepath.Clean(file))
	for _, prefix := range []string{"docs/" + s.osTarget + "/skills/", s.osTarget + "/skills/", "skills/"} {
		if suffix, ok := strings.CutPrefix(cleaned, prefix); ok {
			cleaned = suffix
			break
		}
	}
	if strings.Contains(cleaned, "/") || strings.Contains(cleaned, "..") || !strings.HasSuffix(cleaned, ".md") {
		return "", false
	}
	if s.syzkallerPath == "" {
		return "", false
	}
	fullPath := path.Join("docs", s.osTarget, "skills", cleaned)
	diskPath := filepath.Join(s.syzkallerPath, fullPath)
	if _, err := os.Stat(diskPath); err == nil {
		return fullPath, true
	}
	return "", false
}

// Open opens the named file from the SyzFS filesystem.
func (s *SyzFS) Open(name string) (fs.File, error) {
	if skillRel, ok := s.resolveSkillPath(name); ok {
		return os.Open(filepath.Join(s.syzkallerPath, skillRel))
	}
	return s.FS.Open(name)
}

// ReadFile reads and returns the contents of the file at the specified path from the SyzFS filesystem.
// It validates and cleans the path before reading.
func (s *SyzFS) ReadFile(file string) ([]byte, error) {
	if skillRel, ok := s.resolveSkillPath(file); ok {
		return os.ReadFile(filepath.Join(s.syzkallerPath, skillRel))
	}
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

type SkillInfo struct {
	Name        string
	Description string
}

func (s *SyzFS) ListSkills() ([]SkillInfo, error) {
	entries, err := s.ReadDir("skills")
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return nil, nil
		}
		return nil, err
	}
	var skills []SkillInfo
	for _, ent := range entries {
		if ent.IsDir() || ent.Name() == "README.md" || !strings.HasSuffix(ent.Name(), ".md") {
			continue
		}
		name := strings.TrimSuffix(ent.Name(), ".md")
		desc := name
		if data, err := s.ReadFile(ent.Name()); err == nil {
			if n, d, ok := parseYAMLFrontmatter(data); ok {
				if n != "" {
					name = n
				}
				if d != "" {
					desc = d
				}
			}
		}
		skills = append(skills, SkillInfo{
			Name:        name,
			Description: desc,
		})
	}
	slices.SortFunc(skills, func(a, b SkillInfo) int {
		return strings.Compare(a.Name, b.Name)
	})
	return skills, nil
}

func parseYAMLFrontmatter(data []byte) (name, desc string, ok bool) {
	scanner := bufio.NewScanner(bytes.NewReader(data))
	inFrontmatter := false
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "---" {
			if !inFrontmatter {
				inFrontmatter = true
				continue
			}
			return name, desc, true
		}
		if inFrontmatter {
			if val, found := strings.CutPrefix(line, "name:"); found {
				name = strings.TrimSpace(val)
			} else if val, found := strings.CutPrefix(line, "description:"); found {
				desc = strings.TrimSpace(val)
			}
		}
	}
	return "", "", false
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
