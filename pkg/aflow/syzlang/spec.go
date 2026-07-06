// Copyright 2026 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package syzlang

import (
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing/fstest"

	"github.com/google/syzkaller/pkg/aflow"
	"github.com/google/syzkaller/sys"
	"github.com/google/syzkaller/sys/targets"
)

const autoTxt = "auto.txt"

var (
	syzFS     *SyzFS
	syzFSOnce sync.Once
)

type SyzFS struct {
	fs.FS
	osTarget      string
	syzkallerPath string
}

func (s *SyzFS) OSTarget() string {
	return s.osTarget
}

func NewSyzFS(syzkallerDir, osTarget string) *SyzFS {
	syzFSOnce.Do(func() {
		normalizedOS := strings.ToLower(osTarget)
		if normalizedOS == "" {
			normalizedOS = targets.Linux
		}

		fsMap := make(fstest.MapFS)
		if syzkallerDir == "" {
			// Populate from embedded sys.Files.
			fs.WalkDir(sys.Files, normalizedOS, func(p string, d fs.DirEntry, err error) error {
				if err != nil || d.IsDir() {
					return nil
				}
				if data, err := sys.Files.ReadFile(p); err == nil {
					cleaned := p
					if suffix, ok := strings.CutPrefix(p, normalizedOS+"/"); ok {
						cleaned = suffix
					}
					fsMap[cleaned] = &fstest.MapFile{Data: data}
				}
				return nil
			})
		} else {
			// Populate from local disk.
			walkAndAdd(fsMap, syzkallerDir, "executor")
			walkAndAdd(fsMap, syzkallerDir, "docs")
			// Walk sys/<osTarget>/
			sysOSDir := filepath.Join(syzkallerDir, "sys", normalizedOS)
			filepath.Walk(sysOSDir, func(p string, info os.FileInfo, err error) error {
				if err != nil || info.IsDir() {
					return nil
				}
				rel, err := filepath.Rel(sysOSDir, p)
				if err == nil {
					if data, err := os.ReadFile(p); err == nil {
						fsMap[filepath.ToSlash(rel)] = &fstest.MapFile{
							Data:    data,
							Mode:    info.Mode(),
							ModTime: info.ModTime(),
							Sys:     info.Sys(),
						}
					}
				}
				return nil
			})
		}

		syzFS = &SyzFS{
			FS:            fsMap,
			osTarget:      normalizedOS,
			syzkallerPath: syzkallerDir,
		}
	})
	return syzFS
}

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
	if isLocalSyzlangFile(cleaned) {
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

func (s *SyzFS) ReadFile(file string) ([]byte, error) {
	cleanedFile := s.CleanPath(file)

	if strings.HasPrefix(cleanedFile, "..") || filepath.IsAbs(cleanedFile) {
		return nil, aflow.BadCallError("invalid file path %q", file)
	}

	// Disallow auto.txt or auto.txt.const.
	if cleanedFile == autoTxt || cleanedFile == autoTxt+".const" {
		return nil, aflow.BadCallError("access to auto.txt or auto.txt.const is disallowed")
	}

	if cleanedFile == "" {
		return nil, nil
	}
	return fs.ReadFile(s.FS, cleanedFile)
}

func isLocalSyzlangFile(file string) bool {
	return file == "executor" || strings.HasPrefix(file, "executor/") ||
		file == "docs" || strings.HasPrefix(file, "docs/")
}

func walkAndAdd(fsMap fstest.MapFS, syzkallerDir, dir string) {
	filepath.Walk(filepath.Join(syzkallerDir, dir), func(p string, info os.FileInfo, err error) error {
		if err != nil || info.IsDir() {
			return nil
		}
		rel, _ := filepath.Rel(syzkallerDir, p)
		if data, err := os.ReadFile(p); err == nil {
			fsMap[filepath.ToSlash(rel)] = &fstest.MapFile{
				Data:    data,
				Mode:    info.Mode(),
				ModTime: info.ModTime(),
				Sys:     info.Sys(),
			}
		}
		return nil
	})
}

func ClearFSMap() {
	syzFS = nil
	syzFSOnce = sync.Once{}
}
