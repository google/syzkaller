// Copyright 2025 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package codesearch

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"syscall"

	"github.com/google/syzkaller/pkg/osutil"
)

type Index struct {
	db      *Database
	srcDirs []string
}

type Command struct {
	Name  string
	NArgs int
	Func  func(*Index, []string) (string, error)
}

// Commands are used to run unit tests and for the syz-codesearch tool.
var Commands = []Command{
	{"dir-index", 1, func(index *Index, args []string) (string, error) {
		ok, subdirs, files, err := index.DirIndex(args[0])
		if err != nil || !ok {
			return notFound, err
		}
		b := new(strings.Builder)
		fmt.Fprintf(b, "directory %v subdirs:\n", args[0])
		for _, subdir := range subdirs {
			fmt.Fprintf(b, " - %v\n", subdir)
		}
		fmt.Fprintf(b, "\ndirectory %v files:\n", args[0])
		for _, file := range files {
			fmt.Fprintf(b, " - %v\n", file)
		}
		return b.String(), nil
	}},
	{"file-index", 1, func(index *Index, args []string) (string, error) {
		ok, entities, err := index.FileIndex(args[0])
		if err != nil || !ok {
			return notFound, err
		}
		b := new(strings.Builder)
		fmt.Fprintf(b, "file %v defines the following entities:\n\n", args[0])
		for _, ent := range entities {
			fmt.Fprintf(b, "%v %v\n", ent.Kind, ent.Name)
		}
		return b.String(), nil
	}},
	{"def-comment", 2, func(index *Index, args []string) (string, error) {
		info, err := index.DefinitionComment(args[0], args[1])
		if err != nil || info == nil {
			return notFound, err
		}
		if info.Body == "" {
			return fmt.Sprintf("%v %v is defined in %v and is not commented\n",
				info.Kind, args[1], info.File), nil
		}
		return fmt.Sprintf("%v %v is defined in %v and commented as:\n\n%v",
			info.Kind, args[1], info.File, info.Body), nil
	}},
	{"def-source", 3, func(index *Index, args []string) (string, error) {
		info, err := index.DefinitionSource(args[0], args[1], args[2] == "yes")
		if err != nil || info == nil {
			return notFound, err
		}
		return fmt.Sprintf("%v %v is defined in %v:\n\n%v", info.Kind, args[1], info.File, info.Body), nil
	}},
}

var SourceExtensions = map[string]bool{".c": true, ".h": true, ".S": true, ".rs": true}

const notFound = "not found\n"

func NewIndex(databaseFile string, srcDirs []string) (*Index, error) {
	db, err := osutil.ReadJSON[*Database](databaseFile)
	if err != nil {
		return nil, err
	}
	return &Index{
		db:      db,
		srcDirs: srcDirs,
	}, nil
}

func (index *Index) Command(cmd string, args []string) (string, error) {
	for _, meta := range Commands {
		if cmd == meta.Name {
			if len(args) != meta.NArgs {
				return "", fmt.Errorf("codesearch command %v requires %v args, but %v provided",
					cmd, meta.NArgs, len(args))
			}
			return meta.Func(index, args)
		}
	}
	return "", fmt.Errorf("unknown codesearch command %v", cmd)
}

type Entity struct {
	Kind string
	Name string
}

func (index *Index) DirIndex(dir string) (bool, []string, []string, error) {
	if err := escaping(dir); err != nil {
		return false, nil, nil, nil
	}
	exists := false
	var subdirs, files []string
	for _, root := range index.srcDirs {
		exists1, subdirs1, files1, err := dirIndex(root, dir)
		if err != nil {
			return false, nil, nil, err
		}
		if exists1 {
			exists = true
		}
		subdirs = append(subdirs, subdirs1...)
		files = append(files, files1...)
	}
	slices.Sort(subdirs)
	slices.Sort(files)
	// Dedup dirs across src/build trees,
	// also dedup files, but hopefully there are no duplicates.
	subdirs = slices.Compact(subdirs)
	files = slices.Compact(files)
	return exists, subdirs, files, nil
}

func (index *Index) FileIndex(file string) (bool, []Entity, error) {
	var entities []Entity
	for _, def := range index.db.Definitions {
		if def.Body.File == file {
			entities = append(entities, Entity{
				Kind: def.Kind,
				Name: def.Name,
			})
		}
	}
	return len(entities) != 0, entities, nil
}

type EntityInfo struct {
	File string
	Kind string
	Body string
}

func (index *Index) DefinitionComment(contextFile, name string) (*EntityInfo, error) {
	return index.definitionSource(contextFile, name, true, false)
}

func (index *Index) DefinitionSource(contextFile, name string, includeLines bool) (*EntityInfo, error) {
	return index.definitionSource(contextFile, name, false, includeLines)
}

func (index *Index) definitionSource(contextFile, name string, comment, includeLines bool) (*EntityInfo, error) {
	def := index.findDefinition(contextFile, name)
	if def == nil {
		return nil, nil
	}
	lineRange := def.Body
	if comment {
		lineRange = def.Comment
	}
	src, err := index.formatSource(lineRange, includeLines)
	if err != nil {
		return nil, err
	}
	return &EntityInfo{
		File: def.Body.File,
		Kind: def.Kind,
		Body: src,
	}, nil
}

func (index *Index) findDefinition(contextFile, name string) *Definition {
	var weakMatch *Definition
	for _, def := range index.db.Definitions {
		if def.Name == name {
			if def.Body.File == contextFile {
				return def
			}
			if !def.IsStatic {
				weakMatch = def
			}
		}
	}
	return weakMatch
}

func (index *Index) formatSource(lines LineRange, includeLines bool) (string, error) {
	if lines.File == "" {
		return "", nil
	}
	for _, dir := range index.srcDirs {
		file := filepath.Join(dir, lines.File)
		if !osutil.IsExist(file) {
			continue
		}
		return formatSourceFile(file, lines.StartLine, lines.EndLine, includeLines)
	}
	return "", fmt.Errorf("codesearch: can't find %q file in any of %v", lines.File, index.srcDirs)
}

func formatSourceFile(file string, start, end int, includeLines bool) (string, error) {
	data, err := os.ReadFile(file)
	if err != nil {
		return "", err
	}
	lines := bytes.Split(data, []byte{'\n'})
	start--
	end--
	if start < 0 || end < start || end > len(lines) {
		return "", fmt.Errorf("codesearch: bad line range [%v-%v] for file %v with %v lines",
			start, end, file, len(lines))
	}
	b := new(strings.Builder)
	for line := start; line <= end; line++ {
		if includeLines {
			fmt.Fprintf(b, "%4v:\t%s\n", line, lines[line])
		} else {
			fmt.Fprintf(b, "%s\n", lines[line])
		}
	}
	return b.String(), nil
}

func escaping(path string) error {
	if strings.Contains(filepath.Clean(path), "..") {
		return errors.New("path is outside of the source tree")
	}
	return nil
}

func dirIndex(root, subdir string) (bool, []string, []string, error) {
	dir := filepath.Join(root, subdir)
	entries, err := os.ReadDir(dir)
	if err != nil {
		if os.IsNotExist(err) {
			err = nil
		}
		var errno syscall.Errno
		if errors.As(err, &errno) && errno == syscall.ENOTDIR {
			err = nil
		}
		return false, nil, nil, err
	}
	var subdirs, files []string
	for _, entry := range entries {
		if strings.HasPrefix(entry.Name(), ".") {
			// These are internal things like .git, etc.
		} else if entry.IsDir() {
			subdirs = append(subdirs, entry.Name())
		} else if SourceExtensions[filepath.Ext(entry.Name())] {
			files = append(files, entry.Name())
		}
	}
	return true, subdirs, files, err
}
