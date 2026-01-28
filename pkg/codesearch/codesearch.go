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
	"strconv"
	"strings"
	"syscall"

	"github.com/google/syzkaller/pkg/aflow"
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
		subdirs, files, err := index.DirIndex(args[0])
		if err != nil {
			return "", err
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
	{"read-file", 1, func(index *Index, args []string) (string, error) {
		return index.ReadFile(args[0])
	}},
	{"file-index", 1, func(index *Index, args []string) (string, error) {
		entities, err := index.FileIndex(args[0])
		if err != nil {
			return "", err
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
		if err != nil {
			return "", err
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
		if err != nil {
			return "", err
		}
		return fmt.Sprintf("%v %v is defined in %v:\n\n%v", info.Kind, args[1], info.File, info.Body), nil
	}},
	{"find-references", 5, func(index *Index, args []string) (string, error) {
		contextLines, err := strconv.Atoi(args[3])
		if err != nil {
			return "", fmt.Errorf("failed to parse number of context lines %q: %w", args[3], err)
		}
		outputLimit, err := strconv.Atoi(args[4])
		if err != nil {
			return "", fmt.Errorf("failed to parse output limit %q: %w", args[4], err)
		}
		refs, totalCount, err := index.FindReferences(args[0], args[1], args[2], contextLines, outputLimit)
		if err != nil {
			return "", err
		}
		b := new(strings.Builder)
		fmt.Fprintf(b, "%v has %v references:\n\n", args[1], totalCount)
		for _, ref := range refs {
			fmt.Fprintf(b, "%v %v %v it at %v:%v\n%v\n\n",
				ref.ReferencingEntityKind, ref.ReferencingEntityName, ref.ReferenceKind,
				ref.SourceFile, ref.SourceLine, ref.SourceSnippet)
		}
		return b.String(), nil
	}},
	{"struct-layout", 0, func(index *Index, args []string) (string, error) {
		if len(args) != 2 && len(args) != 3 {
			return "", fmt.Errorf("codesearch command struct-layout requires 2 or 3 args, but %v provided",
				len(args))
		}
		var fieldOffset *uint
		if len(args) == 3 {
			val, err := strconv.ParseUint(args[2], 10, 64)
			if err != nil {
				return "", fmt.Errorf("bad offset: %w", err)
			}
			fieldOffset = new(uint)
			*fieldOffset = uint(val)
		}
		fields, err := index.GetStructLayout(args[0], args[1], fieldOffset)
		if err != nil {
			return "", err
		}
		b := new(strings.Builder)
		fmt.Fprintf(b, "struct %v has %v fields:\n", args[1], len(fields))
		for _, f := range fields {
			fmt.Fprintf(b, "[%v - %v] %v\n", f.OffsetBits, f.OffsetBits+f.SizeBits, f.Name)
		}
		return b.String(), nil
	}},
}

func IsSourceFile(file string) bool {
	return sourceFiles[file] || sourceExtensions[filepath.Ext(file)]
}

var (
	// Files and extensions we want to keep in the build dir and make available to LLM agents.
	sourceExtensions = map[string]bool{".c": true, ".h": true, ".S": true, ".rs": true}
	sourceFiles      = map[string]bool{
		".config": true,
	}
)

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
			if meta.NArgs != 0 && len(args) != meta.NArgs {
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

func (index *Index) DirIndex(dir string) ([]string, []string, error) {
	if err := escaping(dir); err != nil {
		return nil, nil, err
	}
	exists := false
	var subdirs, files []string
	for _, root := range index.srcDirs {
		exists1, subdirs1, files1, err := dirIndex(root, dir)
		if err != nil {
			return nil, nil, err
		}
		if exists1 {
			exists = true
		}
		subdirs = append(subdirs, subdirs1...)
		files = append(files, files1...)
	}
	if !exists {
		return nil, nil, aflow.BadCallError("the directory does not exist")
	}
	slices.Sort(subdirs)
	slices.Sort(files)
	// Dedup dirs across src/build trees,
	// also dedup files, but hopefully there are no duplicates.
	subdirs = slices.Compact(subdirs)
	files = slices.Compact(files)
	return subdirs, files, nil
}

func (index *Index) ReadFile(file string) (string, error) {
	if err := escaping(file); err != nil {
		return "", err
	}
	for _, dir := range index.srcDirs {
		data, err := os.ReadFile(filepath.Join(dir, file))
		if err != nil {
			if os.IsNotExist(err) {
				continue
			}
			var errno syscall.Errno
			if errors.As(err, &errno) && errno == syscall.EISDIR {
				return "", aflow.BadCallError("the file is a directory")
			}
			return "", err
		}
		return string(data), nil
	}
	return "", aflow.BadCallError("the file does not exist")
}

func (index *Index) FileIndex(file string) ([]Entity, error) {
	file = filepath.Clean(file)
	// This allows to distinguish missing files from files that don't define anything.
	if _, err := index.ReadFile(file); err != nil {
		return nil, err
	}
	var entities []Entity
	for _, def := range index.db.Definitions {
		if def.Body.File == file {
			entities = append(entities, Entity{
				Kind: def.Kind.String(),
				Name: def.Name,
			})
		}
	}
	return entities, nil
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
		return nil, aflow.BadCallError("requested entity does not exist")
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
		Kind: def.Kind.String(),
		Body: src,
	}, nil
}

type ReferenceInfo struct {
	ReferencingEntityKind string `jsonschema:"Kind of the referencing entity (function, struct, etc)."`
	ReferencingEntityName string `jsonschema:"Name of the referencing entity."`
	ReferenceKind         string `jsonschema:"Kind of the reference (calls, takes-address, reads, writes-to, etc)."`
	SourceFile            string `jsonschema:"Source file of the reference."`
	SourceLine            int    `jsonschema:"Source line of the reference."`
	SourceSnippet         string `jsonschema:"Surrounding code snippet, if requested." json:",omitempty"`
}

func (index *Index) FindReferences(contextFile, name, srcPrefix string, contextLines, outputLimit int) (
	[]ReferenceInfo, int, error) {
	// Just in case LLM decides to reference structs/fields with the tag.
	name = strings.TrimSpace(strings.TrimPrefix(strings.TrimPrefix(strings.TrimSpace(name),
		"struct "), "union "))
	// We don't export each field as a separate definition,
	// so we do just name-based match for them.
	isField := strings.Contains(name, "::")
	target := index.findDefinition(contextFile, name)
	if target == nil && !isField {
		return nil, 0, aflow.BadCallError("requested entity does not exist")
	}
	if srcPrefix != "" {
		srcPrefix = filepath.Clean(srcPrefix)
	}
	contextLines = min(contextLines, 10000)
	totalCount := 0
	var results []ReferenceInfo
	for _, def := range index.db.Definitions {
		if !strings.HasPrefix(def.Body.File, srcPrefix) {
			continue
		}
		for _, ref := range def.Refs {
			// TODO: this mis-handles the following case:
			// the target is a non-static 'foo' in some file,
			// the reference is in another file and refers to a static 'foo'
			// defined in that file (which is not the target 'foo').
			if ref.Name != name || !isField && (ref.EntityKind != target.Kind ||
				target.IsStatic && target.Body.File != def.Body.File) {
				continue
			}
			totalCount++
			if totalCount > outputLimit {
				continue
			}
			snippet := ""
			if contextLines > 0 {
				lines := LineRange{
					File:      def.Body.File,
					StartLine: max(def.Body.StartLine, uint32(max(0, int(ref.Line)-contextLines))),
					EndLine:   min(def.Body.EndLine, ref.Line+uint32(contextLines)),
				}
				var err error
				snippet, err = index.formatSource(lines, true)
				if err != nil {
					return nil, 0, err
				}
			}
			results = append(results, ReferenceInfo{
				ReferencingEntityKind: def.Kind.String(),
				ReferencingEntityName: def.Name,
				ReferenceKind:         ref.Kind.String(),
				SourceFile:            def.Body.File,
				SourceLine:            int(ref.Line),
				SourceSnippet:         snippet,
			})
		}
	}
	return results, totalCount, nil
}

func (index *Index) findDefinition(contextFile, name string) *Definition {
	var weakMatch, veryWeakMatch *Definition
	for _, def := range index.db.Definitions {
		if def.Name != name {
			continue
		}
		if def.Body.File == contextFile {
			return def
		}
		// Strictly speaking there may be several different static functions in different headers,
		// but we ignore such possibility for now.
		if !def.IsStatic || strings.HasSuffix(def.Body.File, ".h") {
			weakMatch = def
		}
		veryWeakMatch = def
	}
	if weakMatch != nil {
		return weakMatch
	}
	return veryWeakMatch
}

func (index *Index) GetStructLayout(contextFile, name string, fieldOffset *uint) ([]FieldInfo, error) {
	def := index.findDefinition(contextFile, name)
	if def == nil {
		return nil, aflow.BadCallError("requested entity does not exist")
	}
	if def.Kind != EntityKindStruct && def.Kind != EntityKindUnion {
		return nil, aflow.BadCallError("requested entity %v is not a struct/union (is %v)", name, def.Kind)
	}
	if fieldOffset == nil {
		return def.Fields, nil
	}
	var res []FieldInfo
	targetBits := uint64(*fieldOffset) * 8
	for _, f := range def.Fields {
		if f.OffsetBits <= targetBits && targetBits <= f.OffsetBits+f.SizeBits {
			res = append(res, f)
		}
	}
	return res, nil
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
		return formatSourceFile(file, int(lines.StartLine), int(lines.EndLine), includeLines)
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
			fmt.Fprintf(b, "%4v:\t%s\n", line+1, lines[line])
		} else {
			fmt.Fprintf(b, "%s\n", lines[line])
		}
	}
	return b.String(), nil
}

func escaping(path string) error {
	if strings.Contains(filepath.Clean(path), "..") {
		return aflow.BadCallError("path is outside of the source tree")
	}
	return nil
}

func dirIndex(root, subdir string) (bool, []string, []string, error) {
	subdir = filepath.Clean(subdir)
	dir := filepath.Join(root, subdir)
	entries, err := os.ReadDir(dir)
	if err != nil {
		if os.IsNotExist(err) {
			err = nil
		}
		var errno syscall.Errno
		if errors.As(err, &errno) && errno == syscall.ENOTDIR {
			err = aflow.BadCallError("the path is not a directory")
		}
		return false, nil, nil, err
	}
	var subdirs, files []string
	for _, entry := range entries {
		if strings.HasPrefix(entry.Name(), ".") {
			// These are internal things like .git, etc.
		} else if entry.IsDir() {
			subdirs = append(subdirs, entry.Name())
		} else if IsSourceFile(filepath.Join(subdir, entry.Name())) {
			files = append(files, entry.Name())
		}
	}
	return true, subdirs, files, err
}
