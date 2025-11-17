// Copyright 2025 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package codesearch

import (
	"strings"

	"github.com/google/syzkaller/pkg/clangtool"
)

type Database struct {
	Definitions []*Definition `json:"definitions,omitempty"`
}

type Definition struct {
	Kind     string    `json:"kind,omitempty"`
	Name     string    `json:"name,omitempty"`
	Type     string    `json:"type,omitempty"`
	IsStatic bool      `json:"is_static,omitempty"`
	Body     LineRange `json:"body,omitempty"`
	Comment  LineRange `json:"comment,omitempty"`
}

type LineRange struct {
	File      string `json:"file,omitempty"`
	StartLine int    `json:"start_line,omitempty"`
	EndLine   int    `json:"end_line,omitempty"`
}

func (db *Database) Merge(other *Database) {
	db.Definitions = append(db.Definitions, other.Definitions...)
}

func (db *Database) Finalize(v *clangtool.Verifier) {
	db.Definitions = clangtool.SortAndDedupSlice(db.Definitions)

	for _, def := range db.Definitions {
		v.LineRange(def.Body.File, def.Body.StartLine, def.Body.EndLine)
		if def.Comment.File != "" {
			v.LineRange(def.Comment.File, def.Comment.StartLine, def.Comment.EndLine)
		}
	}
}

// SetSoureFile attaches the source file to the entities that need it.
// The clang tool could do it, but it looks easier to do it here.
func (db *Database) SetSourceFile(file string, updatePath func(string) string) {
	for _, def := range db.Definitions {
		def.Body.File = updatePath(def.Body.File)
		def.Comment.File = updatePath(def.Comment.File)
		if strings.HasSuffix(def.Body.File, ".c") && def.Body.File != file {
			def.IsStatic = false
		}
	}
}
