// Copyright 2025 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package codesearch

import (
	"bytes"
	"fmt"
	"maps"
	"slices"
	"strings"

	"github.com/google/jsonschema-go/jsonschema"
	"github.com/google/syzkaller/pkg/clangtool"
	"github.com/google/syzkaller/pkg/hash"
)

type Database struct {
	Definitions []*Definition `json:"definitions,omitempty"`

	mergeCache   map[string]*Definition
	reverseCache map[*Definition]string
	stringCache  map[string]string
}

type Definition struct {
	Name     string      `json:"name,omitempty"`
	Type     string      `json:"type,omitempty"`
	Kind     EntityKind  `json:"kind,omitempty"`
	IsStatic bool        `json:"is_static,omitempty"`
	Body     LineRange   `json:"body,omitempty"`
	Comment  LineRange   `json:"comment,omitempty"`
	Refs     []Reference `json:"refs,omitempty"`
	Fields   []FieldInfo `json:"fields,omitempty"`
}

type FieldInfo struct {
	Name       string `json:"name,omitempty"`
	OffsetBits uint64 `json:"offset"`
	SizeBits   uint64 `json:"size"`
}

type Reference struct {
	Name       string     `json:"name,omitempty"`
	Kind       RefKind    `json:"kind,omitempty"`
	EntityKind EntityKind `json:"entity_kind,omitempty"`
	Line       uint32     `json:"line,omitempty"`
}

type LineRange struct {
	File      string `json:"file,omitempty"`
	StartLine uint32 `json:"start_line,omitempty"`
	EndLine   uint32 `json:"end_line,omitempty"`
}

type EntityKind uint8

const (
	entityKindInvalid EntityKind = iota
	EntityKindFunction
	EntityKindStruct
	EntityKindUnion
	EntityKindVariable
	EntityKindGlobalVariable
	EntityKindMacro
	EntityKindEnum
	EntityKindTypedef
	EntityKindField
	entityKindLast
)

var entityKindNames = [...]string{
	EntityKindFunction:       "function",
	EntityKindStruct:         "struct",
	EntityKindUnion:          "union",
	EntityKindVariable:       "variable",
	EntityKindGlobalVariable: "global_variable",
	EntityKindMacro:          "macro",
	EntityKindEnum:           "enum",
	EntityKindTypedef:        "typedef",
	EntityKindField:          "field",
}

var entityKindBytes = func() [entityKindLast][]byte {
	var ret [entityKindLast][]byte
	for k, v := range entityKindNames {
		ret[k] = []byte("\"" + v + "\"")
	}
	return ret
}()

func (v *EntityKind) String() string {
	return entityKindNames[*v]
}

func (v *EntityKind) MarshalJSON() ([]byte, error) {
	return entityKindBytes[*v], nil
}

func (v *EntityKind) UnmarshalJSON(data []byte) error {
	*v = entityKindInvalid
	for k, val := range entityKindBytes {
		if bytes.Equal(data, val) {
			*v = EntityKind(k)
			break
		}
	}
	return nil
}

type RefKind uint8

const (
	refKindInvalid RefKind = iota
	RefKindUses
	RefKindCall
	RefKindRead
	RefKindWrite
	RefKindTakesAddr
	refKindLast
)

var refKindNames = [...]string{
	RefKindUses:      "uses",
	RefKindCall:      "calls",
	RefKindRead:      "reads",
	RefKindWrite:     "writes",
	RefKindTakesAddr: "takes-address-of",
}

var refKindBytes = func() [refKindLast][]byte {
	var ret [refKindLast][]byte
	for k, v := range refKindNames {
		ret[k] = []byte("\"" + v + "\"")
	}
	return ret
}()

func (v *RefKind) String() string {
	return refKindNames[*v]
}

func (v *RefKind) MarshalJSON() ([]byte, error) {
	return refKindBytes[*v], nil
}

func (v *RefKind) UnmarshalJSON(data []byte) error {
	*v = refKindInvalid
	for k, val := range refKindBytes {
		if bytes.Equal(data, val) {
			*v = RefKind(k)
			break
		}
	}
	return nil
}

// DatabaseFormatHash contains a hash uniquely identifying format of the database.
// In covers both structure and semantics of the data, and is supposed to be used
// for caching of the database files.
var DatabaseFormatHash = func() string {
	// Semantic version should be bumped when the schema does not change,
	// but stored values changes.
	const semanticVersion = "4"
	schema, err := jsonschema.For[Database](nil)
	if err != nil {
		panic(err)
	}
	return hash.String(schema, semanticVersion)
}()

func (db *Database) Merge(other *Database, v *clangtool.Verifier) {
	if db.mergeCache == nil {
		db.mergeCache = make(map[string]*Definition)
		db.reverseCache = make(map[*Definition]string)
		db.stringCache = make(map[string]string)
	}
	for _, def := range other.Definitions {
		id := fmt.Sprintf("%v-%v-%v", def.Kind, def.Name, def.Body.File)
		if _, ok := db.mergeCache[id]; ok {
			continue
		}
		db.mergeCache[id] = def
		db.reverseCache[def] = id
		v.LineRange(def.Body.File, int(def.Body.StartLine), int(def.Body.EndLine))
		if def.Comment.File != "" {
			v.LineRange(def.Comment.File, int(def.Comment.StartLine), int(def.Comment.EndLine))
		}
		db.intern(&def.Name)
		db.intern(&def.Type)
		db.intern(&def.Body.File)
		db.intern(&def.Comment.File)
		for _, ref := range def.Refs {
			db.intern(&ref.Name)
		}
		for i := range def.Fields {
			db.intern(&def.Fields[i].Name)
		}
	}
}

func (db *Database) Finalize(v *clangtool.Verifier) {
	db.Definitions = slices.Collect(maps.Values(db.mergeCache))
	slices.SortFunc(db.Definitions, func(a, b *Definition) int {
		return strings.Compare(db.reverseCache[a], db.reverseCache[b])
	})
	db.mergeCache = nil
	db.reverseCache = nil
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

func (db *Database) intern(str *string) {
	if *str == "" {
		return
	}
	v, ok := db.stringCache[*str]
	if !ok {
		v = strings.Clone(*str)
		db.stringCache[v] = v
	}
	*str = v
}
