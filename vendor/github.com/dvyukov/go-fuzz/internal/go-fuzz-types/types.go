// Copyright 2015 go-fuzz project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

// Package types provides types shared between go-fuzz-build and go-fuzz.
package types

type CoverBlock struct {
	ID        int
	File      string
	StartLine int
	StartCol  int
	EndLine   int
	EndCol    int
	NumStmt   int
}

type Literal struct {
	Val   string
	IsStr bool
}

type MetaData struct {
	Literals    []Literal
	Blocks      []CoverBlock
	Sonar       []CoverBlock
	Funcs       []string // fuzz function names; must have length > 0
	DefaultFunc string   // default function to fuzz
}
