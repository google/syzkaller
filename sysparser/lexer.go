// Copyright 2015/2016 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package sysparser

import (
	"fmt"
	"io"
	"os"
	"sort"
	"strconv"
	"strings"
)

type Description struct {
	Includes  []string
	Defines   map[string]string
	Syscalls  []Syscall
	Structs   map[string]Struct
	Unnamed   map[string][]string
	Flags     map[string][]string
	StrFlags  map[string][]string
	Resources map[string]Resource
}

type Syscall struct {
	Name     string
	CallName string
	Args     [][]string
	Ret      []string
}

type Struct struct {
	Name    string
	Flds    [][]string
	IsUnion bool
	Packed  bool
	Varlen  bool
	Align   int
}

type Resource struct {
	Name   string
	Base   string
	Values []string
}

func Parse(in io.Reader) *Description {
	p := newParser(in)
	var includes []string
	defines := make(map[string]string)
	var syscalls []Syscall
	structs := make(map[string]Struct)
	unnamed := make(map[string][]string)
	flags := make(map[string][]string)
	strflags := make(map[string][]string)
	resources := make(map[string]Resource)
	var str *Struct
	for p.Scan() {
		if p.EOF() || p.Char() == '#' {
			continue
		}
		if str != nil {
			// Parsing a struct.
			if p.Char() == '}' || p.Char() == ']' {
				p.Parse(p.Char())
				for _, attr := range parseType1(p, unnamed, flags, "")[1:] {
					if str.IsUnion {
						switch attr {
						case "varlen":
							str.Varlen = true
						default:
							failf("unknown union %v attribute: %v", str.Name, attr)
						}
					} else {
						switch {
						case attr == "packed":
							str.Packed = true
						case strings.HasPrefix(attr, "align_ptr"):
							str.Align = 8 // TODO: this must be target pointer size
						case strings.HasPrefix(attr, "align_"):
							a, err := strconv.ParseUint(attr[6:], 10, 64)
							if err != nil {
								failf("bad struct %v alignment %v: %v", str.Name, attr, err)
							}
							if a&(a-1) != 0 || a == 0 || a > 1<<30 {
								failf("bad struct %v alignment %v: must be sane power of 2", str.Name, a)
							}
							str.Align = int(a)
						default:
							failf("unknown struct %v attribute: %v", str.Name, attr)
						}
					}
				}
				if str.IsUnion {
					if len(str.Flds) <= 1 {
						failf("union %v has only %v fields, need at least 2", str.Name, len(str.Flds))
					}
				}
				fields := make(map[string]bool)
				for _, f := range str.Flds {
					if f[0] == "parent" {
						failf("struct/union %v contains reserved field 'parent'", str.Name)
					}
					if fields[f[0]] {
						failf("duplicate field %v in struct/union %v", f[0], str.Name)
					}
					fields[f[0]] = true
				}
				structs[str.Name] = *str
				str = nil
			} else {
				p.SkipWs()
				fld := []string{p.Ident()}
				fld = append(fld, parseType(p, unnamed, flags)...)
				str.Flds = append(str.Flds, fld)
			}
		} else {
			name := p.Ident()
			if name == "include" {
				p.Parse('<')
				var include []byte
				for {
					ch := p.Char()
					if ch == '>' {
						break
					}
					p.Parse(ch)
					include = append(include, ch)
				}
				p.Parse('>')
				includes = append(includes, string(include))
			} else if name == "define" {
				key := p.Ident()
				var val []byte
				for !p.EOF() {
					ch := p.Char()
					p.Parse(ch)
					val = append(val, ch)
				}
				if defines[key] != "" {
					failf("%v define is defined multiple times", key)
				}
				defines[key] = fmt.Sprintf("(%s)", val)
			} else if name == "resource" {
				p.SkipWs()
				id := p.Ident()
				p.Parse('[')
				base := p.Ident()
				p.Parse(']')
				var vals []string
				if !p.EOF() && p.Char() == ':' {
					p.Parse(':')
					vals = append(vals, p.Ident())
					for !p.EOF() {
						p.Parse(',')
						vals = append(vals, p.Ident())
					}
				}
				if _, ok := resources[id]; ok {
					failf("resource '%v' is defined multiple times", id)
				}
				if _, ok := structs[id]; ok {
					failf("struct '%v' is redefined as resource", name)
				}
				resources[id] = Resource{id, base, vals}
			} else {
				switch ch := p.Char(); ch {
				case '(':
					// syscall
					p.Parse('(')
					var args [][]string
					for p.Char() != ')' {
						arg := []string{p.Ident()}
						arg = append(arg, parseType(p, unnamed, flags)...)
						args = append(args, arg)
						if p.Char() != ')' {
							p.Parse(',')
						}
					}
					p.Parse(')')
					var ret []string
					if !p.EOF() {
						ret = parseType(p, unnamed, flags)
					}
					callName := name
					if idx := strings.IndexByte(callName, '$'); idx != -1 {
						callName = callName[:idx]
					}
					fields := make(map[string]bool)
					for _, a := range args {
						if fields[a[0]] {
							failf("duplicate arg %v in syscall %v", a[0], name)
						}
						fields[a[0]] = true
					}
					syscalls = append(syscalls, Syscall{name, callName, args, ret})
				case '=':
					// flag
					p.Parse('=')
					str := p.Char() == '"'
					var vals []string
					for {
						v := p.Ident()
						if str {
							v = v[1 : len(v)-1]
						}
						vals = append(vals, v)
						if p.EOF() {
							break
						}
						p.Parse(',')
					}
					if str {
						strflags[name] = vals
					} else {
						flags[name] = vals
					}
				case '{', '[':
					p.Parse(ch)
					if _, ok := structs[name]; ok {
						failf("struct '%v' is defined multiple times", name)
					}
					if _, ok := resources[name]; ok {
						failf("resource '%v' is redefined as struct", name)
					}
					str = &Struct{Name: name, IsUnion: ch == '['}
				default:
					failf("bad line (%v)", p.Str())
				}
			}
		}
		if !p.EOF() {
			failf("trailing data (%v)", p.Str())
		}
	}
	sort.Sort(syscallArray(syscalls))
	return &Description{
		Includes:  includes,
		Defines:   defines,
		Syscalls:  syscalls,
		Structs:   structs,
		Unnamed:   unnamed,
		Flags:     flags,
		StrFlags:  strflags,
		Resources: resources,
	}
}

func isIdentifier(s string) bool {
	for i, c := range s {
		if c == '_' || (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || i > 0 && (c >= '0' && c <= '9') {
			continue
		}
		return false
	}
	return true
}

func parseType(p *parser, unnamed map[string][]string, flags map[string][]string) []string {
	return parseType1(p, unnamed, flags, p.Ident())
}

var (
	unnamedSeq int
	constSeq   int
)

func parseType1(p *parser, unnamed map[string][]string, flags map[string][]string, name string) []string {
	typ := []string{name}
	if !p.EOF() && p.Char() == '[' {
		p.Parse('[')
		for {
			id := p.Ident()
			if p.Char() == '[' {
				inner := parseType1(p, unnamed, flags, id)
				id = fmt.Sprintf("unnamed%v", unnamedSeq)
				unnamedSeq++
				unnamed[id] = inner
			}
			typ = append(typ, id)
			if p.Char() == ']' {
				break
			}
			p.Parse(',')
		}
		p.Parse(']')
	}
	if name == "const" && len(typ) > 1 {
		// Create a fake flag with the const value.
		id := fmt.Sprintf("const_flag_%v", constSeq)
		constSeq++
		flags[id] = typ[1:2]
	}
	if name == "array" && len(typ) > 2 {
		// Create a fake flag with the const value.
		id := fmt.Sprintf("const_flag_%v", constSeq)
		constSeq++
		flags[id] = typ[2:3]
	}
	return typ
}

type syscallArray []Syscall

func (a syscallArray) Len() int           { return len(a) }
func (a syscallArray) Less(i, j int) bool { return a[i].Name < a[j].Name }
func (a syscallArray) Swap(i, j int)      { a[i], a[j] = a[j], a[i] }

func failf(msg string, args ...interface{}) {
	fmt.Fprintf(os.Stderr, msg+"\n", args...)
	os.Exit(1)
}
