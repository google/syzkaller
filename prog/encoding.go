// Copyright 2015 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package prog

import (
	"bufio"
	"bytes"
	"encoding/hex"
	"fmt"
	"strconv"
	"strings"
)

// String generates a very compact program description (mostly for debug output).
func (p *Prog) String() string {
	buf := new(bytes.Buffer)
	for i, c := range p.Calls {
		if i != 0 {
			fmt.Fprintf(buf, "-")
		}
		fmt.Fprintf(buf, "%v", c.Meta.Name)
	}
	return buf.String()
}

func (p *Prog) Serialize() []byte {
	return p.serialize(false)
}

func (p *Prog) SerializeVerbose() []byte {
	return p.serialize(true)
}

func (p *Prog) serialize(verbose bool) []byte {
	p.debugValidate()
	ctx := &serializer{
		target:  p.Target,
		buf:     new(bytes.Buffer),
		vars:    make(map[*ResultArg]int),
		verbose: verbose,
	}
	for _, c := range p.Calls {
		ctx.call(c)
	}
	return ctx.buf.Bytes()
}

type serializer struct {
	target  *Target
	buf     *bytes.Buffer
	vars    map[*ResultArg]int
	varSeq  int
	verbose bool
}

func (ctx *serializer) printf(text string, args ...interface{}) {
	fmt.Fprintf(ctx.buf, text, args...)
}

func (ctx *serializer) allocVarID(arg *ResultArg) int {
	id := ctx.varSeq
	ctx.varSeq++
	ctx.vars[arg] = id
	return id
}

func (ctx *serializer) call(c *Call) {
	if c.Ret != nil && len(c.Ret.uses) != 0 {
		ctx.printf("r%v = ", ctx.allocVarID(c.Ret))
	}
	ctx.printf("%v(", c.Meta.Name)
	for i, a := range c.Args {
		if IsPad(a.Type()) {
			continue
		}
		if i != 0 {
			ctx.printf(", ")
		}
		ctx.arg(a)
	}
	ctx.printf(")\n")
}

func (ctx *serializer) arg(arg Arg) {
	if arg == nil {
		ctx.printf("nil")
		return
	}
	arg.serialize(ctx)
}

func (a *ConstArg) serialize(ctx *serializer) {
	ctx.printf("0x%x", a.Val)
}

func (a *PointerArg) serialize(ctx *serializer) {
	if a.IsSpecial() {
		ctx.printf("0x%x", a.Address)
		return
	}
	target := ctx.target
	ctx.printf("&%v", target.serializeAddr(a))
	if a.Res != nil && !ctx.verbose && isDefault(a.Res) && !target.isAnyPtr(a.Type()) {
		return
	}
	ctx.printf("=")
	if target.isAnyPtr(a.Type()) {
		ctx.printf("ANY=")
	}
	ctx.arg(a.Res)
}

func (a *DataArg) serialize(ctx *serializer) {
	typ := a.Type().(*BufferType)
	if a.Dir() == DirOut {
		ctx.printf("\"\"/%v", a.Size())
		return
	}
	data := a.Data()
	// Statically typed data will be padded with 0s during deserialization,
	// so we can strip them here for readability always. For variable-size
	// data we strip trailing 0s only if we strip enough of them.
	sz := len(data)
	for len(data) >= 2 && data[len(data)-1] == 0 && data[len(data)-2] == 0 {
		data = data[:len(data)-1]
	}
	if typ.Varlen() && len(data)+8 >= sz {
		data = data[:sz]
	}
	serializeData(ctx.buf, data, isReadableDataType(typ))
	if typ.Varlen() && sz != len(data) {
		ctx.printf("/%v", sz)
	}
}

func (a *GroupArg) serialize(ctx *serializer) {
	var delims []byte
	switch a.Type().(type) {
	case *StructType:
		delims = []byte{'{', '}'}
	case *ArrayType:
		delims = []byte{'[', ']'}
	default:
		panic("unknown group type")
	}
	ctx.buf.WriteByte(delims[0])
	lastNonDefault := len(a.Inner) - 1
	if !ctx.verbose && a.fixedInnerSize() {
		for ; lastNonDefault >= 0; lastNonDefault-- {
			if !isDefault(a.Inner[lastNonDefault]) {
				break
			}
		}
	}
	for i := 0; i <= lastNonDefault; i++ {
		arg1 := a.Inner[i]
		if arg1 != nil && IsPad(arg1.Type()) {
			continue
		}
		if i != 0 {
			ctx.printf(", ")
		}
		ctx.arg(arg1)
	}
	ctx.buf.WriteByte(delims[1])
}

func (a *UnionArg) serialize(ctx *serializer) {
	typ := a.Type().(*UnionType)
	ctx.printf("@%v", typ.Fields[a.Index].Name)
	if !ctx.verbose && isDefault(a.Option) {
		return
	}
	ctx.printf("=")
	ctx.arg(a.Option)
}

func (a *ResultArg) serialize(ctx *serializer) {
	if len(a.uses) != 0 {
		ctx.printf("<r%v=>", ctx.allocVarID(a))
	}
	if a.Res == nil {
		ctx.printf("0x%x", a.Val)
		return
	}
	id, ok := ctx.vars[a.Res]
	if !ok {
		panic("no result")
	}
	ctx.printf("r%v", id)
	if a.OpDiv != 0 {
		ctx.printf("/%v", a.OpDiv)
	}
	if a.OpAdd != 0 {
		ctx.printf("+%v", a.OpAdd)
	}
}

type DeserializeMode int

const (
	Strict    DeserializeMode = iota
	NonStrict DeserializeMode = iota
)

func (target *Target) Deserialize(data []byte, mode DeserializeMode) (*Prog, error) {
	defer func() {
		if err := recover(); err != nil {
			panic(fmt.Errorf("%v\ntarget: %v/%v, rev: %v, mode=%v, prog:\n%q",
				err, target.OS, target.Arch, GitRevision, mode, data))
		}
	}()
	p := newParser(target, data, mode == Strict)
	prog, err := p.parseProg()
	if err := p.Err(); err != nil {
		return nil, err
	}
	if err != nil {
		return nil, err
	}
	// This validation is done even in non-debug mode because deserialization
	// procedure does not catch all bugs (e.g. mismatched types).
	// And we can receive bad programs from corpus and hub.
	if err := prog.validate(); err != nil {
		return nil, err
	}
	if p.autos != nil {
		p.fixupAutos(prog)
	}
	if err := prog.sanitize(mode == NonStrict); err != nil {
		return nil, err
	}
	return prog, nil
}

func (p *parser) parseProg() (*Prog, error) {
	prog := &Prog{
		Target: p.target,
	}
	for p.Scan() {
		if p.EOF() {
			if p.comment != "" {
				prog.Comments = append(prog.Comments, p.comment)
				p.comment = ""
			}
			continue
		}
		if p.Char() == '#' {
			if p.comment != "" {
				prog.Comments = append(prog.Comments, p.comment)
			}
			p.comment = strings.TrimSpace(p.s[p.i+1:])
			continue
		}
		name := p.Ident()
		r := ""
		if p.Char() == '=' {
			r = name
			p.Parse('=')
			name = p.Ident()
		}
		meta := p.target.SyscallMap[name]
		if meta == nil {
			return nil, fmt.Errorf("unknown syscall %v", name)
		}
		c := &Call{
			Meta:    meta,
			Ret:     MakeReturnArg(meta.Ret),
			Comment: p.comment,
		}
		prog.Calls = append(prog.Calls, c)
		p.Parse('(')
		for i := 0; p.Char() != ')'; i++ {
			if i >= len(meta.Args) {
				p.eatExcessive(false, "excessive syscall arguments")
				break
			}
			field := meta.Args[i]
			if IsPad(field.Type) {
				return nil, fmt.Errorf("padding in syscall %v arguments", name)
			}
			arg, err := p.parseArg(field.Type, DirIn)
			if err != nil {
				return nil, err
			}
			c.Args = append(c.Args, arg)
			if p.Char() != ')' {
				p.Parse(',')
			}
		}
		p.Parse(')')
		p.SkipWs()
		if !p.EOF() {
			if p.Char() != '#' {
				return nil, fmt.Errorf("tailing data (line #%v)", p.l)
			}
			if c.Comment != "" {
				prog.Comments = append(prog.Comments, c.Comment)
			}
			c.Comment = strings.TrimSpace(p.s[p.i+1:])
		}
		for i := len(c.Args); i < len(meta.Args); i++ {
			p.strictFailf("missing syscall args")
			c.Args = append(c.Args, meta.Args[i].DefaultArg(DirIn))
		}
		if len(c.Args) != len(meta.Args) {
			return nil, fmt.Errorf("wrong call arg count: %v, want %v", len(c.Args), len(meta.Args))
		}
		if r != "" && c.Ret != nil {
			p.vars[r] = c.Ret
		}
		p.comment = ""
	}
	if p.comment != "" {
		prog.Comments = append(prog.Comments, p.comment)
	}
	return prog, nil
}

func (p *parser) parseArg(typ Type, dir Dir) (Arg, error) {
	r := ""
	if p.Char() == '<' {
		p.Parse('<')
		r = p.Ident()
		p.Parse('=')
		p.Parse('>')
	}
	arg, err := p.parseArgImpl(typ, dir)
	if err != nil {
		return nil, err
	}
	if arg == nil {
		if typ != nil {
			arg = typ.DefaultArg(dir)
		} else if r != "" {
			return nil, fmt.Errorf("named nil argument")
		}
	}
	if r != "" {
		if res, ok := arg.(*ResultArg); ok {
			p.vars[r] = res
		}
	}
	return arg, nil
}

func (p *parser) parseArgImpl(typ Type, dir Dir) (Arg, error) {
	if typ == nil && p.Char() != 'n' {
		p.eatExcessive(true, "non-nil argument for nil type")
		return nil, nil
	}
	switch p.Char() {
	case '0':
		return p.parseArgInt(typ, dir)
	case 'r':
		return p.parseArgRes(typ, dir)
	case '&':
		return p.parseArgAddr(typ, dir)
	case '"', '\'':
		return p.parseArgString(typ, dir)
	case '{':
		return p.parseArgStruct(typ, dir)
	case '[':
		return p.parseArgArray(typ, dir)
	case '@':
		return p.parseArgUnion(typ, dir)
	case 'n':
		p.Parse('n')
		p.Parse('i')
		p.Parse('l')
		return nil, nil
	case 'A':
		p.Parse('A')
		p.Parse('U')
		p.Parse('T')
		p.Parse('O')
		return p.parseAuto(typ, dir)
	default:
		return nil, fmt.Errorf("failed to parse argument at '%c' (line #%v/%v: %v)",
			p.Char(), p.l, p.i, p.s)
	}
}

func (p *parser) parseArgInt(typ Type, dir Dir) (Arg, error) {
	val := p.Ident()
	v, err := strconv.ParseUint(val, 0, 64)
	if err != nil {
		return nil, fmt.Errorf("wrong arg value '%v': %v", val, err)
	}
	switch typ.(type) {
	case *ConstType, *IntType, *FlagsType, *ProcType, *CsumType:
		arg := Arg(MakeConstArg(typ, dir, v))
		if dir == DirOut && !typ.isDefaultArg(arg) {
			p.strictFailf("out arg %v has non-default value: %v", typ, v)
			arg = typ.DefaultArg(dir)
		}
		return arg, nil
	case *LenType:
		return MakeConstArg(typ, dir, v), nil
	case *ResourceType:
		return MakeResultArg(typ, dir, nil, v), nil
	case *PtrType, *VmaType:
		index := -v % uint64(len(p.target.SpecialPointers))
		return MakeSpecialPointerArg(typ, dir, index), nil
	default:
		p.eatExcessive(true, "wrong int arg %T", typ)
		return typ.DefaultArg(dir), nil
	}
}

func (p *parser) parseAuto(typ Type, dir Dir) (Arg, error) {
	switch typ.(type) {
	case *ConstType, *LenType, *CsumType:
		return p.auto(MakeConstArg(typ, dir, 0)), nil
	default:
		return nil, fmt.Errorf("wrong type %T for AUTO", typ)
	}
}

func (p *parser) parseArgRes(typ Type, dir Dir) (Arg, error) {
	id := p.Ident()
	var div, add uint64
	if p.Char() == '/' {
		p.Parse('/')
		op := p.Ident()
		v, err := strconv.ParseUint(op, 0, 64)
		if err != nil {
			return nil, fmt.Errorf("wrong result div op: '%v'", op)
		}
		div = v
	}
	if p.Char() == '+' {
		p.Parse('+')
		op := p.Ident()
		v, err := strconv.ParseUint(op, 0, 64)
		if err != nil {
			return nil, fmt.Errorf("wrong result add op: '%v'", op)
		}
		add = v
	}
	v := p.vars[id]
	if v == nil {
		p.strictFailf("undeclared variable %v", id)
		return typ.DefaultArg(dir), nil
	}
	arg := MakeResultArg(typ, dir, v, 0)
	arg.OpDiv = div
	arg.OpAdd = add
	return arg, nil
}

func (p *parser) parseArgAddr(typ Type, dir Dir) (Arg, error) {
	var elem Type
	elemDir := DirInOut
	switch t1 := typ.(type) {
	case *PtrType:
		elem, elemDir = t1.Elem, t1.ElemDir
	case *VmaType:
	default:
		p.eatExcessive(true, "wrong addr arg")
		return typ.DefaultArg(dir), nil
	}
	p.Parse('&')
	auto := false
	var addr, vmaSize uint64
	if p.Char() == 'A' {
		p.Parse('A')
		p.Parse('U')
		p.Parse('T')
		p.Parse('O')
		if elem == nil {
			return nil, fmt.Errorf("vma type can't be AUTO")
		}
		auto = true
	} else {
		var err error
		addr, vmaSize, err = p.parseAddr()
		if err != nil {
			return nil, err
		}
	}
	var inner Arg
	if p.Char() == '=' {
		p.Parse('=')
		if p.Char() == 'A' {
			p.Parse('A')
			p.Parse('N')
			p.Parse('Y')
			p.Parse('=')
			anyPtr := p.target.getAnyPtrType(typ.Size())
			typ, elem, elemDir = anyPtr, anyPtr.Elem, anyPtr.ElemDir
		}
		var err error
		inner, err = p.parseArg(elem, elemDir)
		if err != nil {
			return nil, err
		}
	}
	if elem == nil {
		if addr%p.target.PageSize != 0 {
			p.strictFailf("unaligned vma address 0x%x", addr)
			addr &= ^(p.target.PageSize - 1)
		}
		return MakeVmaPointerArg(typ, dir, addr, vmaSize), nil
	}
	if inner == nil {
		inner = elem.DefaultArg(elemDir)
	}
	arg := MakePointerArg(typ, dir, addr, inner)
	if auto {
		p.auto(arg)
	}
	return arg, nil
}

func (p *parser) parseArgString(t Type, dir Dir) (Arg, error) {
	typ, ok := t.(*BufferType)
	if !ok {
		p.eatExcessive(true, "wrong string arg")
		return t.DefaultArg(dir), nil
	}
	data, err := p.deserializeData()
	if err != nil {
		return nil, err
	}
	size := ^uint64(0)
	if p.Char() == '/' {
		p.Parse('/')
		sizeStr := p.Ident()
		size, err = strconv.ParseUint(sizeStr, 0, 64)
		if err != nil {
			return nil, fmt.Errorf("failed to parse buffer size: %q", sizeStr)
		}
		maxMem := p.target.NumPages * p.target.PageSize
		if size > maxMem {
			p.strictFailf("too large string argument %v", size)
			size = maxMem
		}
	}
	if !typ.Varlen() {
		size = typ.Size()
	} else if size == ^uint64(0) {
		size = uint64(len(data))
	}
	if dir == DirOut {
		return MakeOutDataArg(typ, dir, size), nil
	}
	if diff := int(size) - len(data); diff > 0 {
		data = append(data, make([]byte, diff)...)
	}
	data = data[:size]
	if typ.Kind == BufferString && len(typ.Values) != 0 &&
		// AUTOGENERATED will be padded by 0's.
		!strings.HasPrefix(typ.Values[0], "AUTOGENERATED") {
		matched := false
		for _, val := range typ.Values {
			if string(data) == val {
				matched = true
				break
			}
		}
		if !matched {
			p.strictFailf("bad string value %q, expect %q", data, typ.Values)
			data = []byte(typ.Values[0])
		}
	}
	return MakeDataArg(typ, dir, data), nil
}

func (p *parser) parseArgStruct(typ Type, dir Dir) (Arg, error) {
	p.Parse('{')
	t1, ok := typ.(*StructType)
	if !ok {
		p.eatExcessive(false, "wrong struct arg")
		p.Parse('}')
		return typ.DefaultArg(dir), nil
	}
	var inner []Arg
	for i := 0; p.Char() != '}'; i++ {
		if i >= len(t1.Fields) {
			p.eatExcessive(false, "excessive struct %v fields", typ.Name())
			break
		}
		field := t1.Fields[i]
		if IsPad(field.Type) {
			inner = append(inner, MakeConstArg(field.Type, field.Dir(dir), 0))
		} else {
			arg, err := p.parseArg(field.Type, field.Dir(dir))
			if err != nil {
				return nil, err
			}
			inner = append(inner, arg)
			if p.Char() != '}' {
				p.Parse(',')
			}
		}
	}
	p.Parse('}')
	for len(inner) < len(t1.Fields) {
		field := t1.Fields[len(inner)]
		if !IsPad(field.Type) {
			p.strictFailf("missing struct %v fields %v/%v", typ.Name(), len(inner), len(t1.Fields))
		}
		inner = append(inner, field.Type.DefaultArg(field.Dir(dir)))
	}
	return MakeGroupArg(typ, dir, inner), nil
}

func (p *parser) parseArgArray(typ Type, dir Dir) (Arg, error) {
	p.Parse('[')
	t1, ok := typ.(*ArrayType)
	if !ok {
		p.eatExcessive(false, "wrong array arg %T", typ)
		p.Parse(']')
		return typ.DefaultArg(dir), nil
	}
	var inner []Arg
	for i := 0; p.Char() != ']'; i++ {
		arg, err := p.parseArg(t1.Elem, dir)
		if err != nil {
			return nil, err
		}
		inner = append(inner, arg)
		if p.Char() != ']' {
			p.Parse(',')
		}
	}
	p.Parse(']')
	if t1.Kind == ArrayRangeLen && t1.RangeBegin == t1.RangeEnd {
		for uint64(len(inner)) < t1.RangeBegin {
			p.strictFailf("missing array elements")
			inner = append(inner, t1.Elem.DefaultArg(dir))
		}
		inner = inner[:t1.RangeBegin]
	}
	return MakeGroupArg(typ, dir, inner), nil
}

func (p *parser) parseArgUnion(typ Type, dir Dir) (Arg, error) {
	t1, ok := typ.(*UnionType)
	if !ok {
		p.eatExcessive(true, "wrong union arg")
		return typ.DefaultArg(dir), nil
	}
	p.Parse('@')
	name := p.Ident()
	var (
		optType Type
		optDir  Dir
	)
	index := -1
	for i, field := range t1.Fields {
		if name == field.Name {
			optType, index, optDir = field.Type, i, field.Dir(dir)
			break
		}
	}
	if optType == nil {
		p.eatExcessive(true, "wrong union option")
		return typ.DefaultArg(dir), nil
	}
	var opt Arg
	if p.Char() == '=' {
		p.Parse('=')
		var err error
		opt, err = p.parseArg(optType, optDir)
		if err != nil {
			return nil, err
		}
	} else {
		opt = optType.DefaultArg(optDir)
	}
	return MakeUnionArg(typ, dir, opt, index), nil
}

// Eats excessive call arguments and struct fields to recover after description changes.
func (p *parser) eatExcessive(stopAtComma bool, what string, args ...interface{}) {
	p.strictFailf(what, args...)
	paren, brack, brace := 0, 0, 0
	for !p.EOF() && p.e == nil {
		ch := p.Char()
		switch ch {
		case '(':
			paren++
		case ')':
			if paren == 0 {
				return
			}
			paren--
		case '[':
			brack++
		case ']':
			if brack == 0 {
				return
			}
			brack--
		case '{':
			brace++
		case '}':
			if brace == 0 {
				return
			}
			brace--
		case ',':
			if stopAtComma && paren == 0 && brack == 0 && brace == 0 {
				return
			}
		case '\'', '"':
			p.Parse(ch)
			for !p.EOF() && p.Char() != ch {
				p.Parse(p.Char())
			}
			if p.EOF() {
				return
			}
		}
		p.Parse(ch)
	}
}

const (
	encodingAddrBase = 0x7f0000000000
	maxLineLen       = 1 << 20
)

func (target *Target) serializeAddr(arg *PointerArg) string {
	ssize := ""
	if arg.VmaSize != 0 {
		ssize = fmt.Sprintf("/0x%x", arg.VmaSize)
	}
	return fmt.Sprintf("(0x%x%v)", encodingAddrBase+arg.Address, ssize)
}

func (p *parser) parseAddr() (uint64, uint64, error) {
	p.Parse('(')
	pstr := p.Ident()
	addr, err := strconv.ParseUint(pstr, 0, 64)
	if err != nil {
		return 0, 0, fmt.Errorf("failed to parse addr: %q", pstr)
	}
	if addr < encodingAddrBase {
		return 0, 0, fmt.Errorf("address without base offset: %q", pstr)
	}
	addr -= encodingAddrBase
	// This is not used anymore, but left here to parse old programs.
	if p.Char() == '+' || p.Char() == '-' {
		minus := false
		if p.Char() == '-' {
			minus = true
			p.Parse('-')
		} else {
			p.Parse('+')
		}
		ostr := p.Ident()
		off, err := strconv.ParseUint(ostr, 0, 64)
		if err != nil {
			return 0, 0, fmt.Errorf("failed to parse addr offset: %q", ostr)
		}
		if minus {
			off = -off
		}
		addr += off
	}
	target := p.target
	maxMem := target.NumPages * target.PageSize
	var vmaSize uint64
	if p.Char() == '/' {
		p.Parse('/')
		pstr := p.Ident()
		size, err := strconv.ParseUint(pstr, 0, 64)
		if err != nil {
			return 0, 0, fmt.Errorf("failed to parse addr size: %q", pstr)
		}
		addr = addr & ^(target.PageSize - 1)
		vmaSize = (size + target.PageSize - 1) & ^(target.PageSize - 1)
		if vmaSize == 0 {
			vmaSize = target.PageSize
		}
		if vmaSize > maxMem {
			vmaSize = maxMem
		}
		if addr > maxMem-vmaSize {
			addr = maxMem - vmaSize
		}
	}
	p.Parse(')')
	return addr, vmaSize, nil
}

func serializeData(buf *bytes.Buffer, data []byte, readable bool) {
	if !readable && !isReadableData(data) {
		fmt.Fprintf(buf, "\"%v\"", hex.EncodeToString(data))
		return
	}
	buf.WriteByte('\'')
	encodeData(buf, data, true, false)
	buf.WriteByte('\'')
}

func EncodeData(buf *bytes.Buffer, data []byte, readable bool) {
	if !readable && isReadableData(data) {
		readable = true
	}
	encodeData(buf, data, readable, true)
}

func encodeData(buf *bytes.Buffer, data []byte, readable, cstr bool) {
	for _, v := range data {
		if !readable {
			lo, hi := byteToHex(v)
			buf.Write([]byte{'\\', 'x', hi, lo})
			continue
		}
		switch v {
		case '\a':
			buf.Write([]byte{'\\', 'a'})
		case '\b':
			buf.Write([]byte{'\\', 'b'})
		case '\f':
			buf.Write([]byte{'\\', 'f'})
		case '\n':
			buf.Write([]byte{'\\', 'n'})
		case '\r':
			buf.Write([]byte{'\\', 'r'})
		case '\t':
			buf.Write([]byte{'\\', 't'})
		case '\v':
			buf.Write([]byte{'\\', 'v'})
		case '\'':
			buf.Write([]byte{'\\', '\''})
		case '"':
			buf.Write([]byte{'\\', '"'})
		case '\\':
			buf.Write([]byte{'\\', '\\'})
		default:
			if isPrintable(v) {
				buf.WriteByte(v)
			} else {
				if cstr {
					// We would like to use hex encoding with \x,
					// but C's \x is hard to use: it can contain _any_ number of hex digits
					// (not just 2 or 4), so later non-hex encoded chars will glue to \x.
					c0 := (v>>6)&0x7 + '0'
					c1 := (v>>3)&0x7 + '0'
					c2 := (v>>0)&0x7 + '0'
					buf.Write([]byte{'\\', c0, c1, c2})
				} else {
					lo, hi := byteToHex(v)
					buf.Write([]byte{'\\', 'x', hi, lo})
				}
			}
		}
	}
}

func isReadableDataType(typ *BufferType) bool {
	return typ.Kind == BufferString || typ.Kind == BufferFilename
}

func isReadableData(data []byte) bool {
	if len(data) == 0 {
		return false
	}
	for _, v := range data {
		if isPrintable(v) {
			continue
		}
		switch v {
		case 0, '\a', '\b', '\f', '\n', '\r', '\t', '\v':
			continue
		}
		return false
	}
	return true
}

func (p *parser) deserializeData() ([]byte, error) {
	var data []byte
	if p.Char() == '"' {
		p.Parse('"')
		val := ""
		if p.Char() != '"' {
			val = p.Ident()
		}
		p.Parse('"')
		var err error
		data, err = hex.DecodeString(val)
		if err != nil {
			return nil, fmt.Errorf("data arg has bad value %q", val)
		}
	} else {
		if p.consume() != '\'' {
			return nil, fmt.Errorf("data arg does not start with \" nor with '")
		}
		for p.Char() != '\'' && p.Char() != 0 {
			v := p.consume()
			if v != '\\' {
				data = append(data, v)
				continue
			}
			v = p.consume()
			switch v {
			case 'x':
				hi := p.consume()
				lo := p.consume()
				b, ok := hexToByte(lo, hi)
				if !ok {
					return nil, fmt.Errorf("invalid hex \\x%v%v in data arg", hi, lo)
				}
				data = append(data, b)
			case 'a':
				data = append(data, '\a')
			case 'b':
				data = append(data, '\b')
			case 'f':
				data = append(data, '\f')
			case 'n':
				data = append(data, '\n')
			case 'r':
				data = append(data, '\r')
			case 't':
				data = append(data, '\t')
			case 'v':
				data = append(data, '\v')
			case '\'':
				data = append(data, '\'')
			case '"':
				data = append(data, '"')
			case '\\':
				data = append(data, '\\')
			default:
				return nil, fmt.Errorf("invalid \\%c escape sequence in data arg", v)
			}
		}
		p.Parse('\'')
	}
	return data, nil
}

func isPrintable(v byte) bool {
	return v >= 0x20 && v < 0x7f
}

func byteToHex(v byte) (lo, hi byte) {
	return toHexChar(v & 0xf), toHexChar(v >> 4)
}

func hexToByte(lo, hi byte) (byte, bool) {
	h, ok1 := fromHexChar(hi)
	l, ok2 := fromHexChar(lo)
	return h<<4 + l, ok1 && ok2
}

func toHexChar(v byte) byte {
	if v >= 16 {
		panic("bad hex char")
	}
	if v < 10 {
		return '0' + v
	}
	return 'a' + v - 10
}

func fromHexChar(v byte) (byte, bool) {
	if v >= '0' && v <= '9' {
		return v - '0', true
	}
	if v >= 'a' && v <= 'f' {
		return v - 'a' + 10, true
	}
	return 0, false
}

type parser struct {
	target  *Target
	strict  bool
	vars    map[string]*ResultArg
	autos   map[Arg]bool
	comment string

	r *bufio.Scanner
	s string
	i int
	l int
	e error
}

func newParser(target *Target, data []byte, strict bool) *parser {
	p := &parser{
		target: target,
		strict: strict,
		vars:   make(map[string]*ResultArg),
		r:      bufio.NewScanner(bytes.NewReader(data)),
	}
	p.r.Buffer(nil, maxLineLen)
	return p
}

func (p *parser) auto(arg Arg) Arg {
	if p.autos == nil {
		p.autos = make(map[Arg]bool)
	}
	p.autos[arg] = true
	return arg
}

func (p *parser) fixupAutos(prog *Prog) {
	s := analyze(nil, nil, prog, nil)
	for _, c := range prog.Calls {
		p.target.assignSizesArray(c.Args, c.Meta.Args, p.autos)
		ForeachArg(c, func(arg Arg, _ *ArgCtx) {
			if !p.autos[arg] {
				return
			}
			delete(p.autos, arg)
			switch typ := arg.Type().(type) {
			case *ConstType:
				arg.(*ConstArg).Val = typ.Val
				_ = s
			case *PtrType:
				a := arg.(*PointerArg)
				a.Address = s.ma.alloc(nil, a.Res.Size(), a.Res.Type().Alignment())
			default:
				panic(fmt.Sprintf("unsupported auto type %T", typ))
			}
		})
	}
	if len(p.autos) != 0 {
		panic(fmt.Sprintf("leftoever autos: %+v", p.autos))
	}
}

func (p *parser) Scan() bool {
	if p.e != nil {
		return false
	}
	if !p.r.Scan() {
		p.e = p.r.Err()
		return false
	}
	p.s = p.r.Text()
	p.i = 0
	p.l++
	return true
}

func (p *parser) Err() error {
	return p.e
}

func (p *parser) Str() string {
	return p.s
}

func (p *parser) EOF() bool {
	return p.i == len(p.s)
}

func (p *parser) Char() byte {
	if p.e != nil {
		return 0
	}
	if p.EOF() {
		p.failf("unexpected eof")
		return 0
	}
	return p.s[p.i]
}

func (p *parser) Parse(ch byte) {
	if p.e != nil {
		return
	}
	if p.EOF() {
		p.failf("want %s, got EOF", string(ch))
		return
	}
	if p.s[p.i] != ch {
		p.failf("want '%v', got '%v'", string(ch), string(p.s[p.i]))
		return
	}
	p.i++
	p.SkipWs()
}

func (p *parser) consume() byte {
	if p.e != nil {
		return 0
	}
	if p.EOF() {
		p.failf("unexpected eof")
		return 0
	}
	v := p.s[p.i]
	p.i++
	return v
}

func (p *parser) SkipWs() {
	for p.i < len(p.s) && (p.s[p.i] == ' ' || p.s[p.i] == '\t') {
		p.i++
	}
}

func (p *parser) Ident() string {
	i := p.i
	for p.i < len(p.s) &&
		(p.s[p.i] >= 'a' && p.s[p.i] <= 'z' ||
			p.s[p.i] >= 'A' && p.s[p.i] <= 'Z' ||
			p.s[p.i] >= '0' && p.s[p.i] <= '9' ||
			p.s[p.i] == '_' || p.s[p.i] == '$') {
		p.i++
	}
	if i == p.i {
		p.failf("failed to parse identifier at pos %v", i)
		return ""
	}
	s := p.s[i:p.i]
	p.SkipWs()
	return s
}

func (p *parser) failf(msg string, args ...interface{}) {
	if p.e == nil {
		p.e = fmt.Errorf("%v\nline #%v:%v: %v", fmt.Sprintf(msg, args...), p.l, p.i, p.s)
	}
}

func (p *parser) strictFailf(msg string, args ...interface{}) {
	if p.strict {
		p.failf(msg, args...)
	}
}

// CallSet returns a set of all calls in the program.
// It does very conservative parsing and is intended to parse past/future serialization formats.
func CallSet(data []byte) (map[string]struct{}, int, error) {
	calls := make(map[string]struct{})
	ncalls := 0
	s := bufio.NewScanner(bytes.NewReader(data))
	s.Buffer(nil, maxLineLen)
	for s.Scan() {
		ln := s.Bytes()
		if len(ln) == 0 || ln[0] == '#' {
			continue
		}
		bracket := bytes.IndexByte(ln, '(')
		if bracket == -1 {
			return nil, 0, fmt.Errorf("line does not contain opening bracket")
		}
		call := ln[:bracket]
		if eq := bytes.IndexByte(call, '='); eq != -1 {
			eq++
			for eq < len(call) && call[eq] == ' ' {
				eq++
			}
			call = call[eq:]
		}
		if len(call) == 0 {
			return nil, 0, fmt.Errorf("call name is empty")
		}
		calls[string(call)] = struct{}{}
		ncalls++
	}
	if err := s.Err(); err != nil {
		return nil, 0, err
	}
	if len(calls) == 0 {
		return nil, 0, fmt.Errorf("program does not contain any calls")
	}
	return calls, ncalls, nil
}
