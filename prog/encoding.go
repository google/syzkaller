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
	p.debugValidate()
	ctx := &serializer{
		target: p.Target,
		buf:    new(bytes.Buffer),
		vars:   make(map[*ResultArg]int),
	}
	for _, c := range p.Calls {
		ctx.call(c)
	}
	return ctx.buf.Bytes()
}

type serializer struct {
	target *Target
	buf    *bytes.Buffer
	vars   map[*ResultArg]int
	varSeq int
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
	if a.IsNull() {
		ctx.printf("0x0")
		return
	}
	target := ctx.target
	ctx.printf("&%v", target.serializeAddr(a))
	if a.Res != nil && isDefault(a.Res) && !target.isAnyPtr(a.Type()) {
		return
	}
	ctx.printf("=")
	if target.isAnyPtr(a.Type()) {
		ctx.printf("ANY=")
	}
	ctx.arg(a.Res)
}

func (a *DataArg) serialize(ctx *serializer) {
	if a.Type().Dir() == DirOut {
		ctx.printf("\"\"/%v", a.Size())
		return
	}
	data := a.Data()
	if !a.Type().Varlen() {
		// Statically typed data will be padded with 0s during
		// deserialization, so we can strip them here for readability.
		for len(data) >= 2 && data[len(data)-1] == 0 && data[len(data)-2] == 0 {
			data = data[:len(data)-1]
		}
	}
	serializeData(ctx.buf, data)
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
	if a.fixedInnerSize() {
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
	ctx.printf("@%v", a.Option.Type().FieldName())
	if isDefault(a.Option) {
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

func (target *Target) Deserialize(data []byte) (prog *Prog, err error) {
	prog = &Prog{
		Target: target,
	}
	p := newParser(data)
	vars := make(map[string]*ResultArg)
	comment := ""
	for p.Scan() {
		if p.EOF() {
			if comment != "" {
				prog.Comments = append(prog.Comments, comment)
				comment = ""
			}
			continue
		}
		if p.Char() == '#' {
			if comment != "" {
				prog.Comments = append(prog.Comments, comment)
			}
			comment = strings.TrimSpace(p.s[p.i+1:])
			continue
		}
		name := p.Ident()
		r := ""
		if p.Char() == '=' {
			r = name
			p.Parse('=')
			name = p.Ident()

		}
		meta := target.SyscallMap[name]
		if meta == nil {
			return nil, fmt.Errorf("unknown syscall %v", name)
		}
		c := &Call{
			Meta:    meta,
			Ret:     MakeReturnArg(meta.Ret),
			Comment: comment,
		}
		prog.Calls = append(prog.Calls, c)
		p.Parse('(')
		for i := 0; p.Char() != ')'; i++ {
			if i >= len(meta.Args) {
				eatExcessive(p, false)
				break
			}
			typ := meta.Args[i]
			if IsPad(typ) {
				return nil, fmt.Errorf("padding in syscall %v arguments", name)
			}
			arg, err := target.parseArg(typ, p, vars)
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
			c.Args = append(c.Args, meta.Args[i].makeDefaultArg())
		}
		if len(c.Args) != len(meta.Args) {
			return nil, fmt.Errorf("wrong call arg count: %v, want %v", len(c.Args), len(meta.Args))
		}
		if r != "" && c.Ret != nil {
			vars[r] = c.Ret
		}
		comment = ""
	}
	if comment != "" {
		prog.Comments = append(prog.Comments, comment)
	}
	if err := p.Err(); err != nil {
		return nil, err
	}
	// This validation is done even in non-debug mode because deserialization
	// procedure does not catch all bugs (e.g. mismatched types).
	// And we can receive bad programs from corpus and hub.
	if err := prog.validate(); err != nil {
		return nil, err
	}
	for _, c := range prog.Calls {
		target.SanitizeCall(c)
	}
	return
}

func (target *Target) parseArg(typ Type, p *parser, vars map[string]*ResultArg) (Arg, error) {
	r := ""
	if p.Char() == '<' {
		p.Parse('<')
		r = p.Ident()
		p.Parse('=')
		p.Parse('>')
	}
	arg, err := target.parseArgImpl(typ, p, vars)
	if err != nil {
		return nil, err
	}
	if arg == nil {
		if typ != nil {
			arg = typ.makeDefaultArg()
		} else if r != "" {
			return nil, fmt.Errorf("named nil argument")
		}
	}
	if r != "" {
		if res, ok := arg.(*ResultArg); ok {
			vars[r] = res
		}
	}
	return arg, nil
}

func (target *Target) parseArgImpl(typ Type, p *parser, vars map[string]*ResultArg) (Arg, error) {
	switch p.Char() {
	case '0':
		return target.parseArgInt(typ, p)
	case 'r':
		return target.parseArgRes(typ, p, vars)
	case '&':
		return target.parseArgAddr(typ, p, vars)
	case '"', '\'':
		return target.parseArgString(typ, p)
	case '{':
		return target.parseArgStruct(typ, p, vars)
	case '[':
		return target.parseArgArray(typ, p, vars)
	case '@':
		return target.parseArgUnion(typ, p, vars)
	case 'n':
		p.Parse('n')
		p.Parse('i')
		p.Parse('l')
		return nil, nil

	default:
		return nil, fmt.Errorf("failed to parse argument at %v (line #%v/%v: %v)",
			int(p.Char()), p.l, p.i, p.s)
	}
}

func (target *Target) parseArgInt(typ Type, p *parser) (Arg, error) {
	val := p.Ident()
	v, err := strconv.ParseUint(val, 0, 64)
	if err != nil {
		return nil, fmt.Errorf("wrong arg value '%v': %v", val, err)
	}
	switch typ.(type) {
	case *ConstType, *IntType, *FlagsType, *ProcType, *LenType, *CsumType:
		return MakeConstArg(typ, v), nil
	case *ResourceType:
		return MakeResultArg(typ, nil, v), nil
	case *PtrType, *VmaType:
		if typ.Optional() {
			return MakeNullPointerArg(typ), nil
		}
		return typ.makeDefaultArg(), nil
	default:
		eatExcessive(p, true)
		return typ.makeDefaultArg(), nil
	}
}

func (target *Target) parseArgRes(typ Type, p *parser, vars map[string]*ResultArg) (Arg, error) {
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
	v := vars[id]
	if v == nil {
		return typ.makeDefaultArg(), nil
	}
	arg := MakeResultArg(typ, v, 0)
	arg.OpDiv = div
	arg.OpAdd = add
	return arg, nil
}

func (target *Target) parseArgAddr(typ Type, p *parser, vars map[string]*ResultArg) (Arg, error) {
	var typ1 Type
	switch t1 := typ.(type) {
	case *PtrType:
		typ1 = t1.Type
	case *VmaType:
	default:
		eatExcessive(p, true)
		return typ.makeDefaultArg(), nil
	}
	p.Parse('&')
	addr, vmaSize, err := target.parseAddr(p)
	if err != nil {
		return nil, err
	}
	var inner Arg
	if p.Char() == '=' {
		p.Parse('=')
		if p.Char() == 'A' {
			p.Parse('A')
			p.Parse('N')
			p.Parse('Y')
			p.Parse('=')
			typ = target.makeAnyPtrType(typ.Size(), typ.FieldName())
			typ1 = target.any.array
		}
		inner, err = target.parseArg(typ1, p, vars)
		if err != nil {
			return nil, err
		}
	}
	if typ1 == nil {
		return MakeVmaPointerArg(typ, addr, vmaSize), nil
	}
	if inner == nil {
		inner = typ1.makeDefaultArg()
	}
	return MakePointerArg(typ, addr, inner), nil
}

func (target *Target) parseArgString(typ Type, p *parser) (Arg, error) {
	if _, ok := typ.(*BufferType); !ok {
		eatExcessive(p, true)
		return typ.makeDefaultArg(), nil
	}
	data, err := deserializeData(p)
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
	}
	if !typ.Varlen() {
		size = typ.Size()
	} else if size == ^uint64(0) {
		size = uint64(len(data))
	}
	if typ.Dir() == DirOut {
		return MakeOutDataArg(typ, size), nil
	}
	if diff := int(size) - len(data); diff > 0 {
		data = append(data, make([]byte, diff)...)
	}
	data = data[:size]
	return MakeDataArg(typ, data), nil
}

func (target *Target) parseArgStruct(typ Type, p *parser, vars map[string]*ResultArg) (Arg, error) {
	p.Parse('{')
	t1, ok := typ.(*StructType)
	if !ok {
		eatExcessive(p, false)
		p.Parse('}')
		return typ.makeDefaultArg(), nil
	}
	var inner []Arg
	for i := 0; p.Char() != '}'; i++ {
		if i >= len(t1.Fields) {
			eatExcessive(p, false)
			break
		}
		fld := t1.Fields[i]
		if IsPad(fld) {
			inner = append(inner, MakeConstArg(fld, 0))
		} else {
			arg, err := target.parseArg(fld, p, vars)
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
		inner = append(inner, t1.Fields[len(inner)].makeDefaultArg())
	}
	return MakeGroupArg(typ, inner), nil
}

func (target *Target) parseArgArray(typ Type, p *parser, vars map[string]*ResultArg) (Arg, error) {
	p.Parse('[')
	t1, ok := typ.(*ArrayType)
	if !ok {
		eatExcessive(p, false)
		p.Parse(']')
		return typ.makeDefaultArg(), nil
	}
	var inner []Arg
	for i := 0; p.Char() != ']'; i++ {
		arg, err := target.parseArg(t1.Type, p, vars)
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
			inner = append(inner, t1.Type.makeDefaultArg())
		}
		inner = inner[:t1.RangeBegin]
	}
	return MakeGroupArg(typ, inner), nil
}

func (target *Target) parseArgUnion(typ Type, p *parser, vars map[string]*ResultArg) (Arg, error) {
	t1, ok := typ.(*UnionType)
	if !ok {
		eatExcessive(p, true)
		return typ.makeDefaultArg(), nil
	}
	p.Parse('@')
	name := p.Ident()
	var optType Type
	for _, t2 := range t1.Fields {
		if name == t2.FieldName() {
			optType = t2
			break
		}
	}
	if optType == nil {
		eatExcessive(p, true)
		return typ.makeDefaultArg(), nil
	}
	var opt Arg
	if p.Char() == '=' {
		p.Parse('=')
		var err error
		opt, err = target.parseArg(optType, p, vars)
		if err != nil {
			return nil, err
		}
	} else {
		opt = optType.makeDefaultArg()
	}
	return MakeUnionArg(typ, opt), nil
}

// Eats excessive call arguments and struct fields to recover after description changes.
func eatExcessive(p *parser, stopAtComma bool) {
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

func (target *Target) parseAddr(p *parser) (uint64, uint64, error) {
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

func serializeData(buf *bytes.Buffer, data []byte) {
	readable := true
	for _, v := range data {
		if v >= 0x20 && v < 0x7f {
			continue
		}
		switch v {
		case 0, '\a', '\b', '\f', '\n', '\r', '\t', '\v':
			continue
		}
		readable = false
		break
	}
	if !readable || len(data) == 0 {
		fmt.Fprintf(buf, "\"%v\"", hex.EncodeToString(data))
		return
	}
	buf.WriteByte('\'')
	for _, v := range data {
		switch v {
		case 0:
			buf.Write([]byte{'\\', 'x', '0', '0'})
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
		case '\\':
			buf.Write([]byte{'\\', '\\'})
		default:
			buf.WriteByte(v)
		}
	}
	buf.WriteByte('\'')
}

func deserializeData(p *parser) ([]byte, error) {
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
				if lo != '0' || hi != '0' {
					return nil, fmt.Errorf(
						"invalid \\x%c%c escape sequence in data arg", hi, lo)
				}
				data = append(data, 0)
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

type parser struct {
	r *bufio.Scanner
	s string
	i int
	l int
	e error
}

func newParser(data []byte) *parser {
	p := &parser{r: bufio.NewScanner(bytes.NewReader(data))}
	p.r.Buffer(nil, maxLineLen)
	return p
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
	p.e = fmt.Errorf("%v\nline #%v: %v", fmt.Sprintf(msg, args...), p.l, p.s)
}

// CallSet returns a set of all calls in the program.
// It does very conservative parsing and is intended to parse paste/future serialization formats.
func CallSet(data []byte) (map[string]struct{}, error) {
	calls := make(map[string]struct{})
	s := bufio.NewScanner(bytes.NewReader(data))
	s.Buffer(nil, maxLineLen)
	for s.Scan() {
		ln := s.Bytes()
		if len(ln) == 0 || ln[0] == '#' {
			continue
		}
		bracket := bytes.IndexByte(ln, '(')
		if bracket == -1 {
			return nil, fmt.Errorf("line does not contain opening bracket")
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
			return nil, fmt.Errorf("call name is empty")
		}
		calls[string(call)] = struct{}{}
	}
	if err := s.Err(); err != nil {
		return nil, err
	}
	if len(calls) == 0 {
		return nil, fmt.Errorf("program does not contain any calls")
	}
	return calls, nil
}
