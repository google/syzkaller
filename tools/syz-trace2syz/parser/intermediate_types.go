// Copyright 2018 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package parser

import (
	"bytes"
	"fmt"
	"github.com/google/syzkaller/pkg/log"
	"github.com/google/syzkaller/prog"
	"github.com/google/syzkaller/tools/syz-trace2syz/config"
)

type operation int

const (
	orOp       = iota // OR = |
	andOp             // AND = &
	xorOp             // XOR = ^
	lshiftOp          // LSHIFT = <<
	rshiftOp          // RSHIFT = >>
	onescompOp        // ONESCOMP = ~
	timesOp           // TIMES = *
	landOp            // LAND = &&
	lorOp             // LOR = ||
	lequalOp          // LEQUAL = ==
	negOp             // MINUS -x
	plusOp            // A + B
	minusOp           // A - B
)

// TraceTree struct contains intermediate representation of trace
// If a trace is multiprocess it constructs a trace for each type
type TraceTree struct {
	TraceMap map[int64]*Trace
	Ptree    map[int64][]int64
	RootPid  int64
	Filename string
}

// NewTraceTree initializes a TraceTree
func NewTraceTree() (tree *TraceTree) {
	tree = &TraceTree{
		TraceMap: make(map[int64]*Trace),
		Ptree:    make(map[int64][]int64),
		RootPid:  -1,
	}
	return
}

func (tree *TraceTree) add(call *Syscall) *Syscall {
	if tree.RootPid < 0 {
		tree.RootPid = call.Pid
	}
	if !call.Resumed {
		if tree.TraceMap[call.Pid] == nil {
			tree.TraceMap[call.Pid] = new(Trace)
			tree.Ptree[call.Pid] = make([]int64, 0)
		}
	}
	c := tree.TraceMap[call.Pid].add(call)
	if c.CallName == "clone" && !c.Paused {
		tree.Ptree[c.Pid] = append(tree.Ptree[c.Pid], c.Ret)
	}
	return c
}

// Trace is just a list of system calls
type Trace struct {
	Calls []*Syscall
}

func (trace *Trace) add(call *Syscall) (ret *Syscall) {
	if !call.Resumed {
		trace.Calls = append(trace.Calls, call)
		ret = call
		return
	}
	lastCall := trace.Calls[len(trace.Calls)-1]
	lastCall.Args = append(lastCall.Args, call.Args...)
	lastCall.Paused = false
	lastCall.Ret = call.Ret
	ret = lastCall
	return
}

// IrType is the intermediate representation of the strace output
// Every argument of a system call should be represented in an intermediate type
type IrType interface {
	String() string
}

// Syscall struct is the IR type for any system call
type Syscall struct {
	CallName string
	Args     []IrType
	Pid      int64
	Ret      int64
	Cover    []uint64
	Paused   bool
	Resumed  bool
}

// NewSyscall - constructor
func NewSyscall(pid int64, name string, args []IrType, ret int64, paused, resumed bool) (sys *Syscall) {
	return &Syscall{
		CallName: name,
		Args:     args,
		Pid:      pid,
		Ret:      ret,
		Paused:   paused,
		Resumed:  resumed,
	}
}

// String
func (s *Syscall) String() string {
	buf := new(bytes.Buffer)

	fmt.Fprintf(buf, "Pid: -%v-", s.Pid)
	fmt.Fprintf(buf, "Name: -%v-", s.CallName)
	for _, typ := range s.Args {
		buf.WriteString("-")
		buf.WriteString(typ.String())
		buf.WriteString("-")
	}
	buf.WriteString(fmt.Sprintf("-Ret: %d\n", s.Ret))
	return buf.String()
}

// Call Represents arguments that are expanded by strace into calls
// E.g. inet_addr("127.0.0.1")
type Call struct {
	CallName string
	Args     []IrType
}

func newCallType(name string, args []IrType) *Call {
	return &Call{CallName: name, Args: args}
}

// String implements IrType String()
func (c *Call) String() string {
	buf := new(bytes.Buffer)
	buf.WriteString("Name: " + c.CallName + "\n")
	for _, arg := range c.Args {
		buf.WriteString(fmt.Sprintf("Arg: #%v\n", arg))
	}
	return buf.String()
}

// Eval implements Expression's Eval()
func (c *Call) Eval(target *prog.Target) uint64 {
	return EvalCalls(target, c)
}

// GroupType contains arrays and structs
type GroupType struct {
	Elems []IrType
}

func newGroupType(elems []IrType) (typ *GroupType) {
	return &GroupType{Elems: elems}
}

// String implements IrType String()
func (a *GroupType) String() string {
	var buf bytes.Buffer

	buf.WriteString("[")
	for _, elem := range a.Elems {
		buf.WriteString(elem.String())
		buf.WriteString(",")
	}
	buf.WriteString("]")
	return buf.String()
}

// Expression represents Ints, Flags, Arithmetic expressions
type Expression interface {
	IrType
	Eval(*prog.Target) uint64
}

type binOp struct {
	leftOp  Expression
	op      operation
	rightOp Expression
}

func newBinop(leftOperand, rightOperand IrType, Op operation) *binOp {
	return &binOp{leftOp: leftOperand.(Expression), rightOp: rightOperand.(Expression), op: Op}
}

// Eval implements Expression's Eval()
func (b *binOp) Eval(target *prog.Target) uint64 {
	op1Eval := b.leftOp.Eval(target)
	op2Eval := b.rightOp.Eval(target)
	switch b.op {
	case andOp:
		return op1Eval & op2Eval
	case orOp:
		return op1Eval | op2Eval
	case xorOp:
		return op1Eval ^ op2Eval
	case lshiftOp:
		return op1Eval << op2Eval
	case rshiftOp:
		return op1Eval >> op2Eval
	case timesOp:
		return op1Eval * op2Eval
	case minusOp:
		return op1Eval - op2Eval
	case plusOp:
		return op1Eval + op2Eval
	default:
		log.Fatalf("Unable to handle op: %d", b.op)
		return 0
	}
}

// String implements IrType String()
func (b *binOp) String() string {
	return fmt.Sprintf("op1: %s op2: %s, operand: %v\n", b.leftOp.String(), b.rightOp.String(), b.op)
}

type unOp struct {
	op      operation
	operand Expression
}

func newUnop(operand IrType, op operation) *unOp {
	return &unOp{op: op, operand: operand.(Expression)}
}

// Eval implements Expression's Eval()
func (u *unOp) Eval(target *prog.Target) uint64 {
	opEval := u.operand.Eval(target)
	switch u.op {
	case onescompOp:
		return ^opEval
	case negOp:
		return -opEval
	default:
		log.Fatalf("Unsupported Unop Op: %d", u.op)
	}
	return 0
}

// String implements IrType String()
func (u *unOp) String() string {
	return fmt.Sprintf("op1: %v operand: %v\n", u.operand, u.op)
}

// BufferType contains strings
type BufferType struct {
	Val string
}

func newBufferType(val string) *BufferType {
	return &BufferType{Val: val}
}

// String implements IrType String()
func (b *BufferType) String() string {
	return fmt.Sprintf("Buffer: %s with length: %d\n", b.Val, len(b.Val))
}

// Flags contains set of flagTypes. Most of the time will contain just 1 element
type Flags []*flagType

// Ints Contains set of intTypes. Most of the time will contain just 1 element
type Ints []int64

// NewIntsType - Constructor
func NewIntsType(vals []int64) Ints {
	var ints []int64
	ints = append(ints, vals...)
	return ints
}

// Eval implements Expression's Eval()
func (f Flags) Eval(target *prog.Target) uint64 {
	var val uint64
	for _, v := range f {
		val |= v.eval(target)
	}
	return val
}

// String implements IrType String()
func (f Flags) String() string {
	s := ""
	for _, v := range f {
		s += " " + v.string()
	}
	return s[1:]
}

// Eval implements Expression's Eval()
func (i Ints) Eval(target *prog.Target) uint64 {
	if len(i) > 1 {
		// We need to handle this case by case. We allow more than one elemnt
		// just to properly parse the traces
		log.Fatalf("Cannot evaluate Ints with more than one element")
	}
	if len(i) == 1 {
		return uint64(i[0])
	}
	return 0
}

// String implements IrType String()
func (i Ints) String() string {
	if len(i) == 1 {
		return fmt.Sprintf("%d", i[0])
	}
	return ""
}

type flagType struct {
	Val string
}

func newFlagType(val string) (typ *flagType) {
	return &flagType{Val: val}
}

func (f *flagType) eval(target *prog.Target) uint64 {
	flag := f.string()
	if trueFlag, ok := config.Consts[flag]; ok {
		flag = trueFlag
	}
	if val, ok := target.ConstMap[flag]; ok {
		return val
	}
	if _, ok := config.Ignore[flag]; ok {
		return 0
	}
	log.Fatalf("Failed to eval flag: %s", flag)
	return 0
}

func (f *flagType) string() string {
	return f.Val
}

// PointerType holds pointers from strace e.g. NULL, 0x7f24234234, &2342342={...}
type PointerType struct {
	Address uint64
	Res     IrType
}

// NewPointerType - Constructor
func NewPointerType(addr uint64, res IrType) *PointerType {
	return &PointerType{Res: res, Address: addr}
}

func nullPointer() (typ *PointerType) {
	return &PointerType{Res: newBufferType(""), Address: 0}
}

// IsNull checks if pointer is null
func (p *PointerType) IsNull() bool {
	return p.Address == 0
}

// String implements IrType String()
func (p *PointerType) String() string {
	buf := new(bytes.Buffer)
	fmt.Fprintf(buf, "Address: %d\n", p.Address)
	fmt.Fprintf(buf, "Res: %s\n", p.Res.String())
	return buf.String()
}
