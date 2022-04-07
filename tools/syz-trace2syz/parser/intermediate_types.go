// Copyright 2018 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package parser

import (
	"bytes"
	"fmt"
)

// TraceTree struct contains intermediate representation of trace.
// If a trace is multiprocess it constructs a trace for each type.
type TraceTree struct {
	TraceMap map[int64]*Trace
	Ptree    map[int64][]int64
	RootPid  int64
}

// NewTraceTree initializes a TraceTree.
func NewTraceTree() *TraceTree {
	return &TraceTree{
		TraceMap: make(map[int64]*Trace),
		Ptree:    make(map[int64][]int64),
	}
}

func (tree *TraceTree) add(call *Syscall) {
	if tree.RootPid == 0 {
		tree.RootPid = call.Pid
	}
	if tree.TraceMap[call.Pid] == nil {
		tree.TraceMap[call.Pid] = new(Trace)
	}
	c := tree.TraceMap[call.Pid].add(call)
	if c.CallName == "clone" && !c.Paused {
		tree.Ptree[c.Pid] = append(tree.Ptree[c.Pid], c.Ret)
	}
}

// Trace is just a list of system calls
type Trace struct {
	Calls []*Syscall
}

func (trace *Trace) add(call *Syscall) *Syscall {
	if !call.Resumed {
		trace.Calls = append(trace.Calls, call)
		return call
	}
	lastCall := trace.Calls[len(trace.Calls)-1]
	lastCall.Args = append(lastCall.Args, call.Args...)
	lastCall.Paused = false
	lastCall.Ret = call.Ret
	return lastCall
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

func (s *Syscall) String() string {
	buf := new(bytes.Buffer)
	fmt.Fprintf(buf, "Pid: -%v-Name: -%v-", s.Pid, s.CallName)
	for _, typ := range s.Args {
		fmt.Fprintf(buf, "-%v-", typ)
	}
	fmt.Fprintf(buf, "-Ret: %d\n", s.Ret)
	return buf.String()
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

// Constant represents all evaluated expressions produced by strace
// Constant types are evaluated at parse time
type Constant uint64

func (c Constant) String() string {
	return fmt.Sprintf("%#v", c)
}

func (c Constant) Val() uint64 {
	return uint64(c)
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
	return fmt.Sprintf("Buffer: %v with length: %v\n", b.Val, len(b.Val))
}
