package trace2syz

import (
	"bytes"
	"fmt"
	"github.com/google/syzkaller/prog"
	"strconv"
)

type Operation int

const (
	ORop       = iota //OR = |
	ANDop             //AND = &
	XORop             //XOR = ^
	NOTop             //NOT = !
	LSHIFTop          //LSHIFT = <<
	RSHIFTop          //RSHIFT = >>
	ONESCOMPop        //ONESCOMP = ~
	TIMESop           //TIMES = *
	LANDop            //LAND = &&
	LORop             //LOR = ||
	LEQUALop          //LEQUAL = ==
)

//TraceTree struct contains intermediate representation of trace
//If a trace is multiprocess it constructs a trace for each type
type TraceTree struct {
	TraceMap map[int64]*Trace
	Ptree    map[int64][]int64
	RootPid  int64
	Filename string
}

//NewTraceTree initializes a TraceTree
func NewTraceTree() (tree *TraceTree) {
	tree = &TraceTree{
		TraceMap: make(map[int64]*Trace),
		Ptree:    make(map[int64][]int64),
		RootPid:  -1,
	}
	return
}

func (tree *TraceTree) Contains(pid int64) bool {
	if _, ok := tree.TraceMap[pid]; ok {
		return true
	}
	return false
}

func (tree *TraceTree) Add(call *Syscall) *Syscall {
	if tree.RootPid < 0 {
		tree.RootPid = call.Pid
	}
	if !call.Resumed {
		if !tree.Contains(call.Pid) {
			tree.TraceMap[call.Pid] = newTrace()
			tree.Ptree[call.Pid] = make([]int64, 0)
		}
	}
	c := tree.TraceMap[call.Pid].Add(call)
	if c.CallName == "clone" && !c.Paused {
		tree.Ptree[c.Pid] = append(tree.Ptree[c.Pid], c.Ret)
	}
	return c
}

func (tree *TraceTree) String() string {
	var buf bytes.Buffer

	buf.WriteString(fmt.Sprintf("Root: %d\n", tree.RootPid))
	buf.WriteString(fmt.Sprintf("Pids: %d\n", len(tree.TraceMap)))
	return buf.String()
}

//Trace is just a list of system calls
type Trace struct {
	Calls []*Syscall
}

//newTrace initializes a new trace
func newTrace() (trace *Trace) {
	trace = &Trace{Calls: make([]*Syscall, 0)}
	return
}

func (trace *Trace) Add(call *Syscall) (ret *Syscall) {
	if call.Resumed {
		lastCall := trace.Calls[len(trace.Calls)-1]
		lastCall.Args = append(lastCall.Args, call.Args...)
		lastCall.Paused = false
		lastCall.Ret = call.Ret
		ret = lastCall
	} else {
		trace.Calls = append(trace.Calls, call)
		ret = call
	}
	return
}

//Syscall struct is the IR type for any system call
type Syscall struct {
	CallName string
	Args     []irType
	Pid      int64
	Ret      int64
	Cover    []uint64
	Paused   bool
	Resumed  bool
}

//NewSyscall - constructor
func NewSyscall(pid int64, name string, args []irType, ret int64, paused bool, resumed bool) (sys *Syscall) {
	sys = new(Syscall)
	sys.CallName = name
	sys.Args = args
	sys.Pid = pid
	sys.Ret = ret
	sys.Paused = paused
	sys.Resumed = resumed
	return
}

//String
func (s *Syscall) String() string {
	var buf bytes.Buffer

	buf.WriteString(fmt.Sprintf("Pid: %d-", s.Pid))
	buf.WriteString(fmt.Sprintf("Name: %s-", s.CallName))
	for _, typ := range s.Args {
		buf.WriteString("-")
		buf.WriteString(typ.String())
		buf.WriteString("-")
	}
	buf.WriteString(fmt.Sprintf("-Ret: %d\n", s.Ret))
	return buf.String()
}

type irType interface {
	Name() string
	String() string
	Eval(*prog.Target) uint64
}

type dynamicType struct {
	BeforeCall *expression
	AfterCall  *expression
}

func newDynamicType(before, after irType) *dynamicType {
	return &dynamicType{BeforeCall: before.(*expression), AfterCall: after.(*expression)}
}

func (d *dynamicType) String() string {
	return d.BeforeCall.String()
}

func (d *dynamicType) Name() string {
	return "Dynamic Type"
}

func (d *dynamicType) Eval(target *prog.Target) uint64 {
	panic("Eval called on DynamicType")
}

type expression struct {
	BinOp     *binop
	Unop      *unop
	FlagType  *flagType
	FlagsType flags
	IntType   *intType
	MacroType *macroType
	SetType   *set
	IntsType  ints
}

func newExpression(typ irType) (exp *expression) {
	exp = new(expression)
	switch a := typ.(type) {
	case *binop:
		exp.BinOp = a
	case *unop:
		exp.Unop = a
	case *intType:
		exp.IntType = a
	case *flagType:
		exp.FlagType = a
	case flags:
		exp.FlagsType = a
	case ints:
		exp.IntsType = a
	case *macroType:
		exp.MacroType = a
	case *set:
		exp.SetType = a
	default:
		panic(fmt.Sprintf("Expression received wrong type: %s", typ.Name()))
	}
	return
}

func (r *expression) Name() string {
	return "Expression Type"
}

func (r *expression) String() string {
	if r.BinOp != nil {
		return fmt.Sprintf("Relation Expression is Binop. "+
			"Op 1: %s, Operation: %v, "+
			"Op 2: %s\n", r.BinOp.Operand1, r.BinOp.Op, r.BinOp.Operand2)
	} else if r.Unop != nil {
		return fmt.Sprintf("Relation Expression is Unop. Operand is: %v, op: %v\n", r.Unop.Operand, r.Unop.Op)

	} else if r.FlagType != nil {
		return r.FlagType.String()
	} else if r.FlagsType != nil {
		return r.FlagsType.String()
	} else if r.IntType != nil {
		return r.IntType.String()
	} else if r.IntsType != nil {
		return r.IntsType.String()
	}
	return ""
}

func (r *expression) Eval(target *prog.Target) uint64 {
	if r.BinOp != nil {
		return r.BinOp.Eval(target)
	} else if r.Unop != nil {
		return r.Unop.Eval(target)
	} else if r.FlagType != nil {
		return r.FlagType.Eval(target)
	} else if r.FlagsType != nil {
		return r.FlagsType.Eval(target)
	} else if r.IntType != nil {
		return r.IntType.Eval(target)
	} else if r.MacroType != nil {
		return r.MacroType.Eval(target)
	} else if r.IntsType != nil {
		return r.IntsType.Eval(target)
	}
	panic("Failed to eval expression")
}

type parenthetical struct {
	tmp string
}

func newParenthetical() *parenthetical {
	return &parenthetical{tmp: "tmp"}
}

type macroType struct {
	MacroName string
	Args      []irType
}

func newMacroType(name string, args []irType) (typ *macroType) {
	typ = new(macroType)
	typ.MacroName = name
	typ.Args = args
	return
}

func (m *macroType) Name() string {
	return "Macro"
}

func (m *macroType) String() string {
	var buf bytes.Buffer

	buf.WriteString("Name: " + m.MacroName + "\n")
	for _, arg := range m.Args {
		buf.WriteString("Arg: " + arg.Name() + "\n")
	}
	return buf.String()
}

func (m *macroType) Eval(target *prog.Target) uint64 {
	switch m.MacroName {
	case "KERNEL_VERSION":
		return (m.Args[0].Eval(target) << 16) + (m.Args[1].Eval(target) << 8) + m.Args[2].Eval(target)
	}
	panic("Eval called on macro type")
}

type call struct {
	CallName string
	Args     []irType
}

func newCallType(name string, args []irType) (typ *call) {
	typ = new(call)
	typ.CallName = name
	typ.Args = args
	return
}

func (c *call) Name() string {
	return "Call Type"
}

func (c *call) String() string {
	var buf bytes.Buffer

	buf.WriteString("Name: " + c.CallName + "\n")
	for _, arg := range c.Args {
		buf.WriteString("Arg: " + arg.Name() + "\n")
	}
	return buf.String()
}

func (c *call) Eval(target *prog.Target) uint64 {
	panic("Eval called on call type")
}

type binop struct {
	Operand1 *expression
	Op       Operation
	Operand2 *expression
}

func newBinop(operand1 irType, op Operation, operand2 irType) (b *binop) {
	b = new(binop)
	b.Operand1 = operand1.(*expression)
	b.Op = op
	b.Operand2 = operand2.(*expression)
	return
}

func (b *binop) Eval(target *prog.Target) uint64 {
	op1Eval := b.Operand1.Eval(target)
	op2Eval := b.Operand2.Eval(target)
	switch b.Op {
	case ANDop:
		return op1Eval & op2Eval
	case ORop:
		return op1Eval | op2Eval
	case XORop:
		return op1Eval ^ op2Eval
	case LSHIFTop:
		return op1Eval << op2Eval
	case RSHIFTop:
		return op1Eval >> op2Eval
	case TIMESop:
		return op1Eval * op2Eval
	default:
		panic("Operator Not handled")
	}
}

func (b *binop) String() string {
	return fmt.Sprintf("op1: %s op2: %s, operand: %v\n", b.Operand1.String(), b.Operand2.String(), b.Op)
}

func (b *binop) Name() string {
	return "Binop"
}

type unop struct {
	Operand *expression
	Op      Operation
}

func newUnop(operand irType, op Operation) (u *unop) {
	u = new(unop)
	u.Operand = operand.(*expression)
	u.Op = op
	return
}

func (u *unop) Eval(target *prog.Target) uint64 {
	opEval := u.Operand.Eval(target)
	switch u.Op {
	case ONESCOMPop:
		return ^opEval
	default:
		panic("Unsupported Unop Op")
	}
}

func (u *unop) String() string {
	return fmt.Sprintf("op1: %v operand: %v\n", u.Operand, u.Op)
}

func (u *unop) Name() string {
	return "Unop"
}

type field struct {
	Key string
	Val irType
}

func newField(key string, val irType) (f *field) {
	f = new(field)
	f.Key = key
	f.Val = val
	return
}

func (f *field) Name() string {
	return "Field Type"
}

func (f *field) String() string {
	return f.Val.String()
}

func (f *field) Eval(target *prog.Target) uint64 {
	return f.Val.Eval(target)
}

type intType struct {
	Val int64
}

func newIntsType(vals []int64) ints {
	ints := make([]*intType, 0)
	for _, v := range vals {
		ints = append(ints, newIntType(v))
	}
	return ints
}

func newIntType(val int64) (typ *intType) {
	typ = new(intType)
	typ.Val = val
	return
}

func (i *intType) Eval(target *prog.Target) uint64 {
	return uint64(i.Val)
}

func (i *intType) Name() string {
	return "Int Type"
}

func (i *intType) String() string {
	return strconv.FormatInt(i.Val, 10)
}

type flags []*flagType

type ints []*intType

func (f flags) Eval(target *prog.Target) uint64 {
	if len(f) > 1 {
		var val uint64
		for _, flag := range f {
			val |= flag.Eval(target)
		}
		return val
	} else if len(f) == 1 {
		return f[0].Eval(target)
	} else {
		return 0
	}
}

func (f flags) Name() string {
	return "Flags Type"
}

func (f flags) String() string {
	if len(f) > 1 {
		panic("Cannot get string for set")
	} else if len(f) == 1 {
		return f[0].String()
	} else {
		return ""
	}
}
func (i ints) Eval(target *prog.Target) uint64 {
	if len(i) > 1 {
		panic("Unable to Evaluate Set")
	} else if len(i) == 1 {
		return i[0].Eval(target)
	} else {
		return 0
	}
}

func (i ints) Name() string {
	return "Flags Type"
}

func (i ints) String() string {
	if len(i) > 1 {
		panic("Cannot get string for set")
	} else if len(i) == 1 {
		return i[0].String()
	} else {
		return ""
	}
}

type flagType struct {
	Val string
}

func newFlagType(val string) (typ *flagType) {
	typ = new(flagType)
	typ.Val = val
	return
}

func (f *flagType) Eval(target *prog.Target) uint64 {
	if val, ok := target.ConstMap[f.String()]; ok {
		return val
	} else if val, ok := specialConsts[f.String()]; ok {
		return val
	}
	panic(fmt.Sprintf("Failed to eval flag: %s\n", f.String()))
}

func (f *flagType) Name() string {
	return "Flag Type"
}

func (f *flagType) String() string {
	return f.Val
}

type set struct {
	Exprs []*expression
}

func (b *set) Name() string {
	return "Set Type"
}

func (b *set) String() string {
	return ""
}

func (b *set) Eval(target *prog.Target) uint64 {
	panic("Eval called for set type\n")
}

type bufferType struct {
	Val string
}

func newBufferType(val string) (typ *bufferType) {
	typ = new(bufferType)
	typ.Val = val
	return
}

func (b *bufferType) Name() string {
	return "Buffer Type"
}

func (b *bufferType) String() string {
	return fmt.Sprintf("String Type: %d\n", len(b.Val))
}

func (b *bufferType) Eval(target *prog.Target) uint64 {
	panic("Eval called for buffer type")
}

type pointerType struct {
	Address uint64
	Res     irType
}

func newPointerType(addr uint64, res irType) (typ *pointerType) {
	typ = new(pointerType)
	typ.Res = res
	typ.Address = addr
	return
}

func nullPointer() (typ *pointerType) {
	typ = new(pointerType)
	typ.Address = 0
	typ.Res = newBufferType("")
	return
}

func (p *pointerType) IsNull() bool {
	return p.Address == 0
}

func (p *pointerType) Name() string {
	return "Pointer Type"
}

func (p *pointerType) String() string {
	var buf bytes.Buffer

	buf.WriteString(fmt.Sprintf("Address: %d\n", p.Address))
	buf.WriteString(fmt.Sprintf("Res: %s\n", p.Res.String()))
	return buf.String()
}

func (p *pointerType) Eval(target *prog.Target) uint64 {
	panic("Eval called for PointerType")
}

type structType struct {
	Fields []irType
}

func newStructType(types []irType) (typ *structType) {
	typ = new(structType)
	typ.Fields = types
	return
}

func (s *structType) Name() string {
	return "Struct Type"
}

func (s *structType) String() string {
	var buf bytes.Buffer

	buf.WriteString("{")
	for _, field := range s.Fields {
		buf.WriteString(field.String())
		buf.WriteString(",")
	}
	buf.WriteString("}")
	return buf.String()
}

func (s *structType) Eval(target *prog.Target) uint64 {
	panic("Eval Called For Struct Type")
}

type arrayType struct {
	Elems []irType
	Len   int
}

func newArrayType(elems []irType) (typ *arrayType) {
	typ = new(arrayType)
	typ.Elems = elems
	typ.Len = len(elems)
	return
}

func (a *arrayType) Name() string {
	return "Array Type"
}

func (a *arrayType) String() string {
	var buf bytes.Buffer

	buf.WriteString("[")
	for _, elem := range a.Elems {
		buf.WriteString(elem.String())
		buf.WriteString(",")
	}
	buf.WriteString("]")
	return buf.String()
}

func (a *arrayType) Eval(target *prog.Target) uint64 {
	panic("Eval called for Array Type")
}

type ipType struct {
	Str string
}

func newIPType(val string) (typ *ipType) {
	typ = new(ipType)
	typ.Str = val
	return
}

func (i *ipType) Name() string {
	return "Ip Type"
}

func (i *ipType) String() string {
	return fmt.Sprintf("Ip type :%s", i.Str)
}

func (i *ipType) Eval(target *prog.Target) uint64 {
	panic("Eval called for ip type")
}
