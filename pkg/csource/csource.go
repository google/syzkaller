// Copyright 2015 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

// Package csource generates [almost] equivalent C programs from syzkaller programs.
//
// Outline of the process:
//   - inputs to the generation are the program and options
//   - options control multiple aspects of the resulting C program,
//     like if we want a multi-threaded program or a single-threaded,
//     what type of sandbox we want to use, if we want to setup net devices or not, etc
//   - we use actual executor sources as the base
//   - gen.go takes all executor/common*.h headers and bundles them into generated.go
//   - during generation we tear executor headers apart and take only the bits
//     we need for the current program/options, this is done by running C preprocessor
//     with particular set of defines so that the preprocessor removes unneeded
//     #ifdef SYZ_FOO sections
//   - then we generate actual syscall calls with the given arguments
//     based on the binary "encodingexec" representation of the program
//     (the same representation executor uses for interpretation)
//   - then we glue it all together
//   - as the last step we run some text post-processing on the resulting source code:
//     remove debug calls, replace exitf/fail with exit, hoist/sort/dedup includes,
//     remove duplicate empty lines, etc
package csource

import (
	"bytes"
	"fmt"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/google/syzkaller/prog"
	"github.com/google/syzkaller/sys/targets"
)

// Write generates C source for program p based on the provided options opt.
func Write(p *prog.Prog, opts Options) ([]byte, error) {
	if err := opts.Check(p.Target.OS); err != nil {
		return nil, fmt.Errorf("csource: invalid opts: %v", err)
	}
	ctx := &context{
		p:         p,
		opts:      opts,
		target:    p.Target,
		sysTarget: targets.Get(p.Target.OS, p.Target.Arch),
		calls:     make(map[string]uint64),
	}
	return ctx.generateSource()
}

type context struct {
	p         *prog.Prog
	opts      Options
	target    *prog.Target
	sysTarget *targets.Target
	calls     map[string]uint64 // CallName -> NR
}

func generateSandboxFunctionSignature(sandboxName string, sandboxArg int) string {
	if sandboxName == "" {
		return "loop();"
	}

	arguments := "();"
	if sandboxName == "android" {
		arguments = "(" + strconv.Itoa(sandboxArg) + ");"
	}
	return "do_sandbox_" + sandboxName + arguments
}

func (ctx *context) generateSource() ([]byte, error) {
	ctx.filterCalls()
	calls, vars, err := ctx.generateProgCalls(ctx.p, ctx.opts.Trace)
	if err != nil {
		return nil, err
	}

	mmapProg := ctx.p.Target.DataMmapProg()
	mmapCalls, _, err := ctx.generateProgCalls(mmapProg, false)
	if err != nil {
		return nil, err
	}

	for _, c := range append(mmapProg.Calls, ctx.p.Calls...) {
		ctx.calls[c.Meta.CallName] = c.Meta.NR
		for _, dep := range ctx.sysTarget.PseudoSyscallDeps[c.Meta.CallName] {
			depCall := ctx.target.SyscallMap[dep]
			if depCall == nil {
				panic(dep + " is specified in PseudoSyscallDeps, but not present")
			}
			ctx.calls[depCall.CallName] = depCall.NR
		}
	}

	varsBuf := new(bytes.Buffer)
	if len(vars) != 0 {
		fmt.Fprintf(varsBuf, "uint64 r[%v] = {", len(vars))
		for i, v := range vars {
			if i != 0 {
				fmt.Fprintf(varsBuf, ", ")
			}
			fmt.Fprintf(varsBuf, "0x%x", v)
		}
		fmt.Fprintf(varsBuf, "};\n")
	}

	sandboxFunc := generateSandboxFunctionSignature(ctx.opts.Sandbox, ctx.opts.SandboxArg)
	replacements := map[string]string{
		"PROCS":           fmt.Sprint(ctx.opts.Procs),
		"REPEAT_TIMES":    fmt.Sprint(ctx.opts.RepeatTimes),
		"NUM_CALLS":       fmt.Sprint(len(ctx.p.Calls)),
		"MMAP_DATA":       strings.Join(mmapCalls, ""),
		"SYSCALL_DEFINES": ctx.generateSyscallDefines(),
		"SANDBOX_FUNC":    sandboxFunc,
		"RESULTS":         varsBuf.String(),
		"SYSCALLS":        ctx.generateSyscalls(calls, len(vars) != 0),
	}
	if !ctx.opts.Threaded && !ctx.opts.Repeat && ctx.opts.Sandbox == "" {
		// This inlines syscalls right into main for the simplest case.
		replacements["SANDBOX_FUNC"] = replacements["SYSCALLS"]
		replacements["SYSCALLS"] = "unused"
	}
	timeouts := ctx.sysTarget.Timeouts(ctx.opts.Slowdown)
	replacements["PROGRAM_TIMEOUT_MS"] = fmt.Sprint(int(timeouts.Program / time.Millisecond))
	timeoutExpr := fmt.Sprint(int(timeouts.Syscall / time.Millisecond))
	replacements["BASE_CALL_TIMEOUT_MS"] = timeoutExpr
	for i, call := range ctx.p.Calls {
		if timeout := call.Meta.Attrs.Timeout; timeout != 0 {
			timeoutExpr += fmt.Sprintf(" + (call == %v ? %v : 0)", i, timeout*uint64(timeouts.Scale))
		}
	}
	replacements["CALL_TIMEOUT_MS"] = timeoutExpr
	if ctx.p.RequiredFeatures().Async {
		conditions := []string{}
		for idx, call := range ctx.p.Calls {
			if !call.Props.Async {
				continue
			}
			conditions = append(conditions, fmt.Sprintf("call == %v", idx))
		}
		replacements["ASYNC_CONDITIONS"] = strings.Join(conditions, " || ")
	}

	result, err := createCommonHeader(ctx.p, mmapProg, replacements, ctx.opts)
	if err != nil {
		return nil, err
	}
	const header = "// autogenerated by syzkaller (https://github.com/google/syzkaller)\n\n"
	result = append([]byte(header), result...)
	result = ctx.postProcess(result)
	return result, nil
}

// This is a kludge, but we keep it here until a better approach is implemented.
// TODO: untie syz_emit_ethernet/syz_extract_tcp_res and NetInjection. And also
// untie VhciInjection and syz_emit_vhci. Then we could remove this method.
func (ctx *context) filterCalls() {
	p := ctx.p
	for i := 0; i < len(p.Calls); {
		call := p.Calls[i]
		callName := call.Meta.CallName
		emitCall := (ctx.opts.NetInjection ||
			callName != "syz_emit_ethernet" &&
				callName != "syz_extract_tcp_res") &&
			(ctx.opts.VhciInjection || callName != "syz_emit_vhci")
		if emitCall {
			i++
			continue
		}
		// Remove the call.
		if ctx.p == p {
			// We lazily clone the program to avoid unnecessary copying.
			p = ctx.p.Clone()
		}
		p.RemoveCall(i)
	}
	ctx.p = p
}

func (ctx *context) generateSyscalls(calls []string, hasVars bool) string {
	opts := ctx.opts
	buf := new(bytes.Buffer)
	if !opts.Threaded && !opts.Collide {
		if len(calls) > 0 && (hasVars || opts.Trace) {
			fmt.Fprintf(buf, "\tintptr_t res = 0;\n")
		}
		if opts.Repro {
			fmt.Fprintf(buf, "\tif (write(1, \"executing program\\n\", sizeof(\"executing program\\n\") - 1)) {}\n")
		}
		if opts.Trace {
			fmt.Fprintf(buf, "\tfprintf(stderr, \"### start\\n\");\n")
		}
		for _, c := range calls {
			fmt.Fprintf(buf, "%s", c)
		}
	} else if len(calls) > 0 {
		if hasVars || opts.Trace {
			fmt.Fprintf(buf, "\tintptr_t res = 0;\n")
		}
		fmt.Fprintf(buf, "\tswitch (call) {\n")
		for i, c := range calls {
			fmt.Fprintf(buf, "\tcase %v:\n", i)
			fmt.Fprintf(buf, "%s", strings.Replace(c, "\t", "\t\t", -1))
			fmt.Fprintf(buf, "\t\tbreak;\n")
		}
		fmt.Fprintf(buf, "\t}\n")
	}
	return buf.String()
}

func (ctx *context) generateSyscallDefines() string {
	var calls []string
	for name, nr := range ctx.calls {
		if !ctx.sysTarget.SyscallNumbers ||
			strings.HasPrefix(name, "syz_") || !ctx.sysTarget.NeedSyscallDefine(nr) {
			continue
		}
		calls = append(calls, name)
	}
	sort.Strings(calls)
	buf := new(bytes.Buffer)
	prefix := ctx.sysTarget.SyscallPrefix
	for _, name := range calls {
		fmt.Fprintf(buf, "#ifndef %v%v\n", prefix, name)
		fmt.Fprintf(buf, "#define %v%v %v\n", prefix, name, ctx.calls[name])
		fmt.Fprintf(buf, "#endif\n")
	}
	if ctx.target.OS == targets.Linux && ctx.target.PtrSize == 4 {
		// This is a dirty hack.
		// On 32-bit linux mmap translated to old_mmap syscall which has a different signature.
		// mmap2 has the right signature. syz-extract translates mmap to mmap2, do the same here.
		fmt.Fprintf(buf, "#undef __NR_mmap\n")
		fmt.Fprintf(buf, "#define __NR_mmap __NR_mmap2\n")
	}
	return buf.String()
}

func (ctx *context) generateProgCalls(p *prog.Prog, trace bool) ([]string, []uint64, error) {
	exec := make([]byte, prog.ExecBufferSize)
	progSize, err := p.SerializeForExec(exec)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to serialize program: %v", err)
	}
	decoded, err := ctx.target.DeserializeExec(exec[:progSize])
	if err != nil {
		return nil, nil, err
	}
	calls, vars := ctx.generateCalls(decoded, trace)
	return calls, vars, nil
}

func (ctx *context) generateCalls(p prog.ExecProg, trace bool) ([]string, []uint64) {
	var calls []string
	csumSeq := 0
	for ci, call := range p.Calls {
		w := new(bytes.Buffer)
		// Copyin.
		for _, copyin := range call.Copyin {
			ctx.copyin(w, &csumSeq, copyin)
		}

		if call.Props.FailNth > 0 {
			fmt.Fprintf(w, "\tinject_fault(%v);\n", call.Props.FailNth)
		}
		// Call itself.
		resCopyout := call.Index != prog.ExecNoCopyout
		argCopyout := len(call.Copyout) != 0

		ctx.emitCall(w, call, ci, resCopyout || argCopyout, trace)

		if call.Props.Rerun > 0 {
			// TODO: remove this legacy C89-style definition once we figure out what to do with Akaros.
			fmt.Fprintf(w, "\t{\n\tint i;\n")
			fmt.Fprintf(w, "\tfor(i = 0; i < %v; i++) {\n", call.Props.Rerun)
			// Rerun invocations should not affect the result value.
			ctx.emitCall(w, call, ci, false, false)
			fmt.Fprintf(w, "\t\t}\n\t}\n")
		}
		// Copyout.
		if resCopyout || argCopyout {
			ctx.copyout(w, call, resCopyout)
		}
		calls = append(calls, w.String())
	}
	return calls, p.Vars
}

func (ctx *context) emitCall(w *bytes.Buffer, call prog.ExecCall, ci int, haveCopyout, trace bool) {
	callName := call.Meta.CallName
	_, trampoline := ctx.sysTarget.SyscallTrampolines[callName]
	native := ctx.sysTarget.SyscallNumbers && !strings.HasPrefix(callName, "syz_") && !trampoline
	fmt.Fprintf(w, "\t")
	if !native {
		// This mimics the same as executor does for execute_syscall,
		// but only for non-native syscalls to reduce clutter (native syscalls are assumed to not crash).
		// Arrange for res = -1 in case of syscall abort, we care about errno only if we are tracing for pkg/runtest.
		if haveCopyout || trace {
			fmt.Fprintf(w, "res = -1;\n\t")
		}
		if trace {
			fmt.Fprintf(w, "errno = EFAULT;\n\t")
		}
		fmt.Fprintf(w, "NONFAILING(")
	}
	if haveCopyout || trace {
		fmt.Fprintf(w, "res = ")
	}
	ctx.emitCallBody(w, call, native)
	if !native {
		fmt.Fprintf(w, ")") // close NONFAILING macro
	}
	fmt.Fprintf(w, ");")
	comment := ctx.target.AnnotateCall(call)
	if comment != "" {
		fmt.Fprintf(w, " /* %s */", comment)
	}
	fmt.Fprintf(w, "\n")
	if trace {
		cast := ""
		if !native && !strings.HasPrefix(callName, "syz_") {
			// Potentially we casted a function returning int to a function returning intptr_t.
			// So instead of intptr_t -1 we can get 0x00000000ffffffff. Sign extend it to intptr_t.
			cast = "(intptr_t)(int)"
		}
		fmt.Fprintf(w, "\tfprintf(stderr, \"### call=%v errno=%%u\\n\", %vres == -1 ? errno : 0);\n", ci, cast)
	}
}

func (ctx *context) emitCallBody(w *bytes.Buffer, call prog.ExecCall, native bool) {
	callName, ok := ctx.sysTarget.SyscallTrampolines[call.Meta.CallName]
	if !ok {
		callName = call.Meta.CallName
	}
	if native {
		fmt.Fprintf(w, "syscall(%v%v", ctx.sysTarget.SyscallPrefix, callName)
	} else if strings.HasPrefix(callName, "syz_") {
		fmt.Fprintf(w, "%v(", callName)
	} else {
		args := strings.Repeat(",intptr_t", len(call.Args)+call.Meta.MissingArgs)
		if args != "" {
			args = args[1:]
		}
		fmt.Fprintf(w, "((intptr_t(*)(%v))CAST(%v))(", args, callName)
	}
	for ai, arg := range call.Args {
		if native || ai > 0 {
			fmt.Fprintf(w, ", ")
		}
		switch arg := arg.(type) {
		case prog.ExecArgConst:
			if arg.Format != prog.FormatNative && arg.Format != prog.FormatBigEndian {
				panic("sring format in syscall argument")
			}
			fmt.Fprintf(w, "%v", ctx.constArgToStr(arg, true, native))
		case prog.ExecArgResult:
			if arg.Format != prog.FormatNative && arg.Format != prog.FormatBigEndian {
				panic("sring format in syscall argument")
			}
			val := ctx.resultArgToStr(arg)
			if native && ctx.target.PtrSize == 4 {
				// syscall accepts args as ellipsis, resources are uint64
				// and take 2 slots without the cast, which would be wrong.
				val = "(intptr_t)" + val
			}
			fmt.Fprintf(w, "%v", val)
		default:
			panic(fmt.Sprintf("unknown arg type: %+v", arg))
		}
	}
	for i := 0; i < call.Meta.MissingArgs; i++ {
		if native || len(call.Args) != 0 {
			fmt.Fprintf(w, ", ")
		}
		fmt.Fprintf(w, "0")
	}
}

func (ctx *context) generateCsumInet(w *bytes.Buffer, addr uint64, arg prog.ExecArgCsum, csumSeq int) {
	fmt.Fprintf(w, "\tstruct csum_inet csum_%d;\n", csumSeq)
	fmt.Fprintf(w, "\tcsum_inet_init(&csum_%d);\n", csumSeq)
	for i, chunk := range arg.Chunks {
		switch chunk.Kind {
		case prog.ExecArgCsumChunkData:
			fmt.Fprintf(w, "\tNONFAILING(csum_inet_update(&csum_%d, (const uint8*)0x%x, %d));\n",
				csumSeq, chunk.Value, chunk.Size)
		case prog.ExecArgCsumChunkConst:
			fmt.Fprintf(w, "\tuint%d csum_%d_chunk_%d = 0x%x;\n",
				chunk.Size*8, csumSeq, i, chunk.Value)
			fmt.Fprintf(w, "\tcsum_inet_update(&csum_%d, (const uint8*)&csum_%d_chunk_%d, %d);\n",
				csumSeq, csumSeq, i, chunk.Size)
		default:
			panic(fmt.Sprintf("unknown checksum chunk kind %v", chunk.Kind))
		}
	}
	fmt.Fprintf(w, "\tNONFAILING(*(uint16*)0x%x = csum_inet_digest(&csum_%d));\n",
		addr, csumSeq)
}

func (ctx *context) copyin(w *bytes.Buffer, csumSeq *int, copyin prog.ExecCopyin) {
	switch arg := copyin.Arg.(type) {
	case prog.ExecArgConst:
		if arg.BitfieldOffset == 0 && arg.BitfieldLength == 0 {
			ctx.copyinVal(w, copyin.Addr, arg.Size, ctx.constArgToStr(arg, true, false), arg.Format)
		} else {
			if arg.Format != prog.FormatNative && arg.Format != prog.FormatBigEndian {
				panic("bitfield+string format")
			}
			htobe := ""
			if ctx.target.LittleEndian && arg.Format == prog.FormatBigEndian {
				htobe = fmt.Sprintf("htobe%v", arg.Size*8)
			}
			bitfieldOffset := arg.BitfieldOffset
			if !ctx.target.LittleEndian {
				bitfieldOffset = arg.Size*8 - arg.BitfieldOffset - arg.BitfieldLength
			}
			fmt.Fprintf(w, "\tNONFAILING(STORE_BY_BITMASK(uint%v, %v, 0x%x, %v, %v, %v));\n",
				arg.Size*8, htobe, copyin.Addr, ctx.constArgToStr(arg, false, false),
				bitfieldOffset, arg.BitfieldLength)
		}
	case prog.ExecArgResult:
		ctx.copyinVal(w, copyin.Addr, arg.Size, ctx.resultArgToStr(arg), arg.Format)
	case prog.ExecArgData:
		if bytes.Equal(arg.Data, bytes.Repeat(arg.Data[:1], len(arg.Data))) {
			fmt.Fprintf(w, "\tNONFAILING(memset((void*)0x%x, %v, %v));\n",
				copyin.Addr, arg.Data[0], len(arg.Data))
		} else {
			fmt.Fprintf(w, "\tNONFAILING(memcpy((void*)0x%x, \"%s\", %v));\n",
				copyin.Addr, toCString(arg.Data, arg.Readable), len(arg.Data))
		}
	case prog.ExecArgCsum:
		switch arg.Kind {
		case prog.ExecArgCsumInet:
			*csumSeq++
			ctx.generateCsumInet(w, copyin.Addr, arg, *csumSeq)
		default:
			panic(fmt.Sprintf("unknown csum kind %v", arg.Kind))
		}
	default:
		panic(fmt.Sprintf("bad argument type: %+v", arg))
	}
}

func (ctx *context) copyinVal(w *bytes.Buffer, addr, size uint64, val string, bf prog.BinaryFormat) {
	switch bf {
	case prog.FormatNative, prog.FormatBigEndian:
		fmt.Fprintf(w, "\tNONFAILING(*(uint%v*)0x%x = %v);\n", size*8, addr, val)
	case prog.FormatStrDec:
		if size != 20 {
			panic("bad strdec size")
		}
		fmt.Fprintf(w, "\tNONFAILING(sprintf((char*)0x%x, \"%%020llu\", (long long)%v));\n", addr, val)
	case prog.FormatStrHex:
		if size != 18 {
			panic("bad strdec size")
		}
		fmt.Fprintf(w, "\tNONFAILING(sprintf((char*)0x%x, \"0x%%016llx\", (long long)%v));\n", addr, val)
	case prog.FormatStrOct:
		if size != 23 {
			panic("bad strdec size")
		}
		fmt.Fprintf(w, "\tNONFAILING(sprintf((char*)0x%x, \"%%023llo\", (long long)%v));\n", addr, val)
	default:
		panic("unknown binary format")
	}
}

func (ctx *context) copyout(w *bytes.Buffer, call prog.ExecCall, resCopyout bool) {
	if ctx.sysTarget.OS == targets.Fuchsia {
		// On fuchsia we have real system calls that return ZX_OK on success,
		// and libc calls that are casted to function returning intptr_t,
		// as the result int -1 is returned as 0x00000000ffffffff rather than full -1.
		if strings.HasPrefix(call.Meta.CallName, "zx_") {
			fmt.Fprintf(w, "\tif (res == ZX_OK)")
		} else {
			fmt.Fprintf(w, "\tif ((int)res != -1)")
		}
	} else {
		fmt.Fprintf(w, "\tif (res != -1)")
	}
	copyoutMultiple := len(call.Copyout) > 1 || resCopyout && len(call.Copyout) > 0
	if copyoutMultiple {
		fmt.Fprintf(w, " {")
	}
	fmt.Fprintf(w, "\n")
	if resCopyout {
		fmt.Fprintf(w, "\t\tr[%v] = res;\n", call.Index)
	}
	for _, copyout := range call.Copyout {
		fmt.Fprintf(w, "\t\tNONFAILING(r[%v] = *(uint%v*)0x%x);\n",
			copyout.Index, copyout.Size*8, copyout.Addr)
	}
	if copyoutMultiple {
		fmt.Fprintf(w, "\t}\n")
	}
}

func (ctx *context) constArgToStr(arg prog.ExecArgConst, handleBigEndian, native bool) string {
	mask := (uint64(1) << (arg.Size * 8)) - 1
	v := arg.Value & mask
	val := fmt.Sprintf("%v", v)
	if v == ^uint64(0)&mask {
		val = "-1"
	} else if v >= 10 {
		val = fmt.Sprintf("0x%x", v)
	}
	if native && arg.Size == 8 {
		// syscall() is variadic, so constant arguments must be explicitly
		// promoted. Otherwise the compiler is free to leave garbage in the
		// upper 32 bits of the argument value. In practice this can happen
		// on amd64 with arguments that are passed on the stack, i.e.,
		// arguments beyond the first six. For example, on freebsd/amd64,
		// syscall(SYS_mmap, ..., 0) causes clang to emit a 32-bit store of
		// 0 to the stack, but the kernel expects a 64-bit value.
		//
		// syzkaller's argument type representations do not always match
		// the OS ABI. For instance, "flags" is always 64 bits wide on 64-bit
		// platforms, but is a 32-bit value ("unsigned int" or so) in many
		// cases. Thus, we assume here that passing a 64-bit argument where
		// a 32-bit argument is expected won't break anything. On amd64
		// this should be fine: arguments are passed in 64-bit registers or
		// at 64 bit-aligned addresses on the stack.
		if ctx.target.PtrSize == 4 {
			val += "ull"
		} else {
			val += "ul"
		}
	}
	if ctx.opts.Procs > 1 && arg.PidStride != 0 {
		val += fmt.Sprintf(" + procid*%v", arg.PidStride)
	}
	if handleBigEndian && arg.Format == prog.FormatBigEndian {
		val = fmt.Sprintf("htobe%v(%v)", arg.Size*8, val)
	}
	return val
}

func (ctx *context) resultArgToStr(arg prog.ExecArgResult) string {
	res := fmt.Sprintf("r[%v]", arg.Index)
	if arg.DivOp != 0 {
		res = fmt.Sprintf("%v/%v", res, arg.DivOp)
	}
	if arg.AddOp != 0 {
		res = fmt.Sprintf("%v+%v", res, arg.AddOp)
	}
	if arg.Format == prog.FormatBigEndian {
		res = fmt.Sprintf("htobe%v(%v)", arg.Size*8, res)
	}
	return res
}

func (ctx *context) postProcess(result []byte) []byte {
	// Remove NONFAILING, debug, fail, etc calls.
	if !ctx.opts.HandleSegv {
		result = regexp.MustCompile(`\t*NONFAILING\((.*)\);\n`).ReplaceAll(result, []byte("$1;\n"))
	}
	result = bytes.Replace(result, []byte("NORETURN"), nil, -1)
	result = bytes.Replace(result, []byte("doexit("), []byte("exit("), -1)
	// TODO: Figure out what would be the right replacement for doexit_thread().
	result = bytes.Replace(result, []byte("doexit_thread("), []byte("exit("), -1)
	result = regexp.MustCompile(`PRINTF\(.*?\)`).ReplaceAll(result, nil)
	result = regexp.MustCompile(`\t*debug\((.*\n)*?.*\);\n`).ReplaceAll(result, nil)
	result = regexp.MustCompile(`\t*debug_dump_data\((.*\n)*?.*\);\n`).ReplaceAll(result, nil)
	result = regexp.MustCompile(`\t*exitf\((.*\n)*?.*\);\n`).ReplaceAll(result, []byte("\texit(1);\n"))
	result = regexp.MustCompile(`\t*fail(msg)?\((.*\n)*?.*\);\n`).ReplaceAll(result, []byte("\texit(1);\n"))

	result = ctx.hoistIncludes(result)
	result = ctx.removeEmptyLines(result)
	return result
}

// hoistIncludes moves all includes to the top, removes dups and sorts.
func (ctx *context) hoistIncludes(result []byte) []byte {
	includesStart := bytes.Index(result, []byte("#include"))
	if includesStart == -1 {
		return result
	}
	includes := make(map[string]bool)
	includeRe := regexp.MustCompile("#include <.*>\n")
	for _, match := range includeRe.FindAll(result, -1) {
		includes[string(match)] = true
	}
	result = includeRe.ReplaceAll(result, nil)
	// Certain linux and bsd headers are broken and go to the bottom.
	var sorted, sortedBottom, sortedTop []string
	for include := range includes {
		if strings.Contains(include, "<linux/") {
			sortedBottom = append(sortedBottom, include)
		} else if strings.Contains(include, "<netinet/if_ether.h>") {
			sortedBottom = append(sortedBottom, include)
		} else if ctx.target.OS == targets.FreeBSD && strings.Contains(include, "<sys/types.h>") {
			sortedTop = append(sortedTop, include)
		} else {
			sorted = append(sorted, include)
		}
	}
	sort.Strings(sortedTop)
	sort.Strings(sorted)
	sort.Strings(sortedBottom)
	newResult := append([]byte{}, result[:includesStart]...)
	newResult = append(newResult, strings.Join(sortedTop, "")...)
	newResult = append(newResult, '\n')
	newResult = append(newResult, strings.Join(sorted, "")...)
	newResult = append(newResult, '\n')
	newResult = append(newResult, strings.Join(sortedBottom, "")...)
	newResult = append(newResult, result[includesStart:]...)
	return newResult
}

// removeEmptyLines removes duplicate new lines.
func (ctx *context) removeEmptyLines(result []byte) []byte {
	for {
		newResult := bytes.Replace(result, []byte{'\n', '\n', '\n'}, []byte{'\n', '\n'}, -1)
		newResult = bytes.Replace(newResult, []byte{'\n', '\n', '\t'}, []byte{'\n', '\t'}, -1)
		newResult = bytes.Replace(newResult, []byte{'\n', '\n', ' '}, []byte{'\n', ' '}, -1)
		if len(newResult) == len(result) {
			return result
		}
		result = newResult
	}
}

func toCString(data []byte, readable bool) []byte {
	if len(data) == 0 {
		panic("empty data arg")
	}
	buf := new(bytes.Buffer)
	prog.EncodeData(buf, data, readable)
	return buf.Bytes()
}
