// Copyright 2024 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package vminfo

import (
	"bytes"
	"encoding/gob"
	"fmt"
	"slices"
	"strings"
	"syscall"

	"github.com/google/syzkaller/pkg/hash"
	"github.com/google/syzkaller/pkg/host"
	"github.com/google/syzkaller/pkg/ipc"
	"github.com/google/syzkaller/pkg/mgrconfig"
	"github.com/google/syzkaller/pkg/rpctype"
	"github.com/google/syzkaller/prog"
	"github.com/google/syzkaller/sys/targets"
)

// checkContext arranges checking of presence/support of all target syscalls.
// The actual checking is done by OS-specific impl.syscallCheck,
// while checkContext invokes that function for each syscall in a special manner
// and provides primitives for reading target VM files, checking if a file can be opened,
// executing test programs on the target VM, etc.
//
// To make use of this type simpler, we collect all test programs that need
// to be executed on the target into a batch, send them to the target VM once,
// then get results and finish the check. This means that impl.syscallCheck
// cannot e.g. issue one test program, look at results, and then issue another one.
// This is achieved by starting each impl.syscallCheck in a separate goroutine
// and then waiting when it will call ctx.execRaw to submit syscalls that
// need to be executed on the target. Once all impl.syscallCheck submit
// their test syscalls, we know that we collected all of them.
// impl.syscallCheck may also decide to read a file on the target VM instead
// of executing a test program, this also counts as submitting an empty test program.
// This means that impl.syscallCheck cannot execute a test program after reading a file,
// but can do these things in opposite order (since all files are known ahead of time).
// These rules are bit brittle, but all of the checkers are unit-tested
// and misuse (trying to execute 2 programs, etc) will either crash or hang in tests.
// Theoretically we can execute more than 1 program per checker, but it will
// require some special arrangements, e.g. see handling of PseudoSyscallDeps.
//
// The external interface of this type contains only 2 methods:
// startCheck - starts impl.syscallCheck goroutines and collects all test programs in progs,
// finishCheck - accepts results of program execution, unblocks impl.syscallCheck goroutines,
//
//	waits and returns results of checking.
type checkContext struct {
	impl    checker
	cfg     *mgrconfig.Config
	target  *prog.Target
	sandbox ipc.EnvFlags
	// Checkers use requests channel to submit their test programs,
	// main goroutine will wait for exactly pendingRequests message on this channel
	// (similar to sync.WaitGroup, pendingRequests is incremented before starting
	// a goroutine that will send on requests).
	requests        chan []*rpctype.ExecutionRequest
	pendingRequests int
	// Ready channel is closed after we've recevied results of execution of test
	// programs and file contents. After this results maps and fs are populated.
	ready   chan bool
	results map[int64]*ipc.ProgInfo
	fs      filesystem
	// Once checking of a syscall is finished, the result is sent to syscalls.
	// The main goroutine will wait for exactly pendingSyscalls messages.
	syscalls        chan syscallResult
	pendingSyscalls int
}

type syscallResult struct {
	call   *prog.Syscall
	reason string
}

func newCheckContext(cfg *mgrconfig.Config, impl checker) *checkContext {
	sandbox, err := ipc.SandboxToFlags(cfg.Sandbox)
	if err != nil {
		panic(fmt.Sprintf("failed to parse sandbox: %v", err))
	}
	return &checkContext{
		impl:     impl,
		cfg:      cfg,
		target:   cfg.Target,
		sandbox:  sandbox,
		requests: make(chan []*rpctype.ExecutionRequest),
		results:  make(map[int64]*ipc.ProgInfo),
		syscalls: make(chan syscallResult),
		ready:    make(chan bool),
	}
}

func (ctx *checkContext) startCheck() []rpctype.ExecutionRequest {
	for _, id := range ctx.cfg.Syscalls {
		call := ctx.target.Syscalls[id]
		if call.Attrs.Disabled {
			continue
		}
		ctx.pendingSyscalls++
		syscallCheck := ctx.impl.syscallCheck
		if strings.HasPrefix(call.CallName, "syz_ext_") {
			// Non-mainline pseudo-syscalls in executor/common_ext.h can't have
			// the checking function and are assumed to be unconditionally supported.
			syscallCheck = alwaysSupported
		}
		// HostFuzzer targets can't run Go binaries on the targets,
		// so we actually run on the host on another OS. The same for targets.TestOS OS.
		if ctx.cfg.SysTarget.HostFuzzer || ctx.target.OS == targets.TestOS {
			syscallCheck = alwaysSupported
		}

		var depsReason chan string
		deps := ctx.cfg.SysTarget.PseudoSyscallDeps[call.CallName]
		if len(deps) != 0 {
			ctx.pendingRequests++
			depsReason = make(chan string, 1)
			go func() {
				depsReason <- ctx.supportedSyscalls(deps)
			}()
		}
		ctx.pendingRequests++
		go func() {
			reason := syscallCheck(ctx, call)
			ctx.waitForResults()
			if reason == "" && depsReason != nil {
				reason = <-depsReason
			}
			ctx.syscalls <- syscallResult{call, reason}
		}()
	}
	var progs []rpctype.ExecutionRequest
	dedup := make(map[hash.Sig]int64)
	for i := 0; i < ctx.pendingRequests; i++ {
		for _, req := range <-ctx.requests {
			sig := hashReq(req)
			req.ID = dedup[sig]
			if req.ID != 0 {
				continue
			}
			req.ID = int64(len(dedup) + 1)
			dedup[sig] = req.ID
			progs = append(progs, *req)
		}
	}
	ctx.requests = nil
	return progs
}

func (ctx *checkContext) finishCheck(fileInfos []host.FileInfo, progs []rpctype.ExecutionResult) (
	map[*prog.Syscall]bool, map[*prog.Syscall]string, error) {
	ctx.fs = createVirtualFilesystem(fileInfos)
	for i := range progs {
		res := &progs[i]
		ctx.results[res.ID] = &res.Info
	}
	close(ctx.ready)
	enabled := make(map[*prog.Syscall]bool)
	disabled := make(map[*prog.Syscall]string)
	for i := 0; i < ctx.pendingSyscalls; i++ {
		res := <-ctx.syscalls
		if res.reason == "" {
			enabled[res.call] = true
		} else {
			disabled[res.call] = res.reason
		}
	}
	return enabled, disabled, nil
}

func (ctx *checkContext) rootCanOpen(file string) string {
	return ctx.canOpenImpl(file, nil, true)
}

func (ctx *checkContext) canOpen(file string) string {
	return ctx.canOpenImpl(file, nil, false)
}

func (ctx *checkContext) canWrite(file string) string {
	return ctx.canOpenImpl(file, []uint64{ctx.val("O_WRONLY")}, false)
}

func (ctx *checkContext) canOpenImpl(file string, modes []uint64, root bool) string {
	if len(modes) == 0 {
		modes = ctx.allOpenModes()
	}
	var calls []string
	for _, mode := range modes {
		call := fmt.Sprintf("openat(0x%x, &AUTO='%s', 0x%x, 0x0)", ctx.val("AT_FDCWD"), file, mode)
		calls = append(calls, call)
	}
	info := ctx.execRaw(calls, prog.StrictUnsafe, root)
	for _, call := range info.Calls {
		if call.Errno == 0 {
			return ""
		}
	}
	who := ""
	if root {
		who = "root "
	}
	return fmt.Sprintf("%vfailed to open %s: %v", who, file, syscall.Errno(info.Calls[0].Errno))
}

func (ctx *checkContext) supportedSyscalls(names []string) string {
	var calls []string
	for _, name := range names {
		if strings.HasPrefix(name, "syz_") {
			panic("generic syscall check used for pseudo-syscall: " + name)
		}
		calls = append(calls, name+"()")
	}
	info := ctx.execRaw(calls, prog.NonStrictUnsafe, false)
	for i, res := range info.Calls {
		if res.Errno == int(syscall.ENOSYS) {
			return fmt.Sprintf("syscall %v is not present", names[i])
		}
	}
	return ""
}

func (ctx *checkContext) allOpenModes() []uint64 {
	// Various open modes we need to try if we don't have a concrete mode.
	// Some files can be opened only for reading, some only for writing,
	// and some only in non-blocking mode.
	// Note: some of these consts are different for different arches.
	return []uint64{ctx.val("O_RDONLY"), ctx.val("O_WRONLY"), ctx.val("O_RDWR"),
		ctx.val("O_RDONLY") | ctx.val("O_NONBLOCK")}
}

func (ctx *checkContext) callSucceeds(call string) string {
	return ctx.anyCallSucceeds([]string{call}, call+" failed")
}

func (ctx *checkContext) execCall(call string) syscall.Errno {
	info := ctx.execRaw([]string{call}, prog.StrictUnsafe, false)
	return syscall.Errno(info.Calls[0].Errno)
}

func (ctx *checkContext) anyCallSucceeds(calls []string, msg string) string {
	info := ctx.execRaw(calls, prog.StrictUnsafe, false)
	for _, call := range info.Calls {
		if call.Errno == 0 {
			return ""
		}
	}
	return fmt.Sprintf("%s: %v", msg, syscall.Errno(info.Calls[0].Errno))
}

func (ctx *checkContext) onlySandboxNone() string {
	if ctx.sandbox != 0 {
		return "only supported under root with sandbox=none"
	}
	return ""
}

func (ctx *checkContext) onlySandboxNoneOrNamespace() string {
	if ctx.sandbox != 0 && ctx.sandbox != ipc.FlagSandboxNamespace {
		return "only supported under root with sandbox=none/namespace"
	}
	return ""
}

func (ctx *checkContext) val(name string) uint64 {
	val, ok := ctx.target.ConstMap[name]
	if !ok {
		panic(fmt.Sprintf("const %v is not present", name))
	}
	return val
}

func (ctx *checkContext) execRaw(calls []string, mode prog.DeserializeMode, root bool) *ipc.ProgInfo {
	if ctx.requests == nil {
		panic("only one test execution per checker is supported")
	}
	sandbox := ctx.sandbox
	if root {
		sandbox = 0
	}
	remain := calls
	var requests []*rpctype.ExecutionRequest
	for len(remain) != 0 {
		// Don't put too many syscalls into a single program,
		// it will have higher chances to time out.
		ncalls := min(len(remain), prog.MaxCalls/2)
		progStr := strings.Join(remain[:ncalls], "\n")
		remain = remain[ncalls:]
		p, err := ctx.target.Deserialize([]byte(progStr), mode)
		if err != nil {
			panic(fmt.Sprintf("failed to deserialize: %v\n%v", err, progStr))
		}
		data, err := p.SerializeForExec()
		if err != nil {
			panic(fmt.Sprintf("failed to serialize test program: %v\n%s", err, progStr))
		}
		requests = append(requests, &rpctype.ExecutionRequest{
			ProgData: slices.Clone(data), // clone to reduce memory usage
			ExecOpts: ipc.ExecOpts{
				EnvFlags:   sandbox,
				ExecFlags:  0,
				SandboxArg: ctx.cfg.SandboxArg,
			},
		})
	}
	ctx.requests <- requests
	<-ctx.ready
	info := &ipc.ProgInfo{}
	for _, req := range requests {
		res := ctx.results[req.ID]
		if res == nil {
			panic(fmt.Sprintf("no result for request %v", req.ID))
		}
		if len(res.Calls) == 0 {
			panic(fmt.Sprintf("result for request %v has no calls", req.ID))
		}
		info.Calls = append(info.Calls, res.Calls...)
	}
	if len(info.Calls) != len(calls) {
		panic(fmt.Sprintf("got only %v results for program %v with %v calls:\n%s",
			len(info.Calls), requests[0].ID, len(calls), strings.Join(calls, "\n")))
	}
	return info
}

func (ctx *checkContext) readFile(name string) ([]byte, error) {
	ctx.waitForResults()
	return ctx.fs.ReadFile(name)
}

func (ctx *checkContext) waitForResults() {
	// If syscallCheck has already executed a program, then it's also waited for ctx.ready.
	// If it hasn't, then we need to unblock the loop in startCheck by sending a nil request.
	if ctx.requests == nil {
		return
	}
	ctx.requests <- nil
	<-ctx.ready
	if ctx.fs == nil {
		panic("filesystem should be initialized by now")
	}
}

func hashReq(req *rpctype.ExecutionRequest) hash.Sig {
	buf := new(bytes.Buffer)
	if err := gob.NewEncoder(buf).Encode(req.ExecOpts); err != nil {
		panic(err)
	}
	return hash.Hash(req.ProgData, buf.Bytes())
}

func alwaysSupported(ctx *checkContext, call *prog.Syscall) string {
	return ""
}

func extractStringConst(typ prog.Type) (string, bool) {
	ptr, ok := typ.(*prog.PtrType)
	if !ok {
		panic("first open arg is not a pointer to string const")
	}
	str, ok := ptr.Elem.(*prog.BufferType)
	if !ok || str.Kind != prog.BufferString || len(str.Values) == 0 {
		return "", false
	}
	v := str.Values[0]
	for v != "" && v[len(v)-1] == 0 {
		v = v[:len(v)-1] // string terminating \x00
	}
	return v, true
}
