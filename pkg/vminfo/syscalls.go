// Copyright 2024 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package vminfo

import (
	"context"
	"fmt"
	"strings"
	"syscall"

	"github.com/google/syzkaller/pkg/flatrpc"
	"github.com/google/syzkaller/pkg/fuzzer/queue"
	"github.com/google/syzkaller/pkg/ipc"
	"github.com/google/syzkaller/pkg/mgrconfig"
	"github.com/google/syzkaller/prog"
	"github.com/google/syzkaller/sys/targets"
)

// checkContext arranges checking of presence/support of all target syscalls.
// The actual checking is done by OS-specific impl.syscallCheck,
// while checkContext invokes that function for each syscall in a special manner
// and provides primitives for reading target VM files, checking if a file can be opened,
// executing test programs on the target VM, etc.
//
// The external interface of this type contains only 2 methods:
// startCheck - starts impl.syscallCheck goroutines and collects all test programs in progs,
// finishCheck - accepts results of program execution, unblocks impl.syscallCheck goroutines,
//
//	waits and returns results of checking.
type checkContext struct {
	ctx      context.Context
	impl     checker
	cfg      *mgrconfig.Config
	target   *prog.Target
	sandbox  ipc.EnvFlags
	executor queue.Executor
	fs       filesystem
	// Once checking of a syscall is finished, the result is sent to syscalls.
	// The main goroutine will wait for exactly pendingSyscalls messages.
	syscalls        chan syscallResult
	pendingSyscalls int
	features        chan featureResult
}

type syscallResult struct {
	call   *prog.Syscall
	reason string
}

func newCheckContext(ctx context.Context, cfg *mgrconfig.Config, impl checker,
	executor queue.Executor) *checkContext {
	sandbox, err := ipc.SandboxToFlags(cfg.Sandbox)
	if err != nil {
		panic(fmt.Sprintf("failed to parse sandbox: %v", err))
	}
	return &checkContext{
		ctx:      ctx,
		impl:     impl,
		cfg:      cfg,
		target:   cfg.Target,
		sandbox:  sandbox,
		executor: executor,
		syscalls: make(chan syscallResult),
		features: make(chan featureResult, 100),
	}
}

func (ctx *checkContext) start(fileInfos []flatrpc.FileInfo) {
	ctx.fs = createVirtualFilesystem(fileInfos)
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
		go func() {
			var reason string
			deps := ctx.cfg.SysTarget.PseudoSyscallDeps[call.CallName]
			if len(deps) != 0 {
				reason = ctx.supportedSyscalls(deps)
			}
			// Only check the call if all its dependencies are satisfied.
			if reason == "" {
				reason = syscallCheck(ctx, call)
			}
			ctx.syscalls <- syscallResult{call, reason}
		}()
	}
	ctx.startFeaturesCheck()
}

func (ctx *checkContext) wait(featureInfos []flatrpc.FeatureInfo) (
	map[*prog.Syscall]bool, map[*prog.Syscall]string, Features, error) {
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
	features, err := ctx.finishFeatures(featureInfos)
	return enabled, disabled, features, err
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

func supportedOpenat(ctx *checkContext, call *prog.Syscall) string {
	fname, ok := extractStringConst(call.Args[1].Type)
	if !ok || fname[0] != '/' {
		return ""
	}
	modes := ctx.allOpenModes()
	// Attempt to extract flags from the syscall description.
	if mode, ok := call.Args[2].Type.(*prog.ConstType); ok {
		modes = []uint64{mode.Val}
	}
	var calls []string
	for _, mode := range modes {
		call := fmt.Sprintf("openat(0x%0x, &AUTO='%v', 0x%x, 0x0)", ctx.val("AT_FDCWD"), fname, mode)
		calls = append(calls, call)
	}
	return ctx.anyCallSucceeds(calls, fmt.Sprintf("failed to open %v", fname))
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
	sandbox := ctx.sandbox
	if root {
		sandbox = 0
	}
	info := &ipc.ProgInfo{}
	for remain := calls; len(remain) != 0; {
		// Don't put too many syscalls into a single program,
		// it will have higher chances to time out.
		ncalls := min(len(remain), prog.MaxCalls/2)
		progStr := strings.Join(remain[:ncalls], "\n")
		remain = remain[ncalls:]
		p, err := ctx.target.Deserialize([]byte(progStr), mode)
		if err != nil {
			panic(fmt.Sprintf("failed to deserialize: %v\n%v", err, progStr))
		}
		req := &queue.Request{
			Prog: p,
			ExecOpts: ipc.ExecOpts{
				EnvFlags:   sandbox,
				ExecFlags:  0,
				SandboxArg: ctx.cfg.SandboxArg,
			},
			Important: true,
		}
		ctx.executor.Submit(req)
		res := req.Wait(ctx.ctx)
		if res.Status == queue.Success {
			info.Calls = append(info.Calls, res.Info.Calls...)
		} else if res.Status == queue.Crashed {
			// Pretend these calls were not executed.
			info.Calls = append(info.Calls, ipc.EmptyProgInfo(ncalls).Calls...)
		} else {
			// The program must have been either executed or not due to a crash.
			panic(fmt.Sprintf("got unexpected execution status (%d) for the prog %s",
				res.Status, progStr))
		}
	}
	if len(info.Calls) != len(calls) {
		panic(fmt.Sprintf("got %v != %v results for program:\n%s",
			len(info.Calls), len(calls), strings.Join(calls, "\n")))
	}
	return info
}

func (ctx *checkContext) readFile(name string) ([]byte, error) {
	return ctx.fs.ReadFile(name)
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
