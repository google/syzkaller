// Copyright 2018 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

// Package runtest is a driver for end-to-end testing of syzkaller programs.
// It tests program execution via both executor and csource,
// with different sandboxes and execution modes (threaded, repeated, etc).
// It can run test OS programs locally via run_test.go
// and all other real OS programs via tools/syz-runtest
// which uses manager config to wind up VMs.
// Test programs are located in sys/*/test/* files.
package runtest

import (
	"bufio"
	"bytes"
	"context"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"sort"
	"strconv"
	"strings"

	"github.com/google/syzkaller/pkg/csource"
	"github.com/google/syzkaller/pkg/flatrpc"
	"github.com/google/syzkaller/pkg/fuzzer/queue"
	"github.com/google/syzkaller/pkg/ipc"
	"github.com/google/syzkaller/prog"
	"github.com/google/syzkaller/sys/targets"
)

type runRequest struct {
	*queue.Request

	err      error
	finished chan struct{}
	result   *queue.Result
	results  *ipc.ProgInfo // the expected results

	name   string
	broken string
	skip   string
}

type Context struct {
	Dir          string
	Target       *prog.Target
	Features     flatrpc.Feature
	EnabledCalls map[string]map[*prog.Syscall]bool
	LogFunc      func(text string)
	Retries      int // max number of test retries to deal with flaky tests
	Verbose      bool
	Debug        bool
	Tests        string // prefix to match test file names

	executor queue.PlainQueue
}

func (ctx *Context) log(msg string, args ...interface{}) {
	ctx.LogFunc(fmt.Sprintf(msg, args...))
}

func (ctx *Context) Run() error {
	if ctx.Retries%2 == 0 {
		ctx.Retries++
	}
	progs := make(chan *runRequest, 1000)
	errc := make(chan error, 1)
	go func() {
		defer close(progs)
		errc <- ctx.generatePrograms(progs)
	}()
	var requests []*runRequest
	for req := range progs {
		req := req
		requests = append(requests, req)
		if req.broken != "" || req.skip != "" {
			continue
		}
		req.finished = make(chan struct{})
		go func() {
			// The tests depend on timings and may be flaky, esp on overloaded/slow machines.
			// We don't want to fix this by significantly bumping all timeouts,
			// because if a program fails all the time with the default timeouts,
			// it will also fail during fuzzing. And we want to ensure that it's not the case.
			// So what we want is to tolerate episodic failures with the default timeouts.
			// To achieve this we run each test several times and ensure that it passes
			// in 50+% of cases (i.e. 1/1, 2/3, 3/5, 4/7, etc).
			// In the best case this allows to get off with just 1 test run.
			var resultErr error
			for try, failed := 0, 0; try < ctx.Retries; try++ {
				ctx.executor.Submit(req.Request)
				req.result = req.Request.Wait(context.Background())
				if req.result.Err != nil {
					resultErr = req.result.Err
					break
				}
				err := checkResult(req)
				if err != nil {
					failed++
					resultErr = err
				}
				if ok := try + 1 - failed; ok > failed {
					resultErr = nil
					break
				}
			}
			req.err = resultErr
			close(req.finished)
		}()
	}
	var ok, fail, broken, skip int
	for _, req := range requests {
		result := ""
		verbose := false
		if req.broken != "" {
			broken++
			result = fmt.Sprintf("BROKEN (%v)", req.broken)
			verbose = true
		} else if req.skip != "" {
			skip++
			result = fmt.Sprintf("SKIP (%v)", req.skip)
			verbose = true
		} else {
			<-req.finished
			if req.err != nil {
				fail++
				result = fmt.Sprintf("FAIL: %v",
					strings.Replace(req.err.Error(), "\n", "\n\t", -1))
				res := req.result
				if len(res.Output) != 0 {
					result += fmt.Sprintf("\n\t%s",
						strings.Replace(string(res.Output), "\n", "\n\t", -1))
				}
			} else {
				ok++
				result = "OK"
			}
		}
		if !verbose || ctx.Verbose {
			ctx.log("%-38v: %v", req.name, result)
		}
		if req.Request != nil && req.Request.BinaryFile != "" {
			os.Remove(req.BinaryFile)
		}
	}
	if err := <-errc; err != nil {
		return err
	}
	ctx.log("ok: %v, broken: %v, skip: %v, fail: %v", ok, broken, skip, fail)
	if fail != 0 {
		return fmt.Errorf("tests failed")
	}
	return nil
}

func (ctx *Context) Next() *queue.Request {
	return ctx.executor.Next()
}

func (ctx *Context) generatePrograms(progs chan *runRequest) error {
	cover := []bool{false}
	if ctx.Features&flatrpc.FeatureCoverage != 0 {
		cover = append(cover, true)
	}
	var sandboxes []string
	for sandbox := range ctx.EnabledCalls {
		sandboxes = append(sandboxes, sandbox)
	}
	sort.Strings(sandboxes)
	files, err := progFileList(ctx.Dir, ctx.Tests)
	if err != nil {
		return err
	}
	for _, file := range files {
		if err := ctx.generateFile(progs, sandboxes, cover, file); err != nil {
			return err
		}
	}
	return nil
}

func progFileList(dir, filter string) ([]string, error) {
	files, err := os.ReadDir(dir)
	if err != nil {
		return nil, fmt.Errorf("failed to read %v: %w", dir, err)
	}
	var res []string
	for _, file := range files {
		if strings.HasSuffix(file.Name(), "~") ||
			strings.HasSuffix(file.Name(), ".swp") ||
			!strings.HasPrefix(file.Name(), filter) {
			continue
		}
		res = append(res, file.Name())
	}
	return res, nil
}

func (ctx *Context) generateFile(progs chan *runRequest, sandboxes []string, cover []bool, filename string) error {
	p, requires, results, err := parseProg(ctx.Target, ctx.Dir, filename)
	if err != nil {
		return err
	}
	if p == nil {
		return nil
	}
	sysTarget := targets.Get(ctx.Target.OS, ctx.Target.Arch)
nextSandbox:
	for _, sandbox := range sandboxes {
		name := fmt.Sprintf("%v %v", filename, sandbox)
		for _, call := range p.Calls {
			if !ctx.EnabledCalls[sandbox][call.Meta] {
				progs <- &runRequest{
					name: name,
					skip: fmt.Sprintf("unsupported call %v", call.Meta.Name),
				}
				continue nextSandbox
			}
		}
		properties := map[string]bool{
			"manual":             ctx.Tests != "", // "manual" tests run only if selected by the filter explicitly.
			"sandbox=" + sandbox: true,
			"littleendian":       ctx.Target.LittleEndian,
		}
		for _, threaded := range []bool{false, true} {
			name := name
			if threaded {
				name += "/thr"
			}
			properties["threaded"] = threaded
			for _, times := range []int{1, 3} {
				properties["repeat"] = times > 1
				properties["norepeat"] = times <= 1
				if times > 1 {
					name += "/repeat"
				}
				for _, cov := range cover {
					if sandbox == "" {
						break // executor does not support empty sandbox
					}
					name := name
					if cov {
						name += "/cover"
					}
					properties["cover"] = cov
					properties["C"] = false
					properties["executor"] = true
					req, err := ctx.createSyzTest(p, sandbox, threaded, cov, times)
					if err != nil {
						return err
					}
					ctx.produceTest(progs, req, name, properties, requires, results)
				}
				if sysTarget.HostFuzzer {
					// For HostFuzzer mode, we need to cross-compile
					// and copy the binary to the target system.
					continue
				}
				name := name
				properties["C"] = true
				properties["executor"] = false
				name += " C"
				if !sysTarget.ExecutorUsesForkServer && times > 1 {
					// Non-fork loop implementation does not support repetition.
					progs <- &runRequest{
						name:   name,
						broken: "non-forking loop",
					}
					continue
				}
				req, err := ctx.createCTest(p, sandbox, threaded, times)
				if err != nil {
					return err
				}
				ctx.produceTest(progs, req, name, properties, requires, results)
			}
		}
	}
	return nil
}

func parseProg(target *prog.Target, dir, filename string) (*prog.Prog, map[string]bool, *ipc.ProgInfo, error) {
	data, err := os.ReadFile(filepath.Join(dir, filename))
	if err != nil {
		return nil, nil, nil, fmt.Errorf("failed to read %v: %w", filename, err)
	}
	requires := parseRequires(data)
	// Need to check arch requirement early as some programs
	// may fail to deserialize on some arches due to missing syscalls.
	if !checkArch(requires, target.Arch) {
		return nil, nil, nil, nil
	}
	p, err := target.Deserialize(data, prog.Strict)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("failed to deserialize %v: %w", filename, err)
	}
	errnos := map[string]int{
		"":           0,
		"EPERM":      1,
		"ENOENT":     2,
		"E2BIG":      7,
		"ENOEXEC":    8,
		"EBADF":      9,
		"ENOMEM":     12,
		"EACCES":     13,
		"EFAULT":     14,
		"EXDEV":      18,
		"EINVAL":     22,
		"ENOTTY":     25,
		"EOPNOTSUPP": 95,

		// Fuchsia specific errors.
		"ZX_ERR_NO_RESOURCES":   3,
		"ZX_ERR_INVALID_ARGS":   10,
		"ZX_ERR_BAD_HANDLE":     11,
		"ZX_ERR_BAD_STATE":      20,
		"ZX_ERR_TIMED_OUT":      21,
		"ZX_ERR_SHOULD_WAIT":    22,
		"ZX_ERR_PEER_CLOSED":    24,
		"ZX_ERR_ALREADY_EXISTS": 26,
		"ZX_ERR_ACCESS_DENIED":  30,
	}
	info := &ipc.ProgInfo{Calls: make([]ipc.CallInfo, len(p.Calls))}
	for i, call := range p.Calls {
		info.Calls[i].Flags |= ipc.CallExecuted | ipc.CallFinished
		switch call.Comment {
		case "blocked":
			info.Calls[i].Flags |= ipc.CallBlocked
		case "unfinished":
			info.Calls[i].Flags &^= ipc.CallFinished
		case "unexecuted":
			info.Calls[i].Flags &^= ipc.CallExecuted | ipc.CallFinished
		default:
			res, ok := errnos[call.Comment]
			if !ok {
				return nil, nil, nil, fmt.Errorf("%v: unknown call comment %q",
					filename, call.Comment)
			}
			info.Calls[i].Errno = res
		}
	}
	return p, requires, info, nil
}

func parseRequires(data []byte) map[string]bool {
	requires := make(map[string]bool)
	for s := bufio.NewScanner(bytes.NewReader(data)); s.Scan(); {
		const prefix = "# requires:"
		line := s.Text()
		if !strings.HasPrefix(line, prefix) {
			continue
		}
		for _, req := range strings.Fields(line[len(prefix):]) {
			positive := true
			if req[0] == '-' {
				positive = false
				req = req[1:]
			}
			requires[req] = positive
		}
	}
	return requires
}

func checkArch(requires map[string]bool, arch string) bool {
	for req, positive := range requires {
		const prefix = "arch="
		if strings.HasPrefix(req, prefix) &&
			arch != req[len(prefix):] == positive {
			return false
		}
	}
	return true
}

func (ctx *Context) produceTest(progs chan *runRequest, req *runRequest, name string,
	properties, requires map[string]bool, results *ipc.ProgInfo) {
	req.name = name
	req.results = results
	if !match(properties, requires) {
		req.skip = "excluded by constraints"
	}
	progs <- req
}

func match(props, requires map[string]bool) bool {
	for req, positive := range requires {
		if positive {
			if !props[req] {
				return false
			}
			continue
		}
		matched := true
		for _, req1 := range strings.Split(req, ",") {
			if !props[req1] {
				matched = false
			}
		}
		if matched {
			return false
		}
	}
	return true
}

func (ctx *Context) createSyzTest(p *prog.Prog, sandbox string, threaded, cov bool, times int) (*runRequest, error) {
	var opts ipc.ExecOpts
	sandboxFlags, err := ipc.SandboxToFlags(sandbox)
	if err != nil {
		return nil, err
	}
	opts.EnvFlags |= sandboxFlags
	if threaded {
		opts.ExecFlags |= ipc.FlagThreaded
	}
	if cov {
		opts.EnvFlags |= ipc.FlagSignal
		opts.ExecFlags |= ipc.FlagCollectSignal
		opts.ExecFlags |= ipc.FlagCollectCover
	}
	opts.EnvFlags |= ipc.FeaturesToFlags(ctx.Features, nil)
	if ctx.Debug {
		opts.EnvFlags |= ipc.FlagDebug
	}
	req := &runRequest{
		Request: &queue.Request{
			Prog:     p,
			ExecOpts: &opts,
			Repeat:   times,
		},
	}
	return req, nil
}

func (ctx *Context) createCTest(p *prog.Prog, sandbox string, threaded bool, times int) (*runRequest, error) {
	opts := csource.Options{
		Threaded:    threaded,
		Repeat:      times > 1,
		RepeatTimes: times,
		Procs:       1,
		Slowdown:    1,
		Sandbox:     sandbox,
		UseTmpDir:   true,
		HandleSegv:  true,
		Cgroups:     p.Target.OS == targets.Linux && sandbox != "",
		Trace:       true,
		Swap:        ctx.Features&flatrpc.FeatureSwap != 0,
	}
	if sandbox != "" {
		if ctx.Features&flatrpc.FeatureNetInjection != 0 {
			opts.NetInjection = true
		}
		if ctx.Features&flatrpc.FeatureNetDevices != 0 {
			opts.NetDevices = true
		}
		if ctx.Features&flatrpc.FeatureVhciInjection != 0 {
			opts.VhciInjection = true
		}
		if ctx.Features&flatrpc.FeatureWifiEmulation != 0 {
			opts.Wifi = true
		}
		if ctx.Features&flatrpc.FeatureLRWPANEmulation != 0 {
			opts.IEEE802154 = true
		}
	}
	src, err := csource.Write(p, opts)
	if err != nil {
		return nil, fmt.Errorf("failed to create C source: %w", err)
	}
	bin, err := csource.Build(p.Target, src)
	if err != nil {
		return nil, fmt.Errorf("failed to build C program: %w", err)
	}
	var ipcFlags ipc.ExecFlags
	if threaded {
		ipcFlags |= ipc.FlagThreaded
	}
	req := &runRequest{
		Request: &queue.Request{
			Prog:       p,
			BinaryFile: bin,
			ExecOpts: &ipc.ExecOpts{
				ExecFlags: ipcFlags,
			},
			Repeat: times,
		},
	}
	return req, nil
}

func checkResult(req *runRequest) error {
	if req.result.Status != queue.Success {
		return fmt.Errorf("non-successful result status (%v)", req.result.Status)
	}
	var infos []ipc.ProgInfo
	isC := req.BinaryFile != ""
	if isC {
		var err error
		if infos, err = parseBinOutput(req); err != nil {
			return err
		}
	} else {
		raw := req.result.Info
		for len(raw.Calls) != 0 {
			ncalls := min(len(raw.Calls), len(req.Prog.Calls))
			infos = append(infos, ipc.ProgInfo{
				Extra: raw.Extra,
				Calls: raw.Calls[:ncalls],
			})
			raw.Calls = raw.Calls[ncalls:]
		}
	}
	if req.Repeat != len(infos) {
		return fmt.Errorf("should repeat %v times, but repeated %v, prog calls %v, info calls %v\n%s",
			req.Repeat, len(infos), req.Prog.Calls, len(req.result.Info.Calls), req.result.Output)
	}
	calls := make(map[string]bool)
	for run, info := range infos {
		for call := range info.Calls {
			if err := checkCallResult(req, isC, run, call, info, calls); err != nil {
				return err
			}
		}
	}
	return nil
}

func checkCallResult(req *runRequest, isC bool, run, call int, info ipc.ProgInfo, calls map[string]bool) error {
	inf := info.Calls[call]
	want := req.results.Calls[call]
	for flag, what := range map[ipc.CallFlags]string{
		ipc.CallExecuted: "executed",
		ipc.CallBlocked:  "blocked",
		ipc.CallFinished: "finished",
	} {
		if flag != ipc.CallFinished {
			if isC {
				// C code does not detect blocked/non-finished calls.
				continue
			}
			if req.ExecOpts.ExecFlags&ipc.FlagThreaded == 0 {
				// In non-threaded mode blocked syscalls will block main thread
				// and we won't detect blocked/unfinished syscalls.
				continue
			}
		}
		if runtime.GOOS == targets.FreeBSD && flag == ipc.CallBlocked {
			// Blocking detection is flaky on freebsd.
			// TODO(dvyukov): try to increase the timeout in executor to make it non-flaky.
			continue
		}
		if (inf.Flags^want.Flags)&flag != 0 {
			not := " not"
			if inf.Flags&flag != 0 {
				not = ""
			}
			return fmt.Errorf("run %v: call %v is%v %v", run, call, not, what)
		}
	}
	if inf.Flags&ipc.CallFinished != 0 && inf.Errno != want.Errno {
		return fmt.Errorf("run %v: wrong call %v result %v, want %v",
			run, call, inf.Errno, want.Errno)
	}
	if isC || inf.Flags&ipc.CallExecuted == 0 {
		return nil
	}
	if req.ExecOpts.EnvFlags&ipc.FlagSignal != 0 {
		// Signal is always deduplicated, so we may not get any signal
		// on a second invocation of the same syscall.
		// For calls that are not meant to collect synchronous coverage we
		// allow the signal to be empty as long as the extra signal is not.
		callName := req.Prog.Calls[call].Meta.CallName
		if len(inf.Signal) < 2 && !calls[callName] && len(info.Extra.Signal) == 0 {
			return fmt.Errorf("run %v: call %v: no signal", run, call)
		}
		// syz_btf_id_by_name is a pseudo-syscall that might not provide
		// any coverage when invoked.
		if len(inf.Cover) == 0 && callName != "syz_btf_id_by_name" {
			return fmt.Errorf("run %v: call %v: no cover", run, call)
		}
		calls[callName] = true
	} else {
		if len(inf.Signal) != 0 {
			return fmt.Errorf("run %v: call %v: got %v unwanted signal", run, call, len(inf.Signal))
		}
	}
	return nil
}

func parseBinOutput(req *runRequest) ([]ipc.ProgInfo, error) {
	var infos []ipc.ProgInfo
	s := bufio.NewScanner(bytes.NewReader(req.result.Output))
	re := regexp.MustCompile("^### call=([0-9]+) errno=([0-9]+)$")
	for s.Scan() {
		if s.Text() == "### start" {
			infos = append(infos, ipc.ProgInfo{Calls: make([]ipc.CallInfo, len(req.Prog.Calls))})
		}
		match := re.FindSubmatch(s.Bytes())
		if match == nil {
			continue
		}
		if len(infos) == 0 {
			return nil, fmt.Errorf("call completed without start")
		}
		call, err := strconv.ParseUint(string(match[1]), 10, 64)
		if err != nil {
			return nil, fmt.Errorf("failed to parse call %q in %q",
				string(match[1]), s.Text())
		}
		errno, err := strconv.ParseUint(string(match[2]), 10, 32)
		if err != nil {
			return nil, fmt.Errorf("failed to parse errno %q in %q",
				string(match[2]), s.Text())
		}
		info := &infos[len(infos)-1]
		if call >= uint64(len(info.Calls)) {
			return nil, fmt.Errorf("bad call index %v", call)
		}
		if info.Calls[call].Flags != 0 {
			return nil, fmt.Errorf("double result for call %v", call)
		}
		info.Calls[call].Flags |= ipc.CallExecuted | ipc.CallFinished
		info.Calls[call].Errno = int(errno)
	}
	return infos, nil
}
