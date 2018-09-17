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
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/google/syzkaller/pkg/csource"
	"github.com/google/syzkaller/pkg/host"
	"github.com/google/syzkaller/pkg/ipc"
	"github.com/google/syzkaller/pkg/osutil"
	"github.com/google/syzkaller/prog"
	"github.com/google/syzkaller/sys/targets"
)

type RunRequest struct {
	Bin    string
	P      *prog.Prog
	Cfg    *ipc.Config
	Opts   *ipc.ExecOpts
	Repeat int

	Done   chan struct{}
	Output []byte
	Info   [][]ipc.CallInfo
	Err    error

	results []ipc.CallInfo
	name    string
	broken  string
	skip    string
}

type Context struct {
	Dir          string
	Target       *prog.Target
	Features     *host.Features
	EnabledCalls map[string]map[*prog.Syscall]bool
	Requests     chan *RunRequest
	LogFunc      func(text string)
}

func (ctx *Context) log(msg string, args ...interface{}) {
	ctx.LogFunc(fmt.Sprintf(msg, args...))
}

func (ctx *Context) Run() error {
	progs := make(chan *RunRequest, 1000+2*cap(ctx.Requests))
	errc := make(chan error, 1)
	go func() {
		defer close(progs)
		defer close(ctx.Requests)
		errc <- ctx.generatePrograms(progs)
	}()
	var ok, fail, broken, skip int
	for req := range progs {
		<-req.Done
		if req.Bin != "" {
			os.Remove(req.Bin)
		}
		result := ""
		if req.broken != "" {
			broken++
			result = fmt.Sprintf("BROKEN (%v)", req.broken)
		} else if req.skip != "" {
			skip++
			result = fmt.Sprintf("SKIP (%v)", req.skip)
		} else {
			if req.Err == nil {
				req.Err = checkResult(req)
			}
			if req.Err != nil {
				fail++
				result = fmt.Sprintf("FAIL: %v",
					strings.Replace(req.Err.Error(), "\n", "\n\t", -1))
				if len(req.Output) != 0 {
					result += fmt.Sprintf("\n\t%s",
						strings.Replace(string(req.Output), "\n", "\n\t", -1))
				}
			} else {
				ok++
				result = "OK"
			}
		}
		ctx.log("%-38v: %v", req.name, result)
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

func (ctx *Context) generatePrograms(progs chan *RunRequest) error {
	files, err := ioutil.ReadDir(ctx.Dir)
	if err != nil {
		return fmt.Errorf("failed to read %v: %v", ctx.Dir, err)
	}
	cover := []bool{false}
	if ctx.Features[host.FeatureCoverage].Enabled {
		cover = append(cover, true)
	}
	var sandboxes []string
	for sandbox := range ctx.EnabledCalls {
		sandboxes = append(sandboxes, sandbox)
	}
	sort.Strings(sandboxes)
	sysTarget := targets.Get(ctx.Target.OS, ctx.Target.Arch)
	closedDone := make(chan struct{})
	close(closedDone)
	for _, file := range files {
		if strings.HasSuffix(file.Name(), "~") {
			continue
		}
		p, requires, results, err := ctx.parseProg(file.Name())
		if err != nil {
			return err
		}
	nextSandbox:
		for _, sandbox := range sandboxes {
			name := fmt.Sprintf("%v %v", file.Name(), sandbox)
			for _, call := range p.Calls {
				if !ctx.EnabledCalls[sandbox][call.Meta] {
					progs <- &RunRequest{
						Done: closedDone,
						name: name,
						skip: fmt.Sprintf("unsupported call %v", call.Meta.Name),
					}
					continue nextSandbox
				}
			}
			properties := map[string]bool{
				"sandbox=" + sandbox: true,
			}
			for _, threaded := range []bool{false, true} {
				name := name
				if threaded {
					name += "/thr"
				}
				properties["threaded"] = threaded
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
					req, err := ctx.createSyzTest(p, sandbox, threaded, cov)
					if err != nil {
						return err
					}
					ctx.produceTest(progs, req, name, properties, requires, results)
				}
				for _, times := range []int{1, 3} {
					name := name
					properties["C"] = true
					properties["executor"] = false
					properties["repeat"] = times > 1
					properties["norepeat"] = times <= 1
					if times > 1 {
						name += "/repeat"
					}
					name += " C"
					if !sysTarget.ExecutorUsesForkServer && times > 1 {
						// Non-fork loop implementation does not support repetition.
						progs <- &RunRequest{
							Done:   closedDone,
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
	}
	return nil
}

func (ctx *Context) parseProg(filename string) (*prog.Prog, map[string]bool, []ipc.CallInfo, error) {
	data, err := ioutil.ReadFile(filepath.Join(ctx.Dir, filename))
	if err != nil {
		return nil, nil, nil, fmt.Errorf("failed to read %v: %v", filename, err)
	}
	p, err := ctx.Target.Deserialize(data)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("failed to deserialize %v: %v", filename, err)
	}
	requires := make(map[string]bool)
	for _, comment := range p.Comments {
		const prefix = "requires:"
		if !strings.HasPrefix(comment, prefix) {
			continue
		}
		for _, req := range strings.Fields(comment[len(prefix):]) {
			positive := true
			if req[0] == '-' {
				positive = false
				req = req[1:]
			}
			requires[req] = positive
		}
	}
	errnos := map[string]int{
		"":        0,
		"EPERM":   1,
		"ENOENT":  2,
		"ENOEXEC": 8,
		"EBADF":   9,
		"ENOMEM":  12,
		"EACCES":  13,
		"EINVAL":  22,
	}
	info := make([]ipc.CallInfo, len(p.Calls))
	for i, call := range p.Calls {
		info[i].Flags |= ipc.CallExecuted | ipc.CallFinished
		switch call.Comment {
		case "blocked":
			info[i].Flags |= ipc.CallBlocked
		case "unfinished":
			info[i].Flags &^= ipc.CallFinished
		default:
			res, ok := errnos[call.Comment]
			if !ok {
				return nil, nil, nil, fmt.Errorf("%v: unknown comment %q",
					filename, call.Comment)
			}
			info[i].Errno = res
		}
	}
	return p, requires, info, nil
}

func (ctx *Context) produceTest(progs chan *RunRequest, req *RunRequest, name string,
	properties, requires map[string]bool, results []ipc.CallInfo) {
	req.name = name
	req.results = results
	if match(properties, requires) {
		req.Done = make(chan struct{})
		ctx.Requests <- req
	} else {
		req.skip = "excluded by constraints"
		req.Done = make(chan struct{})
		close(req.Done)
	}
	progs <- req
}

func match(props map[string]bool, requires map[string]bool) bool {
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

func (ctx *Context) createSyzTest(p *prog.Prog, sandbox string, threaded, cov bool) (*RunRequest, error) {
	sysTarget := targets.Get(p.Target.OS, p.Target.Arch)
	cfg := new(ipc.Config)
	opts := new(ipc.ExecOpts)
	if sysTarget.ExecutorUsesShmem {
		cfg.Flags |= ipc.FlagUseShmem
	}
	if sysTarget.ExecutorUsesForkServer {
		cfg.Flags |= ipc.FlagUseForkServer
	}
	switch sandbox {
	case "namespace":
		cfg.Flags |= ipc.FlagSandboxNamespace
	case "setuid":
		cfg.Flags |= ipc.FlagSandboxSetuid
	case "android_untrusted_app":
		cfg.Flags |= ipc.FlagSandboxAndroidUntrustedApp
	}
	if threaded {
		opts.Flags |= ipc.FlagThreaded | ipc.FlagCollide
	}
	if cov {
		cfg.Flags |= ipc.FlagSignal
		opts.Flags |= ipc.FlagCollectCover
	}
	if ctx.Features[host.FeatureNetworkInjection].Enabled {
		cfg.Flags |= ipc.FlagEnableTun
	}
	if ctx.Features[host.FeatureNetworkDevices].Enabled {
		cfg.Flags |= ipc.FlagEnableNetDev
	}
	req := &RunRequest{
		P:      p,
		Cfg:    cfg,
		Opts:   opts,
		Repeat: 3,
	}
	return req, nil
}

func (ctx *Context) createCTest(p *prog.Prog, sandbox string, threaded bool, times int) (*RunRequest, error) {
	opts := csource.Options{
		Threaded:      threaded,
		Collide:       false,
		Repeat:        times > 1,
		RepeatTimes:   times,
		Procs:         1,
		Sandbox:       sandbox,
		UseTmpDir:     true,
		HandleSegv:    true,
		EnableCgroups: p.Target.OS == "linux" && sandbox != "",
		Trace:         true,
	}
	if sandbox != "" {
		if ctx.Features[host.FeatureNetworkInjection].Enabled {
			opts.EnableTun = true
		}
		if ctx.Features[host.FeatureNetworkDevices].Enabled {
			opts.EnableNetdev = true
		}
	}
	src, err := csource.Write(p, opts)
	if err != nil {
		return nil, fmt.Errorf("failed to create C source: %v", err)
	}
	bin, err := csource.Build(p.Target, src)
	if err != nil {
		return nil, fmt.Errorf("failed to build C program: %v", err)
	}
	req := &RunRequest{
		P:      p,
		Bin:    bin,
		Repeat: times,
	}
	return req, nil
}

func checkResult(req *RunRequest) error {
	isC := req.Bin != ""
	if isC {
		var err error
		if req.Info, err = parseBinOutput(req); err != nil {
			return err
		}
	}
	if req.Repeat != len(req.Info) {
		return fmt.Errorf("should repeat %v times, but repeated %v",
			req.Repeat, len(req.Info))
	}
	calls := make(map[string]bool)
	for run, info := range req.Info {
		for i, inf := range info {
			want := req.results[i]
			for flag, what := range map[ipc.CallFlags]string{
				ipc.CallExecuted: "executed",
				ipc.CallBlocked:  "blocked",
				ipc.CallFinished: "finished",
			} {
				if isC && flag == ipc.CallBlocked {
					// C code does not detect when a call was blocked.
					continue
				}
				if (inf.Flags^want.Flags)&flag != 0 {
					not := " not"
					if inf.Flags&flag != 0 {
						not = ""
					}
					return fmt.Errorf("run %v: call %v is%v %v", run, i, not, what)
				}
			}
			if inf.Flags&ipc.CallFinished != 0 && inf.Errno != want.Errno {
				return fmt.Errorf("run %v: wrong call %v result %v, want %v",
					run, i, inf.Errno, want.Errno)
			}
			if isC {
				continue
			}
			if req.Cfg.Flags&ipc.FlagSignal != 0 {
				// Signal is always deduplicated, so we may not get any signal
				// on a second invocation of the same syscall.
				callName := req.P.Calls[i].Meta.CallName
				if len(inf.Signal) < 2 && !calls[callName] {
					return fmt.Errorf("run %v: call %v: no signal", run, i)
				}
				if len(inf.Cover) == 0 {
					return fmt.Errorf("run %v: call %v: no cover", run, i)
				}
				calls[callName] = true
			} else {
				if len(inf.Signal) == 0 {
					return fmt.Errorf("run %v: call %v: no fallback signal", run, i)
				}
			}
		}
	}
	return nil
}

func parseBinOutput(req *RunRequest) ([][]ipc.CallInfo, error) {
	var infos [][]ipc.CallInfo
	s := bufio.NewScanner(bytes.NewReader(req.Output))
	re := regexp.MustCompile("^### call=([0-9]+) errno=([0-9]+)$")
	for s.Scan() {
		if s.Text() == "### start" {
			infos = append(infos, make([]ipc.CallInfo, len(req.P.Calls)))
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
		info := infos[len(infos)-1]
		if call >= uint64(len(info)) {
			return nil, fmt.Errorf("bad call index %v", call)
		}
		if info[call].Flags != 0 {
			return nil, fmt.Errorf("double result for call %v", call)
		}
		info[call].Flags |= ipc.CallExecuted | ipc.CallFinished
		info[call].Errno = int(errno)
	}
	for _, info := range infos {
		for i := range info {
			info[i].Flags |= ipc.CallExecuted
		}
	}
	return infos, nil
}

func RunTest(req *RunRequest, executor string) {
	if req.Bin != "" {
		tmpDir, err := ioutil.TempDir("", "syz-runtest")
		if err != nil {
			req.Err = fmt.Errorf("failed to create temp dir: %v", err)
			return
		}
		defer os.RemoveAll(tmpDir)
		req.Output, req.Err = osutil.RunCmd(20*time.Second, tmpDir, req.Bin)
		return
	}
	req.Cfg.Executor = executor
	env, err := ipc.MakeEnv(req.Cfg, 0)
	if err != nil {
		req.Err = fmt.Errorf("failed to create ipc env: %v", err)
		return
	}
	defer env.Close()
	for run := 0; run < req.Repeat; run++ {
		output, info, failed, hanged, err := env.Exec(req.Opts, req.P)
		req.Output = append(req.Output, output...)
		if err != nil {
			req.Err = fmt.Errorf("run %v: failed to run: %v", run, err)
			return
		}
		if failed {
			req.Err = fmt.Errorf("run %v: failed", run)
			return
		}
		if hanged {
			req.Err = fmt.Errorf("run %v: hanged", run)
			return
		}
		for i := range info {
			// Detach them because they point into the output shmem region.
			info[i].Signal = append([]uint32{}, info[i].Signal...)
			info[i].Cover = append([]uint32{}, info[i].Cover...)
		}
		req.Info = append(req.Info, info)
	}
}
