// Copyright 2015 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package ipc

import (
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"time"
	"unsafe"

	"github.com/google/syzkaller/pkg/cover"
	"github.com/google/syzkaller/pkg/csource"
	"github.com/google/syzkaller/pkg/flatrpc"
	"github.com/google/syzkaller/pkg/osutil"
	"github.com/google/syzkaller/pkg/signal"
	"github.com/google/syzkaller/prog"
	"github.com/google/syzkaller/sys/targets"
)

// Config is the configuration for Env.
type Config struct {
	// Path to executor binary.
	Executor string

	UseShmem      bool // use shared memory instead of pipes for communication
	UseForkServer bool // use extended protocol with handshake
	RateLimit     bool // rate limit start of new processes for host fuzzer mode

	Timeouts targets.Timeouts
}

type Env struct {
	in  []byte
	out []byte

	cmd       *command
	inFile    *os.File
	outFile   *os.File
	bin       []string
	linkedBin string
	pid       int
	config    *Config
}

const (
	outputSize = 16 << 20

	statusFail = 67

	// Comparison types masks taken from KCOV headers.
	compSizeMask  = 6
	compSize8     = 6
	compConstMask = 1

	extraReplyIndex = 0xffffffff // uint32(-1)
)

func SandboxToFlags(sandbox string) (flatrpc.ExecEnv, error) {
	switch sandbox {
	case "none":
		return 0, nil
	case "setuid":
		return flatrpc.ExecEnvSandboxSetuid, nil
	case "namespace":
		return flatrpc.ExecEnvSandboxNamespace, nil
	case "android":
		return flatrpc.ExecEnvSandboxAndroid, nil
	default:
		return 0, fmt.Errorf("sandbox must contain one of none/setuid/namespace/android")
	}
}

func FlagsToSandbox(flags flatrpc.ExecEnv) string {
	if flags&flatrpc.ExecEnvSandboxSetuid != 0 {
		return "setuid"
	} else if flags&flatrpc.ExecEnvSandboxNamespace != 0 {
		return "namespace"
	} else if flags&flatrpc.ExecEnvSandboxAndroid != 0 {
		return "android"
	}
	return "none"
}

func FeaturesToFlags(features flatrpc.Feature, manual csource.Features) flatrpc.ExecEnv {
	for feat := range flatrpc.EnumNamesFeature {
		opt := FlatRPCFeaturesToCSource[feat]
		if opt != "" && manual != nil && !manual[opt].Enabled {
			features &= ^feat
		}
	}
	var flags flatrpc.ExecEnv
	if manual == nil || manual["net_reset"].Enabled {
		flags |= flatrpc.ExecEnvEnableNetReset
	}
	if manual == nil || manual["cgroups"].Enabled {
		flags |= flatrpc.ExecEnvEnableCgroups
	}
	if manual == nil || manual["close_fds"].Enabled {
		flags |= flatrpc.ExecEnvEnableCloseFds
	}
	if features&flatrpc.FeatureExtraCoverage != 0 {
		flags |= flatrpc.ExecEnvExtraCover
	}
	if features&flatrpc.FeatureDelayKcovMmap != 0 {
		flags |= flatrpc.ExecEnvDelayKcovMmap
	}
	if features&flatrpc.FeatureNetInjection != 0 {
		flags |= flatrpc.ExecEnvEnableTun
	}
	if features&flatrpc.FeatureNetDevices != 0 {
		flags |= flatrpc.ExecEnvEnableNetDev
	}
	if features&flatrpc.FeatureDevlinkPCI != 0 {
		flags |= flatrpc.ExecEnvEnableDevlinkPCI
	}
	if features&flatrpc.FeatureNicVF != 0 {
		flags |= flatrpc.ExecEnvEnableNicVF
	}
	if features&flatrpc.FeatureVhciInjection != 0 {
		flags |= flatrpc.ExecEnvEnableVhciInjection
	}
	if features&flatrpc.FeatureWifiEmulation != 0 {
		flags |= flatrpc.ExecEnvEnableWifi
	}
	return flags
}

var FlatRPCFeaturesToCSource = map[flatrpc.Feature]string{
	flatrpc.FeatureNetInjection:    "tun",
	flatrpc.FeatureNetDevices:      "net_dev",
	flatrpc.FeatureDevlinkPCI:      "devlink_pci",
	flatrpc.FeatureNicVF:           "nic_vf",
	flatrpc.FeatureVhciInjection:   "vhci",
	flatrpc.FeatureWifiEmulation:   "wifi",
	flatrpc.FeatureUSBEmulation:    "usb",
	flatrpc.FeatureBinFmtMisc:      "binfmt_misc",
	flatrpc.FeatureLRWPANEmulation: "ieee802154",
	flatrpc.FeatureSwap:            "swap",
}

func MakeEnv(config *Config, pid int) (*Env, error) {
	if config.Timeouts.Slowdown == 0 || config.Timeouts.Scale == 0 ||
		config.Timeouts.Syscall == 0 || config.Timeouts.Program == 0 {
		return nil, fmt.Errorf("ipc.MakeEnv: uninitialized timeouts (%+v)", config.Timeouts)
	}
	var inf, outf *os.File
	var inmem, outmem []byte
	if config.UseShmem {
		var err error
		inf, inmem, err = osutil.CreateMemMappedFile(prog.ExecBufferSize)
		if err != nil {
			return nil, err
		}
		defer func() {
			if inf != nil {
				osutil.CloseMemMappedFile(inf, inmem)
			}
		}()
		outf, outmem, err = osutil.CreateMemMappedFile(outputSize)
		if err != nil {
			return nil, err
		}
		defer func() {
			if outf != nil {
				osutil.CloseMemMappedFile(outf, outmem)
			}
		}()
	} else {
		outmem = make([]byte, outputSize)
	}
	env := &Env{
		in:      inmem,
		out:     outmem,
		inFile:  inf,
		outFile: outf,
		bin:     append(strings.Split(config.Executor, " "), "exec"),
		pid:     pid,
		config:  config,
	}
	if len(env.bin) == 0 {
		return nil, fmt.Errorf("binary is empty string")
	}
	env.bin[0] = osutil.Abs(env.bin[0]) // we are going to chdir
	// Append pid to binary name.
	// E.g. if binary is 'syz-executor' and pid=15,
	// we create a link from 'syz-executor.15' to 'syz-executor' and use 'syz-executor.15' as binary.
	// This allows to easily identify program that lead to a crash in the log.
	// Log contains pid in "executing program 15" and crashes usually contain "Comm: syz-executor.15".
	// Note: pkg/report knowns about this and converts "syz-executor.15" back to "syz-executor".
	base := filepath.Base(env.bin[0])
	pidStr := fmt.Sprintf(".%v", pid)
	const maxLen = 16 // TASK_COMM_LEN is currently set to 16
	if len(base)+len(pidStr) >= maxLen {
		// Remove beginning of file name, in tests temp files have unique numbers at the end.
		base = base[len(base)+len(pidStr)-maxLen+1:]
	}
	binCopy := filepath.Join(filepath.Dir(env.bin[0]), base+pidStr)
	if err := os.Link(env.bin[0], binCopy); err == nil {
		env.bin[0] = binCopy
		env.linkedBin = binCopy
	}
	inf = nil
	outf = nil
	return env, nil
}

func (env *Env) Close() error {
	if env.cmd != nil {
		env.cmd.close()
	}
	if env.linkedBin != "" {
		os.Remove(env.linkedBin)
	}
	var err1, err2 error
	if env.inFile != nil {
		err1 = osutil.CloseMemMappedFile(env.inFile, env.in)
	}
	if env.outFile != nil {
		err2 = osutil.CloseMemMappedFile(env.outFile, env.out)
	}
	switch {
	case err1 != nil:
		return err1
	case err2 != nil:
		return err2
	default:
		return nil
	}
}

// Exec starts executor binary to execute program stored in progData in exec encoding
// and returns information about the execution:
// output: process output
// info: per-call info
// hanged: program hanged and was killed
// err0: failed to start the process or bug in executor itself.
func (env *Env) ExecProg(opts *flatrpc.ExecOpts, progData []byte) (
	output []byte, info *flatrpc.ProgInfo, hanged bool, err0 error) {
	ncalls, err := prog.ExecCallCount(progData)
	if err != nil {
		err0 = err
		return
	}
	// Copy-in serialized program.
	if env.config.UseShmem {
		copy(env.in, progData)
		progData = nil
	}
	// Zero out the first two words (ncmd and nsig), so that we don't have garbage there
	// if executor crashes before writing non-garbage there.
	for i := 0; i < 4; i++ {
		env.out[i] = 0
	}

	err0 = env.RestartIfNeeded(opts)
	if err0 != nil {
		return
	}

	start := osutil.MonotonicNano()
	output, hanged, err0 = env.cmd.exec(opts, progData)
	elapsed := osutil.MonotonicNano() - start
	if err0 != nil {
		env.cmd.close()
		env.cmd = nil
		return
	}

	info, err0 = env.parseOutput(opts, ncalls)
	if info != nil {
		info.Elapsed = uint64(elapsed)
		info.Freshness = env.cmd.freshness
	}
	env.cmd.freshness++
	if !env.config.UseForkServer {
		env.cmd.close()
		env.cmd = nil
	}
	return
}

func (env *Env) Exec(opts *flatrpc.ExecOpts, p *prog.Prog) (
	output []byte, info *flatrpc.ProgInfo, hanged bool, err0 error) {
	progData, err := p.SerializeForExec()
	if err != nil {
		err0 = err
		return
	}
	return env.ExecProg(opts, progData)
}

func (env *Env) ForceRestart() {
	if env.cmd != nil {
		env.cmd.close()
		env.cmd = nil
	}
}

// RestartIfNeeded brings up an executor process if it was stopped.
func (env *Env) RestartIfNeeded(opts *flatrpc.ExecOpts) error {
	if env.cmd != nil {
		if env.cmd.flags == opts.EnvFlags && env.cmd.sandboxArg == opts.SandboxArg {
			return nil
		}
		env.ForceRestart()
	}
	if env.config.RateLimit {
		rateLimiterOnce.Do(func() {
			rateLimiter = time.NewTicker(1 * time.Second).C
		})
		<-rateLimiter
	}
	var err error
	env.cmd, err = env.makeCommand(opts, "./")
	return err
}

var (
	rateLimiterOnce sync.Once
	rateLimiter     <-chan time.Time
)

func (env *Env) parseOutput(opts *flatrpc.ExecOpts, ncalls int) (*flatrpc.ProgInfo, error) {
	out := env.out
	ncmd, ok := readUint32(&out)
	if !ok {
		return nil, fmt.Errorf("failed to read number of calls")
	}
	info := flatrpc.EmptyProgInfo(ncalls)
	extraParts := make([]flatrpc.CallInfo, 0)
	for i := uint32(0); i < ncmd; i++ {
		if len(out) < int(unsafe.Sizeof(callReply{})) {
			return nil, fmt.Errorf("failed to read call %v reply", i)
		}
		reply := *(*callReply)(unsafe.Pointer(&out[0]))
		out = out[unsafe.Sizeof(callReply{}):]
		var inf *flatrpc.CallInfo
		if reply.magic != outMagic {
			return nil, fmt.Errorf("bad reply magic 0x%x", reply.magic)
		}
		if reply.index != extraReplyIndex {
			if int(reply.index) >= len(info.Calls) {
				return nil, fmt.Errorf("bad call %v index %v/%v", i, reply.index, len(info.Calls))
			}
			inf = info.Calls[reply.index]
			if inf.Flags != 0 || inf.Signal != nil {
				return nil, fmt.Errorf("duplicate reply for call %v/%v/%v", i, reply.index, reply.num)
			}
			inf.Error = int32(reply.errno)
			inf.Flags = flatrpc.CallFlag(reply.flags)
		} else {
			extraParts = append(extraParts, flatrpc.CallInfo{})
			inf = &extraParts[len(extraParts)-1]
		}
		if inf.Signal, ok = readUint64Array(&out, reply.signalSize); !ok {
			return nil, fmt.Errorf("call %v/%v/%v: signal overflow: %v/%v",
				i, reply.index, reply.num, reply.signalSize, len(out))
		}
		if inf.Cover, ok = readUint64Array(&out, reply.coverSize); !ok {
			return nil, fmt.Errorf("call %v/%v/%v: cover overflow: %v/%v",
				i, reply.index, reply.num, reply.coverSize, len(out))
		}
		comps, err := readComps(&out, reply.compsSize)
		if err != nil {
			return nil, err
		}
		inf.Comps = comps
	}
	if len(extraParts) == 0 {
		return info, nil
	}
	info.Extra = convertExtra(extraParts, opts.ExecFlags&flatrpc.ExecFlagDedupCover != 0)
	return info, nil
}

func convertExtra(extraParts []flatrpc.CallInfo, dedupCover bool) *flatrpc.CallInfo {
	var extra flatrpc.CallInfo
	if dedupCover {
		extraCover := make(cover.Cover)
		for _, part := range extraParts {
			extraCover.Merge(part.Cover)
		}
		extra.Cover = extraCover.Serialize()
	} else {
		for _, part := range extraParts {
			extra.Cover = append(extra.Cover, part.Cover...)
		}
	}
	extraSignal := make(signal.Signal)
	for _, part := range extraParts {
		extraSignal.Merge(signal.FromRaw(part.Signal, 0))
	}
	extra.Signal = make([]uint64, len(extraSignal))
	i := 0
	for s := range extraSignal {
		extra.Signal[i] = uint64(s)
		i++
	}
	for _, part := range extraParts {
		extra.Comps = append(extra.Comps, part.Comps...)
	}
	return &extra
}

func readComps(outp *[]byte, compsSize uint32) ([]*flatrpc.Comparison, error) {
	comps := make([]*flatrpc.Comparison, 0, 2*compsSize)
	for i := uint32(0); i < compsSize; i++ {
		typ, ok := readUint32(outp)
		if !ok {
			return nil, fmt.Errorf("failed to read comp %v", i)
		}
		if typ > compConstMask|compSizeMask {
			return nil, fmt.Errorf("bad comp %v type %v", i, typ)
		}
		var op1, op2 uint64
		var ok1, ok2 bool
		if typ&compSizeMask == compSize8 {
			op1, ok1 = readUint64(outp)
			op2, ok2 = readUint64(outp)
		} else {
			var tmp1, tmp2 uint32
			tmp1, ok1 = readUint32(outp)
			tmp2, ok2 = readUint32(outp)
			op1, op2 = uint64(tmp1), uint64(tmp2)
		}
		if !ok1 || !ok2 {
			return nil, fmt.Errorf("failed to read comp %v op", i)
		}
		if op1 == op2 {
			continue // it's useless to store such comparisons
		}
		comps = append(comps, &flatrpc.Comparison{Op1: op2, Op2: op1})
		if (typ & compConstMask) != 0 {
			// If one of the operands was const, then this operand is always
			// placed first in the instrumented callbacks. Such an operand
			// could not be an argument of our syscalls (because otherwise
			// it wouldn't be const), thus we simply ignore it.
			continue
		}
		comps = append(comps, &flatrpc.Comparison{Op1: op1, Op2: op2})
	}
	return comps, nil
}

func readUint32(outp *[]byte) (uint32, bool) {
	out := *outp
	if len(out) < 4 {
		return 0, false
	}
	v := prog.HostEndian.Uint32(out)
	*outp = out[4:]
	return v, true
}

func readUint64(outp *[]byte) (uint64, bool) {
	out := *outp
	if len(out) < 8 {
		return 0, false
	}
	v := prog.HostEndian.Uint64(out)
	*outp = out[8:]
	return v, true
}

func readUint64Array(outp *[]byte, size uint32) ([]uint64, bool) {
	if size == 0 {
		return nil, true
	}
	out := *outp
	dataSize := int(size * 8)
	if dataSize > len(out) {
		return nil, false
	}
	res := unsafe.Slice((*uint64)(unsafe.Pointer(&out[0])), size)
	*outp = out[dataSize:]
	// Detach the resulting array from the original data.
	return slices.Clone(res), true
}

type command struct {
	pid        int
	config     *Config
	flags      flatrpc.ExecEnv
	sandboxArg int64
	timeout    time.Duration
	cmd        *exec.Cmd
	dir        string
	readDone   chan []byte
	exited     chan error
	inrp       *os.File
	outwp      *os.File
	outmem     []byte
	freshness  uint64
}

const (
	inMagic  = uint64(0xbadc0ffeebadface)
	outMagic = uint32(0xbadf00d)
)

type handshakeReq struct {
	magic      uint64
	flags      uint64 // env flags
	pid        uint64
	sandboxArg uint64
}

type handshakeReply struct {
	magic uint32
}

type executeReq struct {
	magic            uint64
	envFlags         uint64 // env flags
	execFlags        uint64 // exec flags
	pid              uint64
	syscallTimeoutMS uint64
	programTimeoutMS uint64
	slowdownScale    uint64
	progSize         uint64
	// This structure is followed by a serialized test program in encodingexec format.
	// Both when sent over a pipe or in shared memory.
}

type executeReply struct {
	magic uint32
	// If done is 0, then this is call completion message followed by callReply.
	// If done is 1, then program execution is finished and status is set.
	done   uint32
	status uint32
}

type callReply struct {
	magic      uint32
	index      uint32 // call index in the program
	num        uint32 // syscall number (for cross-checking)
	errno      uint32
	flags      uint32 // see CallFlags
	signalSize uint32
	coverSize  uint32
	compsSize  uint32
	// signal/cover/comps follow
}

func (env *Env) makeCommand(opts *flatrpc.ExecOpts, tmpDir string) (*command, error) {
	dir, err := os.MkdirTemp(tmpDir, "syzkaller-testdir")
	if err != nil {
		return nil, fmt.Errorf("failed to create temp dir: %w", err)
	}
	dir = osutil.Abs(dir)

	timeout := env.config.Timeouts.Program
	if env.config.UseForkServer {
		// Executor has an internal timeout and protects against most hangs when fork server is enabled,
		// so we use quite large timeout. Executor can be slow due to global locks in namespaces
		// and other things, so let's better wait than report false misleading crashes.
		timeout *= 5
	}

	c := &command{
		pid:        env.pid,
		config:     env.config,
		flags:      opts.EnvFlags,
		sandboxArg: opts.SandboxArg,
		timeout:    timeout,
		dir:        dir,
		outmem:     env.out,
	}
	defer func() {
		if c != nil {
			c.close()
		}
	}()

	if err := os.Chmod(dir, 0777); err != nil {
		return nil, fmt.Errorf("failed to chmod temp dir: %w", err)
	}

	// Output capture pipe.
	rp, wp, err := os.Pipe()
	if err != nil {
		return nil, fmt.Errorf("failed to create pipe: %w", err)
	}
	defer wp.Close()

	// executor->ipc command pipe.
	inrp, inwp, err := os.Pipe()
	if err != nil {
		return nil, fmt.Errorf("failed to create pipe: %w", err)
	}
	defer inwp.Close()
	c.inrp = inrp

	// ipc->executor command pipe.
	outrp, outwp, err := os.Pipe()
	if err != nil {
		return nil, fmt.Errorf("failed to create pipe: %w", err)
	}
	defer outrp.Close()
	c.outwp = outwp

	c.readDone = make(chan []byte, 1)

	cmd := osutil.Command(env.bin[0], env.bin[1:]...)
	if env.inFile != nil && env.outFile != nil {
		cmd.ExtraFiles = []*os.File{env.inFile, env.outFile}
	}
	cmd.Dir = dir
	// Tell ASAN to not mess with our NONFAILING.
	cmd.Env = append(append([]string{}, os.Environ()...), "ASAN_OPTIONS=handle_segv=0 allow_user_segv_handler=1")
	cmd.Stdin = outrp
	cmd.Stdout = inwp
	if c.flags&flatrpc.ExecEnvDebug != 0 {
		close(c.readDone)
		cmd.Stderr = os.Stdout
	} else {
		cmd.Stderr = wp
		go func(c *command) {
			// Read out output in case executor constantly prints something.
			const bufSize = 128 << 10
			output := make([]byte, bufSize)
			var size uint64
			for {
				n, err := rp.Read(output[size:])
				if n > 0 {
					size += uint64(n)
					if size >= bufSize*3/4 {
						copy(output, output[size-bufSize/2:size])
						size = bufSize / 2
					}
				}
				if err != nil {
					rp.Close()
					c.readDone <- output[:size]
					close(c.readDone)
					return
				}
			}
		}(c)
	}
	if err := cmd.Start(); err != nil {
		return nil, fmt.Errorf("failed to start executor binary: %w", err)
	}
	c.exited = make(chan error, 1)
	c.cmd = cmd
	go func(c *command) {
		err := c.cmd.Wait()
		c.exited <- err
		close(c.exited)
		// Avoid a livelock if cmd.Stderr has been leaked to another alive process.
		rp.SetDeadline(time.Now().Add(5 * time.Second))
	}(c)
	wp.Close()
	// Note: we explicitly close inwp before calling handshake even though we defer it above.
	// If we don't do it and executor exits before writing handshake reply,
	// reading from inrp will hang since we hold another end of the pipe open.
	inwp.Close()

	if c.config.UseForkServer {
		if err := c.handshake(); err != nil {
			return nil, err
		}
	}
	tmp := c
	c = nil // disable defer above
	return tmp, nil
}

func (c *command) close() {
	if c.cmd != nil {
		c.cmd.Process.Kill()
		c.wait()
	}
	osutil.RemoveAll(c.dir)
	if c.inrp != nil {
		c.inrp.Close()
	}
	if c.outwp != nil {
		c.outwp.Close()
	}
}

// handshake sends handshakeReq and waits for handshakeReply.
func (c *command) handshake() error {
	req := &handshakeReq{
		magic:      inMagic,
		flags:      uint64(c.flags),
		pid:        uint64(c.pid),
		sandboxArg: uint64(c.sandboxArg),
	}
	reqData := (*[unsafe.Sizeof(*req)]byte)(unsafe.Pointer(req))[:]
	if _, err := c.outwp.Write(reqData); err != nil {
		return c.handshakeError(fmt.Errorf("failed to write control pipe: %w", err))
	}

	read := make(chan error, 1)
	go func() {
		reply := &handshakeReply{}
		replyData := (*[unsafe.Sizeof(*reply)]byte)(unsafe.Pointer(reply))[:]
		if _, err := io.ReadFull(c.inrp, replyData); err != nil {
			read <- err
			return
		}
		if reply.magic != outMagic {
			read <- fmt.Errorf("bad handshake reply magic 0x%x", reply.magic)
			return
		}
		read <- nil
	}()
	// Sandbox setup can take significant time.
	timeout := time.NewTimer(time.Minute * c.config.Timeouts.Scale)
	select {
	case err := <-read:
		timeout.Stop()
		if err != nil {
			return c.handshakeError(err)
		}
		return nil
	case <-timeout.C:
		return c.handshakeError(fmt.Errorf("not serving"))
	}
}

func (c *command) handshakeError(err error) error {
	c.cmd.Process.Kill()
	output := <-c.readDone
	err = fmt.Errorf("executor %v: %w\n%s", c.pid, err, output)
	c.wait()
	return err
}

func (c *command) wait() error {
	return <-c.exited
}

func (c *command) exec(opts *flatrpc.ExecOpts, progData []byte) (output []byte, hanged bool, err0 error) {
	if c.flags != opts.EnvFlags || c.sandboxArg != opts.SandboxArg {
		panic("wrong command")
	}
	req := &executeReq{
		magic:            inMagic,
		envFlags:         uint64(c.flags),
		execFlags:        uint64(opts.ExecFlags),
		pid:              uint64(c.pid),
		syscallTimeoutMS: uint64(c.config.Timeouts.Syscall / time.Millisecond),
		programTimeoutMS: uint64(c.config.Timeouts.Program / time.Millisecond),
		slowdownScale:    uint64(c.config.Timeouts.Scale),
		progSize:         uint64(len(progData)),
	}
	reqData := (*[unsafe.Sizeof(*req)]byte)(unsafe.Pointer(req))[:]
	if _, err := c.outwp.Write(reqData); err != nil {
		output = <-c.readDone
		err0 = fmt.Errorf("executor %v: failed to write control pipe: %w", c.pid, err)
		return
	}
	if progData != nil {
		if _, err := c.outwp.Write(progData); err != nil {
			output = <-c.readDone
			err0 = fmt.Errorf("executor %v: failed to write control pipe: %w", c.pid, err)
			return
		}
	}
	// At this point program is executing.

	done := make(chan bool)
	hang := make(chan bool)
	go func() {
		t := time.NewTimer(c.timeout)
		select {
		case <-t.C:
			c.cmd.Process.Kill()
			hang <- true
		case <-done:
			t.Stop()
			hang <- false
		}
	}()
	exitStatus := -1
	completedCalls := (*uint32)(unsafe.Pointer(&c.outmem[0]))
	outmem := c.outmem[4:]
	for {
		reply := &executeReply{}
		replyData := (*[unsafe.Sizeof(*reply)]byte)(unsafe.Pointer(reply))[:]
		if _, err := io.ReadFull(c.inrp, replyData); err != nil {
			break
		}
		if reply.magic != outMagic {
			fmt.Fprintf(os.Stderr, "executor %v: got bad reply magic 0x%x\n", c.pid, reply.magic)
			os.Exit(1)
		}
		if reply.done != 0 {
			exitStatus = int(reply.status)
			break
		}
		callReply := &callReply{}
		callReplyData := (*[unsafe.Sizeof(*callReply)]byte)(unsafe.Pointer(callReply))[:]
		if _, err := io.ReadFull(c.inrp, callReplyData); err != nil {
			break
		}
		if callReply.signalSize != 0 || callReply.coverSize != 0 || callReply.compsSize != 0 {
			// This is unsupported yet.
			fmt.Fprintf(os.Stderr, "executor %v: got call reply with coverage\n", c.pid)
			os.Exit(1)
		}
		copy(outmem, callReplyData)
		outmem = outmem[len(callReplyData):]
		*completedCalls++
	}
	close(done)
	if exitStatus == 0 {
		// Program was OK.
		<-hang
		return
	}
	c.cmd.Process.Kill()
	output = <-c.readDone
	err := c.wait()
	if err != nil {
		output = append(output, err.Error()...)
		output = append(output, '\n')
	}
	if <-hang {
		hanged = true
		return
	}
	if exitStatus == -1 {
		if c.cmd.ProcessState == nil {
			exitStatus = statusFail
		} else {
			exitStatus = osutil.ProcessExitStatus(c.cmd.ProcessState)
		}
	}
	// Ignore all other errors.
	// Without fork server executor can legitimately exit (program contains exit_group),
	// with fork server the top process can exit with statusFail if it wants special handling.
	if exitStatus == statusFail {
		err0 = fmt.Errorf("executor %v: exit status %d err %w\n%s", c.pid, exitStatus, err, output)
	}
	return
}
