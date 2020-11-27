// Copyright 2015 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package ipc

import (
	"fmt"
	"io"
	"io/ioutil"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strings"
	"sync/atomic"
	"time"
	"unsafe"

	"github.com/google/syzkaller/pkg/cover"
	"github.com/google/syzkaller/pkg/osutil"
	"github.com/google/syzkaller/pkg/signal"
	"github.com/google/syzkaller/prog"
	"github.com/google/syzkaller/sys/targets"
)

// Configuration flags for Config.Flags.
type EnvFlags uint64

// Note: New / changed flags should be added to parse_env_flags in executor.cc.
const (
	FlagDebug               EnvFlags = 1 << iota // debug output from executor
	FlagSignal                                   // collect feedback signals (coverage)
	FlagSandboxSetuid                            // impersonate nobody user
	FlagSandboxNamespace                         // use namespaces for sandboxing
	FlagSandboxAndroid                           // use Android sandboxing for the untrusted_app domain
	FlagExtraCover                               // collect extra coverage
	FlagEnableTun                                // setup and use /dev/tun for packet injection
	FlagEnableNetDev                             // setup more network devices for testing
	FlagEnableNetReset                           // reset network namespace between programs
	FlagEnableCgroups                            // setup cgroups for testing
	FlagEnableCloseFds                           // close fds after each program
	FlagEnableDevlinkPCI                         // setup devlink PCI device
	FlagEnableVhciInjection                      // setup and use /dev/vhci for hci packet injection
	FlagEnableWifi                               // setup and use mac80211_hwsim for wifi emulation
)

// Per-exec flags for ExecOpts.Flags.
type ExecFlags uint64

const (
	FlagCollectCover ExecFlags = 1 << iota // collect coverage
	FlagDedupCover                         // deduplicate coverage in executor
	FlagInjectFault                        // inject a fault in this execution (see ExecOpts)
	FlagCollectComps                       // collect KCOV comparisons
	FlagThreaded                           // use multiple threads to mitigate blocked syscalls
	FlagCollide                            // collide syscalls to provoke data races
	FlagDoubleFetch                        // Collect Double fetching bug
)

type ExecOpts struct {
	Flags     ExecFlags
	FaultCall int // call index for fault injection (0-based)
	FaultNth  int // fault n-th operation in the call (0-based)
}

// Config is the configuration for Env.
type Config struct {
	// Path to executor binary.
	Executor string

	UseShmem      bool // use shared memory instead of pipes for communication
	UseForkServer bool // use extended protocol with handshake

	// Flags are configuation flags, defined above.
	Flags EnvFlags

	// Timeout is the execution timeout for a single program.
	Timeout time.Duration
}

type CallFlags uint32

const (
	CallExecuted      CallFlags = 1 << iota // was started at all
	CallFinished                            // finished executing (rather than blocked forever)
	CallBlocked                             // finished but blocked during execution
	CallFaultInjected                       // fault was injected into this call
)

type CallInfo struct {
	Flags  CallFlags
	Signal []uint32 // feedback signal, filled if FlagSignal is set
	Cover  []uint32 // per-call coverage, filled if FlagSignal is set and cover == true,
	// if dedup == false, then cov effectively contains a trace, otherwise duplicates are removed
	Comps prog.CompMap // per-call comparison operands
	Errno int          // call errno (0 if the call was successful)
}

type ProgInfo struct {
	Calls []CallInfo
	Extra CallInfo // stores Signal and Cover collected from background threads
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

	StatExecs    uint64
	StatRestarts uint64
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

func SandboxToFlags(sandbox string) (EnvFlags, error) {
	switch sandbox {
	case "none":
		return 0, nil
	case "setuid":
		return FlagSandboxSetuid, nil
	case "namespace":
		return FlagSandboxNamespace, nil
	case "android":
		return FlagSandboxAndroid, nil
	default:
		return 0, fmt.Errorf("sandbox must contain one of none/setuid/namespace/android")
	}
}

func FlagsToSandbox(flags EnvFlags) string {
	if flags&FlagSandboxSetuid != 0 {
		return "setuid"
	} else if flags&FlagSandboxNamespace != 0 {
		return "namespace"
	} else if flags&FlagSandboxAndroid != 0 {
		return "android"
	}
	return "none"
}

func MakeEnv(config *Config, pid int) (*Env, error) {
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
		inmem = make([]byte, prog.ExecBufferSize)
		outmem = make([]byte, outputSize)
	}
	env := &Env{
		in:      inmem,
		out:     outmem,
		inFile:  inf,
		outFile: outf,
		bin:     strings.Split(config.Executor, " "),
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

var rateLimit = time.NewTicker(1 * time.Second)

// Exec starts executor binary to execute program p and returns information about the execution:
// output: process output
// info: per-call info
// hanged: program hanged and was killed
// err0: failed to start the process or bug in executor itself.
func (env *Env) Exec(opts *ExecOpts, p *prog.Prog) (output []byte, info *ProgInfo, hanged bool, err0 error) {
	// Copy-in serialized program.
	progSize, err := p.SerializeForExec(env.in)
	if err != nil {
		err0 = err
		return
	}
	var progData []byte
	if !env.config.UseShmem {
		progData = env.in[:progSize]
	}
	// Zero out the first two words (ncmd and nsig), so that we don't have garbage there
	// if executor crashes before writing non-garbage there.
	for i := 0; i < 4; i++ {
		env.out[i] = 0
	}

	atomic.AddUint64(&env.StatExecs, 1)
	if env.cmd == nil {
		if p.Target.OS != targets.TestOS && targets.Get(p.Target.OS, p.Target.Arch).HostFuzzer {
			// The executor is actually ssh,
			// starting them too frequently leads to timeouts.
			<-rateLimit.C
		}
		tmpDirPath := "./"
		atomic.AddUint64(&env.StatRestarts, 1)
		env.cmd, err0 = makeCommand(env.pid, env.bin, env.config, env.inFile, env.outFile, env.out, tmpDirPath)
		if err0 != nil {
			return
		}
	}
	output, hanged, err0 = env.cmd.exec(opts, progData)
	if err0 != nil {
		env.cmd.close()
		env.cmd = nil
		return
	}

	info, err0 = env.parseOutput(p)
	if info != nil && env.config.Flags&FlagSignal == 0 {
		addFallbackSignal(p, info)
	}
	if !env.config.UseForkServer {
		env.cmd.close()
		env.cmd = nil
	}
	return
}

// addFallbackSignal computes simple fallback signal in cases we don't have real coverage signal.
// We use syscall number or-ed with returned errno value as signal.
// At least this gives us all combinations of syscall+errno.
func addFallbackSignal(p *prog.Prog, info *ProgInfo) {
	callInfos := make([]prog.CallInfo, len(info.Calls))
	for i, inf := range info.Calls {
		if inf.Flags&CallExecuted != 0 {
			callInfos[i].Flags |= prog.CallExecuted
		}
		if inf.Flags&CallFinished != 0 {
			callInfos[i].Flags |= prog.CallFinished
		}
		if inf.Flags&CallBlocked != 0 {
			callInfos[i].Flags |= prog.CallBlocked
		}
		callInfos[i].Errno = inf.Errno
	}
	p.FallbackSignal(callInfos)
	for i, inf := range callInfos {
		info.Calls[i].Signal = inf.Signal
	}
}

func (env *Env) parseOutput(p *prog.Prog) (*ProgInfo, error) {
	out := env.out
	ncmd, ok := readUint32(&out)
	if !ok {
		return nil, fmt.Errorf("failed to read number of calls")
	}
	info := &ProgInfo{Calls: make([]CallInfo, len(p.Calls))}
	extraParts := make([]CallInfo, 0)
	for i := uint32(0); i < ncmd; i++ {
		if len(out) < int(unsafe.Sizeof(callReply{})) {
			return nil, fmt.Errorf("failed to read call %v reply", i)
		}
		reply := *(*callReply)(unsafe.Pointer(&out[0]))
		out = out[unsafe.Sizeof(callReply{}):]
		var inf *CallInfo
		if reply.index != extraReplyIndex {
			if int(reply.index) >= len(info.Calls) {
				return nil, fmt.Errorf("bad call %v index %v/%v", i, reply.index, len(info.Calls))
			}
			if num := p.Calls[reply.index].Meta.ID; int(reply.num) != num {
				return nil, fmt.Errorf("wrong call %v num %v/%v", i, reply.num, num)
			}
			inf = &info.Calls[reply.index]
			if inf.Flags != 0 || inf.Signal != nil {
				return nil, fmt.Errorf("duplicate reply for call %v/%v/%v", i, reply.index, reply.num)
			}
			inf.Errno = int(reply.errno)
			inf.Flags = CallFlags(reply.flags)
		} else {
			extraParts = append(extraParts, CallInfo{})
			inf = &extraParts[len(extraParts)-1]
		}
		if inf.Signal, ok = readUint32Array(&out, reply.signalSize); !ok {
			return nil, fmt.Errorf("call %v/%v/%v: signal overflow: %v/%v",
				i, reply.index, reply.num, reply.signalSize, len(out))
		}
		if inf.Cover, ok = readUint32Array(&out, reply.coverSize); !ok {
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
	info.Extra = convertExtra(extraParts)
	return info, nil
}

func convertExtra(extraParts []CallInfo) CallInfo {
	var extra CallInfo
	extraCover := make(cover.Cover)
	extraSignal := make(signal.Signal)
	for _, part := range extraParts {
		extraCover.Merge(part.Cover)
		extraSignal.Merge(signal.FromRaw(part.Signal, 0))
	}
	extra.Cover = extraCover.Serialize()
	extra.Signal = make([]uint32, len(extraSignal))
	i := 0
	for s := range extraSignal {
		extra.Signal[i] = uint32(s)
		i++
	}
	return extra
}

func readComps(outp *[]byte, compsSize uint32) (prog.CompMap, error) {
	if compsSize == 0 {
		return nil, nil
	}
	compMap := make(prog.CompMap)
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
		compMap.AddComp(op2, op1)
		if (typ & compConstMask) != 0 {
			// If one of the operands was const, then this operand is always
			// placed first in the instrumented callbacks. Such an operand
			// could not be an argument of our syscalls (because otherwise
			// it wouldn't be const), thus we simply ignore it.
			continue
		}
		compMap.AddComp(op1, op2)
	}
	return compMap, nil
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

func readUint32Array(outp *[]byte, size uint32) ([]uint32, bool) {
	if size == 0 {
		return nil, true
	}
	out := *outp
	if int(size)*4 > len(out) {
		return nil, false
	}
	hdr := reflect.SliceHeader{
		Data: uintptr(unsafe.Pointer(&out[0])),
		Len:  int(size),
		Cap:  int(size),
	}
	res := *(*[]uint32)(unsafe.Pointer(&hdr))
	*outp = out[size*4:]
	return res, true
}

type command struct {
	pid      int
	config   *Config
	timeout  time.Duration
	cmd      *exec.Cmd
	dir      string
	readDone chan []byte
	exited   chan struct{}
	inrp     *os.File
	outwp    *os.File
	outmem   []byte
}

const (
	inMagic  = uint64(0xbadc0ffeebadface)
	outMagic = uint32(0xbadf00d)
)

type handshakeReq struct {
	magic uint64
	flags uint64 // env flags
	pid   uint64
}

type handshakeReply struct {
	magic uint32
}

type executeReq struct {
	magic     uint64
	envFlags  uint64 // env flags
	execFlags uint64 // exec flags
	pid       uint64
	faultCall uint64
	faultNth  uint64
	progSize  uint64
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
	index      uint32 // call index in the program
	num        uint32 // syscall number (for cross-checking)
	errno      uint32
	flags      uint32 // see CallFlags
	signalSize uint32
	coverSize  uint32
	compsSize  uint32
	// signal/cover/comps follow
}

func makeCommand(pid int, bin []string, config *Config, inFile, outFile *os.File, outmem []byte,
	tmpDirPath string) (*command, error) {
	dir, err := ioutil.TempDir(tmpDirPath, "syzkaller-testdir")
	if err != nil {
		return nil, fmt.Errorf("failed to create temp dir: %v", err)
	}
	dir = osutil.Abs(dir)

	c := &command{
		pid:     pid,
		config:  config,
		timeout: sanitizeTimeout(config),
		dir:     dir,
		outmem:  outmem,
	}
	defer func() {
		if c != nil {
			c.close()
		}
	}()

	if err := os.Chmod(dir, 0777); err != nil {
		return nil, fmt.Errorf("failed to chmod temp dir: %v", err)
	}

	// Output capture pipe.
	rp, wp, err := os.Pipe()
	if err != nil {
		return nil, fmt.Errorf("failed to create pipe: %v", err)
	}
	defer wp.Close()

	// executor->ipc command pipe.
	inrp, inwp, err := os.Pipe()
	if err != nil {
		return nil, fmt.Errorf("failed to create pipe: %v", err)
	}
	defer inwp.Close()
	c.inrp = inrp

	// ipc->executor command pipe.
	outrp, outwp, err := os.Pipe()
	if err != nil {
		return nil, fmt.Errorf("failed to create pipe: %v", err)
	}
	defer outrp.Close()
	c.outwp = outwp

	c.readDone = make(chan []byte, 1)
	c.exited = make(chan struct{})

	cmd := osutil.Command(bin[0], bin[1:]...)
	if inFile != nil && outFile != nil {
		cmd.ExtraFiles = []*os.File{inFile, outFile}
	}
	cmd.Dir = dir
	// Tell ASAN to not mess with our NONFAILING.
	cmd.Env = append(append([]string{}, os.Environ()...), "ASAN_OPTIONS=handle_segv=0 allow_user_segv_handler=1")
	cmd.Stdin = outrp
	cmd.Stdout = inwp
	if config.Flags&FlagDebug != 0 {
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
		return nil, fmt.Errorf("failed to start executor binary: %v", err)
	}
	c.cmd = cmd
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
		magic: inMagic,
		flags: uint64(c.config.Flags),
		pid:   uint64(c.pid),
	}
	reqData := (*[unsafe.Sizeof(*req)]byte)(unsafe.Pointer(req))[:]
	if _, err := c.outwp.Write(reqData); err != nil {
		return c.handshakeError(fmt.Errorf("failed to write control pipe: %v", err))
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
	timeout := time.NewTimer(time.Minute)
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
	err = fmt.Errorf("executor %v: %v\n%s", c.pid, err, output)
	c.wait()
	return err
}

func (c *command) wait() error {
	err := c.cmd.Wait()
	select {
	case <-c.exited:
		// c.exited closed by an earlier call to wait.
	default:
		close(c.exited)
	}
	return err
}

func (c *command) exec(opts *ExecOpts, progData []byte) (output []byte, hanged bool, err0 error) {
	req := &executeReq{
		magic:     inMagic,
		envFlags:  uint64(c.config.Flags),
		execFlags: uint64(opts.Flags),
		pid:       uint64(c.pid),
		faultCall: uint64(opts.FaultCall),
		faultNth:  uint64(opts.FaultNth),
		progSize:  uint64(len(progData)),
	}
	reqData := (*[unsafe.Sizeof(*req)]byte)(unsafe.Pointer(req))[:]
	if _, err := c.outwp.Write(reqData); err != nil {
		output = <-c.readDone
		err0 = fmt.Errorf("executor %v: failed to write control pipe: %v", c.pid, err)
		return
	}
	if progData != nil {
		if _, err := c.outwp.Write(progData); err != nil {
			output = <-c.readDone
			err0 = fmt.Errorf("executor %v: failed to write control pipe: %v", c.pid, err)
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
	if err := c.wait(); <-hang {
		hanged = true
		if err != nil {
			output = append(output, err.Error()...)
			output = append(output, '\n')
		}
		return
	}
	if exitStatus == -1 {
		exitStatus = osutil.ProcessExitStatus(c.cmd.ProcessState)
	}
	// Ignore all other errors.
	// Without fork server executor can legitimately exit (program contains exit_group),
	// with fork server the top process can exit with statusFail if it wants special handling.
	if exitStatus == statusFail {
		err0 = fmt.Errorf("executor %v: exit status %d\n%s", c.pid, exitStatus, output)
	}
	return
}

func sanitizeTimeout(config *Config) time.Duration {
	const (
		executorTimeout = 5 * time.Second
		minTimeout      = executorTimeout + 2*time.Second
	)
	timeout := config.Timeout
	if timeout == 0 {
		// Executor protects against most hangs, so we use quite large timeout here.
		// Executor can be slow due to global locks in namespaces and other things,
		// so let's better wait than report false misleading crashes.
		timeout = time.Minute
		if !config.UseForkServer {
			// If there is no fork server, executor does not have internal timeout.
			timeout = executorTimeout
		}
	}
	// IPC timeout must be larger then executor timeout.
	// Otherwise IPC will kill parent executor but leave child executor alive.
	if config.UseForkServer && timeout < minTimeout {
		timeout = minTimeout
	}
	return timeout
}
