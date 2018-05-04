// Copyright 2015 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package ipc

import (
	"bytes"
	"flag"
	"fmt"
	"io"
	"io/ioutil"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"time"
	"unsafe"

	"github.com/google/syzkaller/pkg/host"
	"github.com/google/syzkaller/pkg/osutil"
	"github.com/google/syzkaller/prog"
	"github.com/google/syzkaller/sys/targets"
)

// Configuration flags for Config.Flags.
type EnvFlags uint64

const (
	FlagDebug            EnvFlags = 1 << iota // debug output from executor
	FlagSignal                                // collect feedback signals (coverage)
	FlagSandboxSetuid                         // impersonate nobody user
	FlagSandboxNamespace                      // use namespaces for sandboxing
	FlagEnableTun                             // initialize and use tun in executor
	FlagEnableFault                           // enable fault injection support
	FlagUseShmem                              // use shared memory instead of pipes for communication
	FlagUseForkServer                         // use extended protocol with handshake
)

// Per-exec flags for ExecOpts.Flags:
type ExecFlags uint64

const (
	FlagCollectCover ExecFlags = 1 << iota // collect coverage
	FlagDedupCover                         // deduplicate coverage in executor
	FlagInjectFault                        // inject a fault in this execution (see ExecOpts)
	FlagCollectComps                       // collect KCOV comparisons
	FlagThreaded                           // use multiple threads to mitigate blocked syscalls
	FlagCollide                            // collide syscalls to provoke data races
)

const (
	outputSize = 16 << 20

	statusFail  = 67
	statusError = 68
	statusRetry = 69
)

var (
	flagExecutor    = flag.String("executor", "./syz-executor", "path to executor binary")
	flagThreaded    = flag.Bool("threaded", true, "use threaded mode in executor")
	flagCollide     = flag.Bool("collide", true, "collide syscalls to provoke data races")
	flagSignal      = flag.Bool("cover", false, "collect feedback signals (coverage)")
	flagSandbox     = flag.String("sandbox", "none", "sandbox for fuzzing (none/setuid/namespace)")
	flagDebug       = flag.Bool("debug", false, "debug output from executor")
	flagTimeout     = flag.Duration("timeout", 0, "execution timeout")
	flagAbortSignal = flag.Int("abort_signal", 0, "initial signal to send to executor"+
		" in error conditions; upgrades to SIGKILL if executor does not exit")
	flagBufferSize = flag.Uint64("buffer_size", 0, "internal buffer size (in bytes) for executor output")
	flagIPC        = flag.String("ipc", "", "ipc scheme (pipe/shmem)")
)

type ExecOpts struct {
	Flags     ExecFlags
	FaultCall int // call index for fault injection (0-based)
	FaultNth  int // fault n-th operation in the call (0-based)
}

// ExecutorFailure is returned from MakeEnv or from env.Exec when executor terminates by calling fail function.
// This is considered a logical error (a failed assert).
type ExecutorFailure string

func (err ExecutorFailure) Error() string {
	return string(err)
}

// Config is the configuration for Env.
type Config struct {
	// Path to executor binary.
	Executor string

	// Flags are configuation flags, defined above.
	Flags EnvFlags

	// Timeout is the execution timeout for a single program.
	Timeout time.Duration

	// AbortSignal is the signal to send to the executor in error conditions.
	AbortSignal int

	// BufferSize is the size of the internal buffer for executor output.
	BufferSize uint64
}

func DefaultConfig() (*Config, *ExecOpts, error) {
	c := &Config{
		Executor:    *flagExecutor,
		Timeout:     *flagTimeout,
		AbortSignal: *flagAbortSignal,
		BufferSize:  *flagBufferSize,
	}
	if *flagSignal {
		c.Flags |= FlagSignal
	}
	if *flagDebug {
		c.Flags |= FlagDebug
	}
	switch *flagSandbox {
	case "none":
	case "setuid":
		c.Flags |= FlagSandboxSetuid
	case "namespace":
		c.Flags |= FlagSandboxNamespace
	default:
		return nil, nil, fmt.Errorf("flag sandbox must contain one of none/setuid/namespace")
	}

	sysTarget := targets.List[runtime.GOOS][runtime.GOARCH]
	if sysTarget.ExecutorUsesShmem {
		c.Flags |= FlagUseShmem
	}
	if sysTarget.ExecutorUsesForkServer {
		c.Flags |= FlagUseForkServer
	}
	switch *flagIPC {
	case "":
	case "pipe":
		c.Flags &^= FlagUseShmem
	case "shmem":
		c.Flags |= FlagUseShmem
	default:
		return nil, nil, fmt.Errorf("unknown ipc scheme: %v", *flagIPC)
	}

	opts := &ExecOpts{
		Flags: FlagDedupCover,
	}
	if *flagThreaded {
		opts.Flags |= FlagThreaded
	}
	if *flagCollide {
		opts.Flags |= FlagCollide
	}

	return c, opts, nil
}

type CallInfo struct {
	Signal []uint32 // feedback signal, filled if FlagSignal is set
	Cover  []uint32 // per-call coverage, filled if FlagSignal is set and cover == true,
	//if dedup == false, then cov effectively contains a trace, otherwise duplicates are removed
	Comps         prog.CompMap // per-call comparison operands
	Errno         int          // call errno (0 if the call was successful)
	FaultInjected bool
}

type Env struct {
	in  []byte
	out []byte

	cmd     *command
	inFile  *os.File
	outFile *os.File
	bin     []string
	pid     int
	config  *Config

	StatExecs    uint64
	StatRestarts uint64
}

const (
	// Comparison types masks taken from KCOV headers.
	compSizeMask  = 6
	compSize8     = 6
	compConstMask = 1
)

func MakeEnv(config *Config, pid int) (*Env, error) {
	var inf, outf *os.File
	var inmem, outmem []byte
	if config.Flags&FlagUseShmem != 0 {
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
	// we create a link from 'syz-executor15' to 'syz-executor' and use 'syz-executor15' as binary.
	// This allows to easily identify program that lead to a crash in the log.
	// Log contains pid in "executing program 15" and crashes usually contain "Comm: syz-executor15".
	base := filepath.Base(env.bin[0])
	pidStr := fmt.Sprint(pid)
	if len(base)+len(pidStr) >= 16 {
		// TASK_COMM_LEN is currently set to 16
		base = base[:15-len(pidStr)]
	}
	binCopy := filepath.Join(filepath.Dir(env.bin[0]), base+pidStr)
	if err := os.Link(env.bin[0], binCopy); err == nil {
		env.bin[0] = binCopy
	}
	inf = nil
	outf = nil
	return env, nil
}

func (env *Env) Close() error {
	if env.cmd != nil {
		env.cmd.close()
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

var enableFaultOnce sync.Once

// Exec starts executor binary to execute program p and returns information about the execution:
// output: process output
// info: per-call info
// failed: true if executor has detected a kernel bug
// hanged: program hanged and was killed
// err0: failed to start process, or executor has detected a logical error
func (env *Env) Exec(opts *ExecOpts, p *prog.Prog) (output []byte, info []CallInfo, failed, hanged bool, err0 error) {
	if opts.Flags&FlagInjectFault != 0 {
		enableFaultOnce.Do(func() {
			if err := host.EnableFaultInjection(); err != nil {
				panic(err)
			}
		})
	}
	// Copy-in serialized program.
	progSize, err := p.SerializeForExec(env.in)
	if err != nil {
		err0 = fmt.Errorf("executor %v: failed to serialize: %v", env.pid, err)
		return
	}
	var progData []byte
	if env.config.Flags&FlagUseShmem == 0 {
		progData = env.in[:progSize]
	}
	if env.out != nil {
		// Zero out the first two words (ncmd and nsig), so that we don't have garbage there
		// if executor crashes before writing non-garbage there.
		for i := 0; i < 4; i++ {
			env.out[i] = 0
		}
	}

	atomic.AddUint64(&env.StatExecs, 1)
	if env.cmd == nil {
		atomic.AddUint64(&env.StatRestarts, 1)
		env.cmd, err0 = makeCommand(env.pid, env.bin, env.config, env.inFile, env.outFile)
		if err0 != nil {
			return
		}
	}
	var restart bool
	output, failed, hanged, restart, err0 = env.cmd.exec(opts, progData)
	if err0 != nil || restart {
		env.cmd.close()
		env.cmd = nil
		return
	}

	if env.out != nil {
		info, err0 = env.readOutCoverage(p)
	}
	return
}

func (env *Env) readOutCoverage(p *prog.Prog) (info []CallInfo, err0 error) {
	out := ((*[1 << 28]uint32)(unsafe.Pointer(&env.out[0])))[:len(env.out)/int(unsafe.Sizeof(uint32(0)))]
	readOut := func(v *uint32) bool {
		if len(out) == 0 {
			return false
		}
		*v = out[0]
		out = out[1:]
		return true
	}

	readOutAndSetErr := func(v *uint32, msg string, args ...interface{}) bool {
		if !readOut(v) {
			err0 = fmt.Errorf(msg, args)
			return false
		}
		return true
	}

	// Reads out a 64 bits int in Little-endian as two blocks of 32 bits.
	readOut64 := func(v *uint64, msg string, args ...interface{}) bool {
		var a, b uint32
		if !(readOutAndSetErr(&a, msg, args) && readOutAndSetErr(&b, msg, args)) {
			return false
		}
		*v = uint64(a) + uint64(b)<<32
		return true
	}

	var ncmd uint32
	if !readOutAndSetErr(&ncmd,
		"executor %v: failed to read output coverage", env.pid) {
		return
	}
	info = make([]CallInfo, len(p.Calls))
	for i := range info {
		info[i].Errno = -1 // not executed
	}
	dumpCov := func() string {
		buf := new(bytes.Buffer)
		for i, inf := range info {
			str := "nil"
			if inf.Signal != nil {
				str = fmt.Sprint(len(inf.Signal))
			}
			fmt.Fprintf(buf, "%v:%v|", i, str)
		}
		return buf.String()
	}
	for i := uint32(0); i < ncmd; i++ {
		var callIndex, callNum, errno, faultInjected, signalSize, coverSize, compsSize uint32
		if !readOut(&callIndex) || !readOut(&callNum) || !readOut(&errno) ||
			!readOut(&faultInjected) || !readOut(&signalSize) ||
			!readOut(&coverSize) || !readOut(&compsSize) {
			err0 = fmt.Errorf("executor %v: failed to read output coverage", env.pid)
			return
		}
		if int(callIndex) >= len(info) {
			err0 = fmt.Errorf("executor %v: failed to read output coverage: record %v, call %v, total calls %v (cov: %v)",
				env.pid, i, callIndex, len(info), dumpCov())
			return
		}
		c := p.Calls[callIndex]
		if num := c.Meta.ID; uint32(num) != callNum {
			err0 = fmt.Errorf("executor %v: failed to read output coverage:"+
				" record %v call %v: expect syscall %v, got %v, executed %v (cov: %v)",
				env.pid, i, callIndex, num, callNum, ncmd, dumpCov())
			return
		}
		if info[callIndex].Signal != nil {
			err0 = fmt.Errorf("executor %v: failed to read output coverage: double coverage for call %v (cov: %v)",
				env.pid, callIndex, dumpCov())
			return
		}
		info[callIndex].Errno = int(errno)
		info[callIndex].FaultInjected = faultInjected != 0
		if signalSize > uint32(len(out)) {
			err0 = fmt.Errorf("executor %v: failed to read output signal: record %v, call %v, signalsize=%v coversize=%v",
				env.pid, i, callIndex, signalSize, coverSize)
			return
		}
		// Read out signals.
		info[callIndex].Signal = out[:signalSize:signalSize]
		out = out[signalSize:]
		// Read out coverage.
		if coverSize > uint32(len(out)) {
			err0 = fmt.Errorf("executor %v: failed to read output coverage: record %v, call %v, signalsize=%v coversize=%v",
				env.pid, i, callIndex, signalSize, coverSize)
			return
		}
		info[callIndex].Cover = out[:coverSize:coverSize]
		out = out[coverSize:]
		// Read out comparisons.
		compMap := make(prog.CompMap)
		for j := uint32(0); j < compsSize; j++ {
			var typ uint32
			if !readOutAndSetErr(&typ,
				"executor %v: failed while reading type of comparison %v/%v",
				env.pid, callIndex, j) {
				return
			}
			if typ > compConstMask|compSizeMask {
				err0 = fmt.Errorf("executor %v: got wrong value (%v) while reading type of comparison %v/%v",
					env.pid, typ, callIndex, j)
				return
			}

			arg1ErrString := "executor %v: failed while reading op1 of comparison %v"
			arg2ErrString := "executor %v: failed while reading op2 of comparison %v"
			var op1, op2 uint64
			if (typ & compSizeMask) == compSize8 {
				if !readOut64(&op1, arg1ErrString, env.pid, j) ||
					!readOut64(&op2, arg2ErrString, env.pid, j) {
					return
				}
			} else {
				var tmp1, tmp2 uint32
				if !readOutAndSetErr(&tmp1, arg1ErrString, env.pid, j) ||
					!readOutAndSetErr(&tmp2, arg2ErrString, env.pid, j) {
					return
				}
				op1 = uint64(tmp1)
				op2 = uint64(tmp2)
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
		info[callIndex].Comps = compMap
	}
	return
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
	// prog follows on pipe or in shmem
}

type executeReply struct {
	magic uint32
	// If done is 0, then this is call completion message followed by callReply.
	// If done is 1, then program execution is finished and status is set.
	done   uint32
	status uint32
}

// TODO(dvyukov): we currently parse this manually, should cast output to this struct instead.
/*
type callReply struct {
	callIndex     uint32
	callNum       uint32
	errno         uint32
	blocked       uint32
	faultInjected uint32
	signalSize    uint32
	coverSize     uint32
	compsSize     uint32
	// signal/cover/comps follow
}
*/

func makeCommand(pid int, bin []string, config *Config, inFile *os.File, outFile *os.File) (*command, error) {
	dir, err := ioutil.TempDir("./", "syzkaller-testdir")
	if err != nil {
		return nil, fmt.Errorf("failed to create temp dir: %v", err)
	}

	c := &command{
		pid:     pid,
		config:  config,
		timeout: sanitizeTimeout(config),
		dir:     dir,
	}
	defer func() {
		if c != nil {
			c.close()
		}
	}()

	if config.Flags&(FlagSandboxSetuid|FlagSandboxNamespace) != 0 {
		if err := os.Chmod(dir, 0777); err != nil {
			return nil, fmt.Errorf("failed to chmod temp dir: %v", err)
		}
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
	cmd.Env = []string{}
	cmd.Dir = dir
	cmd.Stdin = outrp
	cmd.Stdout = inwp
	if config.Flags&FlagDebug != 0 {
		close(c.readDone)
		cmd.Stderr = os.Stdout
	} else if config.Flags&FlagUseForkServer == 0 {
		close(c.readDone)
		// TODO: read out output after execution failure.
	} else {
		cmd.Stderr = wp
		go func(c *command) {
			// Read out output in case executor constantly prints something.
			bufSize := c.config.BufferSize
			if bufSize == 0 {
				bufSize = 128 << 10
			}
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
	inwp.Close()

	if c.config.Flags&FlagUseForkServer != 0 {
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
		c.abort()
		c.wait()
	}
	osutil.UmountAll(c.dir)
	os.RemoveAll(c.dir)
	if c.inrp != nil {
		c.inrp.Close()
	}
	if c.outwp != nil {
		c.outwp.Close()
	}
}

// handshake sends handshakeReq and waits for handshakeReply (sandbox setup can take significant time).
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
	c.abort()
	output := <-c.readDone
	err = fmt.Errorf("executor %v: %v\n%s", c.pid, err, output)
	c.wait()
	if c.cmd.ProcessState != nil {
		// Magic values returned by executor.
		if osutil.ProcessExitStatus(c.cmd.ProcessState) == statusFail {
			err = ExecutorFailure(err.Error())
		}
	}
	return err
}

// abort sends the abort signal to the command and then SIGKILL if wait doesn't return within 5s.
func (c *command) abort() {
	if osutil.ProcessSignal(c.cmd.Process, c.config.AbortSignal) {
		return
	}
	go func() {
		t := time.NewTimer(5 * time.Second)
		select {
		case <-t.C:
			c.cmd.Process.Kill()
		case <-c.exited:
			t.Stop()
		}
	}()
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

func (c *command) exec(opts *ExecOpts, progData []byte) (output []byte, failed, hanged,
	restart bool, err0 error) {
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
			c.abort()
			hang <- true
		case <-done:
			t.Stop()
			hang <- false
		}
	}()
	var exitStatus int
	if c.config.Flags&FlagUseForkServer == 0 {
		restart = true
		c.cmd.Wait()
		close(done)
		<-hang
		exitStatus = osutil.ProcessExitStatus(c.cmd.ProcessState)
	} else {
		reply := &executeReply{}
		replyData := (*[unsafe.Sizeof(*reply)]byte)(unsafe.Pointer(reply))[:]
		_, readErr := io.ReadFull(c.inrp, replyData)
		close(done)
		if readErr == nil {
			if reply.magic != outMagic {
				panic(fmt.Sprintf("executor %v: got bad reply magic 0x%x", c.pid, reply.magic))
			}
			if reply.done == 0 {
				// TODO: call completion/coverage over the control pipe is not supported yet.
				panic(fmt.Sprintf("executor %v: got call reply", c.pid))
			}
			if reply.status == 0 {
				// Program was OK.
				<-hang
				return
			}
			// Executor writes magic values into the pipe before exiting,
			// so proceed with killing and joining it.
		}
		c.abort()
		output = <-c.readDone
		if err := c.wait(); <-hang {
			hanged = true
			// In all likelihood, this will be duplicated by the default
			// case below, but that's fine.
			output = append(output, []byte(err.Error())...)
			output = append(output, '\n')
		}
		exitStatus = int(reply.status)
	}
	// Handle magic values returned by executor.
	switch exitStatus {
	case statusFail:
		err0 = ExecutorFailure(fmt.Sprintf("executor %v: failed: %s", c.pid, output))
	case statusError:
		err0 = fmt.Errorf("executor %v: detected kernel bug", c.pid)
		failed = true
	case statusRetry:
		// This is a temporal error (ENOMEM) or an unfortunate
		// program that messes with testing setup (e.g. kills executor
		// loop process). Pretend that nothing happened.
		// It's better than a false crash report.
		err0 = nil
		hanged = false
		restart = true
	default:
		if c.config.Flags&FlagUseForkServer == 0 {
			return
		}
		// Failed to get a valid (or perhaps any) status from the executor.
		//
		// Once the executor is serving the status is always written to
		// the pipe, so we don't bother to check the specific exit codes from wait.
		err0 = fmt.Errorf("executor %v: invalid status %d, exit status: %s",
			c.pid, exitStatus, c.cmd.ProcessState)
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
		if config.Flags&FlagUseForkServer == 0 {
			// If there is no fork server, executor does not have internal timeout.
			timeout = executorTimeout
		}
	}
	// IPC timeout must be larger then executor timeout.
	// Otherwise IPC will kill parent executor but leave child executor alive.
	if config.Flags&FlagUseForkServer != 0 && timeout < minTimeout {
		timeout = minTimeout
	}
	return timeout
}
