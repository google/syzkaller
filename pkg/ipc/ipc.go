// Copyright 2015 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package ipc

import (
	"bytes"
	"flag"
	"fmt"
	"io/ioutil"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"
	"unsafe"

	"github.com/google/syzkaller/pkg/osutil"
	"github.com/google/syzkaller/prog"
)

type Env struct {
	In  []byte
	Out []byte

	cmd     *command
	inFile  *os.File
	outFile *os.File
	bin     []string
	pid     int
	config  Config

	StatExecs    uint64
	StatRestarts uint64
}

// Configuration flags for Config.Flags.
const (
	FlagDebug            = uint64(1) << iota // debug output from executor
	FlagSignal                               // collect feedback signals (coverage)
	FlagThreaded                             // use multiple threads to mitigate blocked syscalls
	FlagCollide                              // collide syscalls to provoke data races
	FlagSandboxSetuid                        // impersonate nobody user
	FlagSandboxNamespace                     // use namespaces for sandboxing
	FlagEnableTun                            // initialize and use tun in executor
	FlagEnableFault                          // enable fault injection support
	FlagEnableComps
)

// Per-exec flags for ExecOpts.Flags:
const (
	FlagCollectCover = uint64(1) << iota // collect coverage
	FlagDedupCover                       // deduplicate coverage in executor
	FlagInjectFault                      // inject a fault in this execution (see ExecOpts)
	FlagCollectComps                     //collect KCOV comparisons
)

const (
	outputSize   = 16 << 20
	signalOffset = 15 << 20

	statusFail  = 67
	statusError = 68
	statusRetry = 69
)

var (
	flagThreaded = flag.Bool("threaded", true, "use threaded mode in executor")
	flagCollide  = flag.Bool("collide", true, "collide syscalls to provoke data races")
	flagSignal   = flag.Bool("cover", true, "collect feedback signals (coverage)")
	flagSandbox  = flag.String("sandbox", "setuid", "sandbox for fuzzing (none/setuid/namespace)")
	flagDebug    = flag.Bool("debug", false, "debug output from executor")
	// Executor protects against most hangs, so we use quite large timeout here.
	// Executor can be slow due to global locks in namespaces and other things,
	// so let's better wait than report false misleading crashes.
	flagTimeout     = flag.Duration("timeout", 1*time.Minute, "execution timeout")
	flagAbortSignal = flag.Int("abort_signal", 0, "initial signal to send to executor in error conditions; upgrades to SIGKILL if executor does not exit")
	flagBufferSize  = flag.Uint64("buffer_size", 0, "internal buffer size (in bytes) for executor output")
)

type ExecOpts struct {
	Flags     uint64
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
	// Flags are configuation flags, defined above.
	Flags uint64

	// Timeout is the execution timeout for a single program.
	Timeout time.Duration

	// AbortSignal is the signal to send to the executor in error
	// conditions.
	AbortSignal syscall.Signal

	// BufferSize is the size of the internal buffer for executor output.
	BufferSize uint64
}

func DefaultConfig() (Config, error) {
	var c Config
	if *flagThreaded {
		c.Flags |= FlagThreaded
	}
	if *flagCollide {
		c.Flags |= FlagCollide
	}
	if *flagSignal {
		c.Flags |= FlagSignal
	}
	switch *flagSandbox {
	case "none":
	case "setuid":
		c.Flags |= FlagSandboxSetuid
	case "namespace":
		c.Flags |= FlagSandboxNamespace
	default:
		return Config{}, fmt.Errorf("flag sandbox must contain one of none/setuid/namespace")
	}
	if *flagDebug {
		c.Flags |= FlagDebug
	}
	c.Timeout = *flagTimeout
	c.AbortSignal = syscall.Signal(*flagAbortSignal)
	c.BufferSize = *flagBufferSize
	return c, nil
}

func MakeEnv(bin string, pid int, config Config) (*Env, error) {
	// IPC timeout must be larger then executor timeout.
	// Otherwise IPC will kill parent executor but leave child executor alive.
	if config.Timeout < 7*time.Second {
		config.Timeout = 7 * time.Second
	}
	inf, inmem, err := createMapping(prog.ExecBufferSize)
	if err != nil {
		return nil, err
	}
	defer func() {
		if inf != nil {
			closeMapping(inf, inmem)
		}
	}()
	outf, outmem, err := createMapping(outputSize)
	if err != nil {
		return nil, err
	}
	defer func() {
		if outf != nil {
			closeMapping(outf, outmem)
		}
	}()
	serializeUint64(inmem[0:], config.Flags)
	serializeUint64(inmem[8:], uint64(pid))
	inmem = inmem[16:]
	env := &Env{
		In:      inmem,
		Out:     outmem,
		inFile:  inf,
		outFile: outf,
		bin:     strings.Split(bin, " "),
		pid:     pid,
		config:  config,
	}
	if len(env.bin) == 0 {
		return nil, fmt.Errorf("binary is empty string")
	}
	env.bin[0], err = filepath.Abs(env.bin[0]) // we are going to chdir
	if err != nil {
		return nil, fmt.Errorf("filepath.Abs failed: %v", err)
	}
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
	err1 := closeMapping(env.inFile, env.In)
	err2 := closeMapping(env.outFile, env.Out)
	switch {
	case err1 != nil:
		return err1
	case err2 != nil:
		return err2
	default:
		return nil
	}
}

type CallInfo struct {
	Signal []uint32 // feedback signal, filled if FlagSignal is set
	Cover  []uint32 // per-call coverage, filled if FlagSignal is set and cover == true,
	//if dedup == false, then cov effectively contains a trace, otherwise duplicates are removed
	Comps         prog.CompMap // per-call comparison operands
	Errno         int          // call errno (0 if the call was successful)
	FaultInjected bool
}

func GetCompMaps(info []CallInfo) []prog.CompMap {
	compMaps := make([]prog.CompMap, len(info))
	for i, inf := range info {
		compMaps[i] = inf.Comps
	}
	return compMaps
}

// Exec starts executor binary to execute program p and returns information about the execution:
// output: process output
// info: per-call info
// failed: true if executor has detected a kernel bug
// hanged: program hanged and was killed
// err0: failed to start process, or executor has detected a logical error
func (env *Env) Exec(opts *ExecOpts, p *prog.Prog) (output []byte, info []CallInfo, failed, hanged bool, err0 error) {
	if p != nil {
		// Copy-in serialized program.
		if err := p.SerializeForExec(env.In, env.pid); err != nil {
			err0 = fmt.Errorf("executor %v: failed to serialize: %v", env.pid, err)
			return
		}
	}
	if env.config.Flags&FlagSignal != 0 {
		// Zero out the first two words (ncmd and nsig), so that we don't have garbage there
		// if executor crashes before writing non-garbage there.
		for i := 0; i < 4; i++ {
			env.Out[i] = 0
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
	output, failed, hanged, restart, err0 = env.cmd.exec(opts)
	if err0 != nil || restart {
		env.cmd.close()
		env.cmd = nil
		return
	}

	if p == nil || env.config.Flags&FlagSignal == 0 &&
		env.config.Flags&FlagCollectComps == 0 {
		return
	}
	info, err0 = env.readOutCoverage(p, opts)
	return
}

func (env *Env) readOutCoverage(p *prog.Prog, opts *ExecOpts) (info []CallInfo, err0 error) {
	out := ((*[1 << 28]uint32)(unsafe.Pointer(&env.Out[0])))[:len(env.Out)/int(unsafe.Sizeof(uint32(0)))]
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
	readOut64 := func(v *uintptr, msg string, args ...interface{}) bool {
		var a, b uint32
		if !(readOutAndSetErr(&a, msg, args) && readOutAndSetErr(&b, msg, args)) {
			return false
		}
		*v = uintptr(a) + uintptr(b)<<32
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
		if !readOut(&callIndex) || !readOut(&callNum) || !readOut(&errno) || !readOut(&faultInjected) || !readOut(&signalSize) || !readOut(&coverSize) || !readOut(&compsSize) {
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
			err0 = fmt.Errorf("executor %v: failed to read output coverage: record %v call %v: expect syscall %v, got %v, executed %v (cov: %v)",
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
			var op1, op2 uintptr
			if !readOutAndSetErr(&typ,
				"executor %v: failed while reading type of comparison %v", env.pid, j) {
				return
			}
			if typ > 3 {
				err0 = fmt.Errorf("executor %v: got wrong value (%v) while reading type of comparison %v",
					env.pid, typ, j)
				return
			}

			isSize8 := typ & (1 << 0)
			isConst := typ & (1 << 1)
			arg1ErrString := "executor %v: failed while reading op1 of comparison %v"
			arg2ErrString := "executor %v: failed while reading op2 of comparison %v"
			if isSize8 == 0 {
				var tmp1, tmp2 uint32
				if !readOutAndSetErr(&tmp1, arg1ErrString, env.pid, j) ||
					!readOutAndSetErr(&tmp2, arg2ErrString, env.pid, j) {
					return
				}
				op1 = uintptr(tmp1)
				op2 = uintptr(tmp2)
			} else {
				if !readOut64(&op1, arg1ErrString, env.pid, j) ||
					!readOut64(&op2, arg2ErrString, env.pid, j) {
					return
				}
			}
			if op1 == op2 {
				// It's useless to store such comparisons.
				continue
			}
			if _, ok := prog.SpecialIntsSet[op1]; !ok {
				// We don't want to add op1 because it's in the set of
				// "interesting" values, which the fuzzer will try anyways.
				compMap.AddComp(op2, op1)
			}
			if isConst != 0 {
				// If one of the operands was const, then this operand is always
				// placed first in the instrumented callbacks. Such an operand
				// could not be an argument of our syscalls (because otherwise
				// it wouldn't be const), thus we simply ignore it.
				continue
			}
			if _, ok := prog.SpecialIntsSet[op2]; !ok {
				compMap.AddComp(op1, op2)
			}
		}
		info[callIndex].Comps = compMap
	}
	return
}

func createMapping(size int) (f *os.File, mem []byte, err error) {
	f, err = ioutil.TempFile("./", "syzkaller-shm")
	if err != nil {
		err = fmt.Errorf("failed to create temp file: %v", err)
		return
	}
	if err = f.Truncate(int64(size)); err != nil {
		err = fmt.Errorf("failed to truncate shm file: %v", err)
		f.Close()
		os.Remove(f.Name())
		return
	}
	f.Close()
	fname := f.Name()
	f, err = os.OpenFile(f.Name(), os.O_RDWR, osutil.DefaultFilePerm)
	if err != nil {
		err = fmt.Errorf("failed to open shm file: %v", err)
		os.Remove(fname)
		return
	}
	mem, err = syscall.Mmap(int(f.Fd()), 0, size, syscall.PROT_READ|syscall.PROT_WRITE, syscall.MAP_SHARED)
	if err != nil {
		err = fmt.Errorf("failed to mmap shm file: %v", err)
		f.Close()
		os.Remove(f.Name())
		return
	}
	return
}

func closeMapping(f *os.File, mem []byte) error {
	err1 := syscall.Munmap(mem)
	err2 := f.Close()
	err3 := os.Remove(f.Name())
	switch {
	case err1 != nil:
		return err1
	case err2 != nil:
		return err2
	case err3 != nil:
		return err3
	default:
		return nil
	}
}

type command struct {
	pid      int
	config   Config
	cmd      *exec.Cmd
	dir      string
	readDone chan []byte
	exited   chan struct{}
	inrp     *os.File
	outwp    *os.File
}

func makeCommand(pid int, bin []string, config Config, inFile *os.File, outFile *os.File) (*command, error) {
	dir, err := ioutil.TempDir("./", "syzkaller-testdir")
	if err != nil {
		return nil, fmt.Errorf("failed to create temp dir: %v", err)
	}

	c := &command{
		pid:    pid,
		config: config,
		dir:    dir,
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

	// Input command pipe.
	inrp, inwp, err := os.Pipe()
	if err != nil {
		return nil, fmt.Errorf("failed to create pipe: %v", err)
	}
	defer inwp.Close()
	c.inrp = inrp

	// Output command pipe.
	outrp, outwp, err := os.Pipe()
	if err != nil {
		return nil, fmt.Errorf("failed to create pipe: %v", err)
	}
	defer outrp.Close()
	c.outwp = outwp

	c.readDone = make(chan []byte, 1)
	c.exited = make(chan struct{})

	cmd := exec.Command(bin[0], bin[1:]...)
	cmd.ExtraFiles = []*os.File{inFile, outFile, outrp, inwp}
	cmd.Env = []string{}
	cmd.Dir = dir
	if config.Flags&FlagDebug == 0 {
		cmd.Stdout = wp
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
	} else {
		close(c.readDone)
		cmd.Stdout = os.Stdout
		cmd.Stderr = os.Stdout
	}
	if err := cmd.Start(); err != nil {
		return nil, fmt.Errorf("failed to start executor binary: %v", err)
	}
	c.cmd = cmd
	wp.Close()
	inwp.Close()
	if err := c.waitServing(); err != nil {
		return nil, err
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

// Wait for executor to start serving (sandbox setup can take significant time).
func (c *command) waitServing() error {
	read := make(chan error, 1)
	go func() {
		var buf [1]byte
		_, err := c.inrp.Read(buf[:])
		read <- err
	}()
	timeout := time.NewTimer(time.Minute)
	select {
	case err := <-read:
		timeout.Stop()
		if err != nil {
			c.abort()
			output := <-c.readDone
			err = fmt.Errorf("executor is not serving: %v\n%s", err, output)
			c.wait()
			if c.cmd.ProcessState != nil {
				sys := c.cmd.ProcessState.Sys()
				if ws, ok := sys.(syscall.WaitStatus); ok {
					// Magic values returned by executor.
					if ws.ExitStatus() == statusFail {
						err = ExecutorFailure(fmt.Sprintf("executor is not serving:\n%s", output))
					}
				}
			}
		}
		return err
	case <-timeout.C:
		return fmt.Errorf("executor is not serving")
	}
}

// abort sends the abort signal to the command and then SIGKILL if wait doesn't
// return within 5s.
func (c *command) abort() {
	sig := c.config.AbortSignal
	if sig <= 0 || sig >= 32 {
		sig = syscall.SIGKILL
	}
	syscall.Kill(c.cmd.Process.Pid, sig)
	if sig != syscall.SIGKILL {
		go func() {
			t := time.NewTimer(5 * time.Second)
			select {
			case <-t.C:
				syscall.Kill(c.cmd.Process.Pid, syscall.SIGKILL)
			case <-c.exited:
				t.Stop()
			}
		}()
	}
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

func (c *command) exec(opts *ExecOpts) (output []byte, failed, hanged, restart bool, err0 error) {
	if opts.Flags&FlagInjectFault != 0 {
		enableFaultOnce.Do(enableFaultInjection)
	}
	var inCmd [24]byte
	serializeUint64(inCmd[0:], opts.Flags)
	serializeUint64(inCmd[8:], uint64(opts.FaultCall))
	serializeUint64(inCmd[16:], uint64(opts.FaultNth))
	if _, err := c.outwp.Write(inCmd[:]); err != nil {
		output = <-c.readDone
		err0 = fmt.Errorf("failed to write control pipe: %v", err)
		return
	}
	done := make(chan bool)
	hang := make(chan bool)
	go func() {
		t := time.NewTimer(c.config.Timeout)
		select {
		case <-t.C:
			c.abort()
			hang <- true
		case <-done:
			t.Stop()
			hang <- false
		}
	}()
	var reply [1]byte
	readN, readErr := c.inrp.Read(reply[:])
	close(done)
	status := 0
	if readErr == nil {
		if readN != len(reply) {
			panic(fmt.Sprintf("executor %v: read only %v bytes", c.pid, readN))
		}
		status = int(reply[0])
		if status == 0 {
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
	// Handle magic values returned by executor.
	switch status {
	case statusFail:
		err0 = ExecutorFailure(fmt.Sprintf("executor failed: %s", output))
	case statusError:
		err0 = fmt.Errorf("executor detected kernel bug")
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
		// Failed to get a valid (or perhaps any) status from the
		// executor.
		//
		// Once the executor is serving the status is always written to
		// the pipe, so we don't bother to check the specific exit
		// codes from wait.
		err0 = fmt.Errorf("invalid (or no) executor status received: %d, executor exit: %s", status, c.cmd.ProcessState)
	}
	return
}

func serializeUint64(buf []byte, v uint64) {
	for i := 0; i < 8; i++ {
		buf[i] = byte(v >> (8 * uint(i)))
	}
}

var enableFaultOnce sync.Once

func enableFaultInjection() {
	if err := osutil.WriteFile("/sys/kernel/debug/failslab/ignore-gfp-wait", []byte("N")); err != nil {
		panic(fmt.Sprintf("failed to write /sys/kernel/debug/failslab/ignore-gfp-wait: %v", err))
	}
	if err := osutil.WriteFile("/sys/kernel/debug/fail_futex/ignore-private", []byte("N")); err != nil {
		panic(fmt.Sprintf("failed to write /sys/kernel/debug/fail_futex/ignore-private: %v", err))
	}
}
