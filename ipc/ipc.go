// Copyright 2015 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package ipc

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"io/ioutil"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/google/syzkaller/fileutil"
	"github.com/google/syzkaller/prog"
)

type Env struct {
	In  []byte
	Out []byte

	cmd     *command
	inFile  *os.File
	outFile *os.File
	bin     []string
	timeout time.Duration
	flags   uint64

	StatExecs    uint64
	StatRestarts uint64
}

const (
	FlagDebug      = uint64(1) << iota // debug output from executor
	FlagCover                          // collect coverage
	FlagThreaded                       // use multiple threads to mitigate blocked syscalls
	FlagCollide                        // collide syscalls to provoke data races
	FlagDedupCover                     // deduplicate coverage in executor
	FlagDropPrivs                      // impersonate nobody user
	FlagNoSetpgid                      // don't use setpgid
	FlagStrace                         // run executor under strace
)

func MakeEnv(bin string, timeout time.Duration, flags uint64) (*Env, error) {
	// IPC timeout must be larger then executor timeout.
	// Otherwise IPC will kill parent executor but leave child executor alive.
	if timeout < 7*time.Second {
		timeout = 7 * time.Second
	}
	inf, inmem, err := createMapping(2 << 20)
	if err != nil {
		return nil, err
	}
	defer func() {
		if inf != nil {
			closeMapping(inf, inmem)
		}
	}()
	outf, outmem, err := createMapping(16 << 20)
	if err != nil {
		return nil, err
	}
	defer func() {
		if outf != nil {
			closeMapping(outf, outmem)
		}
	}()
	for i := 0; i < 8; i++ {
		inmem[i] = byte(flags >> (8 * uint(i)))
	}
	inmem = inmem[8:]
	env := &Env{
		In:      inmem,
		Out:     outmem,
		inFile:  inf,
		outFile: outf,
		bin:     strings.Split(bin, " "),
		timeout: timeout,
		flags:   flags,
	}
	if len(env.bin) == 0 {
		return nil, fmt.Errorf("binary is empty string")
	}
	env.bin[0], err = filepath.Abs(env.bin[0]) // we are going to chdir
	if err != nil {
		return nil, fmt.Errorf("filepath.Abs failed: %v", err)
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

// Exec starts executor binary to execute program p and returns information about the execution:
// output: process output
// strace: strace output if env is created with FlagStrace
// cov: per-call coverage, len(cov) == len(p.Calls)
// failed: true if executor has detected a kernel bug
// hanged: program hanged and was killed
// err0: failed to start process, or executor has detected a logical error
func (env *Env) Exec(p *prog.Prog) (output, strace []byte, cov [][]uint32, errnos []int, failed, hanged bool, err0 error) {
	if p != nil {
		// Copy-in serialized program.
		progData := p.SerializeForExec()
		if len(progData) > len(env.In) {
			panic("program is too long")
		}
		copy(env.In, progData)
	}
	if env.flags&FlagCover != 0 {
		// Zero out the first word (ncmd), so that we don't have garbage there
		// if executor crashes before writing non-garbage there.
		for i := 0; i < 4; i++ {
			env.Out[i] = 0
		}
	}

	atomic.AddUint64(&env.StatExecs, 1)
	if env.cmd == nil {
		atomic.AddUint64(&env.StatRestarts, 1)
		env.cmd, err0 = makeCommand(env.bin, env.timeout, env.flags, env.inFile, env.outFile)
		if err0 != nil {
			return
		}
	}
	output, strace, failed, hanged, err0 = env.cmd.exec()
	if err0 != nil {
		env.cmd.close()
		env.cmd = nil
		return
	}

	if env.flags&FlagCover == 0 || p == nil {
		return
	}
	// Read out coverage information.
	r := bytes.NewReader(env.Out)
	var ncmd uint32
	if err := binary.Read(r, binary.LittleEndian, &ncmd); err != nil {
		err0 = fmt.Errorf("failed to read output coverage: %v", err)
		return
	}
	cov = make([][]uint32, len(p.Calls))
	errnos = make([]int, len(p.Calls))
	for i := range errnos {
		errnos[i] = -1 // not executed
	}
	for i := uint32(0); i < ncmd; i++ {
		var callIndex, callNum, errno, coverSize, pc uint32
		if err := binary.Read(r, binary.LittleEndian, &callIndex); err != nil {
			err0 = fmt.Errorf("failed to read output coverage: %v", err)
			return
		}
		if err := binary.Read(r, binary.LittleEndian, &callNum); err != nil {
			err0 = fmt.Errorf("failed to read output coverage: %v", err)
			return
		}
		if err := binary.Read(r, binary.LittleEndian, &errno); err != nil {
			err0 = fmt.Errorf("failed to read output errno: %v", err)
			return
		}
		if err := binary.Read(r, binary.LittleEndian, &coverSize); err != nil {
			err0 = fmt.Errorf("failed to read output coverage: %v", err)
			return
		}
		if int(callIndex) > len(cov) {
			err0 = fmt.Errorf("failed to read output coverage: expect index %v, got %v", i, callIndex)
			return
		}
		if cov[callIndex] != nil {
			err0 = fmt.Errorf("failed to read output coverage: double coverage for call %v", callIndex)
			return
		}
		c := p.Calls[callIndex]
		if num := c.Meta.ID; uint32(num) != callNum {
			err0 = fmt.Errorf("failed to read output coverage: call %v: expect syscall %v, got %v, executed %v", callIndex, num, callNum, ncmd)
			return
		}
		cov1 := make([]uint32, coverSize)
		for j := uint32(0); j < coverSize; j++ {
			if err := binary.Read(r, binary.LittleEndian, &pc); err != nil {
				err0 = fmt.Errorf("failed to read output coverage: expect index %v, got %v", i, callIndex)
				return
			}
			cov1[j] = pc
		}
		cov[callIndex] = cov1
		errnos[callIndex] = int(errno)
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
	f, err = os.OpenFile(f.Name(), os.O_RDWR, 0)
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
	timeout time.Duration
	cmd     *exec.Cmd
	flags   uint64
	dir     string
	rp      *os.File
	inrp    *os.File
	outwp   *os.File
}

func makeCommand(bin []string, timeout time.Duration, flags uint64, inFile *os.File, outFile *os.File) (*command, error) {
	dir, err := ioutil.TempDir("./", "syzkaller-testdir")
	if err != nil {
		return nil, fmt.Errorf("failed to create temp dir: %v", err)
	}

	c := &command{timeout: timeout, flags: flags, dir: dir}
	defer func() {
		if c != nil {
			c.close()
		}
	}()

	if flags&FlagDropPrivs != 0 {
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
	c.rp = rp

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

	cmd := exec.Command(bin[0], bin[1:]...)
	/*
		traceFile := ""
		if flags&FlagStrace != 0 {
			f, err := ioutil.TempFile("./", "syzkaller-strace")
			if err != nil {
				return nil, fmt.Errorf("failed to create temp file: %v", err)
			}
			f.Close()
			defer os.Remove(f.Name())
			traceFile, _ = filepath.Abs(f.Name())
			args := []string{"-s", "8", "-o", traceFile}
			args = append(args, env.bin...)
			if env.flags&FlagThreaded != 0 {
				args = append([]string{"-f"}, args...)
			}
			cmd = exec.Command("strace", args...)
		}
	*/
	cmd.ExtraFiles = []*os.File{inFile, outFile, outrp, inwp}
	cmd.Env = []string{}
	cmd.Dir = dir
	if flags&FlagDebug == 0 {
		cmd.Stdout = wp
		cmd.Stderr = wp
	} else {
		cmd.Stdout = os.Stdout
		cmd.Stderr = os.Stdout
	}
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: flags&FlagNoSetpgid == 0}
	if syscall.Getuid() == 0 {
		// Running under root, more isolation is possible.
		cmd.SysProcAttr.Cloneflags = syscall.CLONE_NEWNS
	}
	if err := cmd.Start(); err != nil {
		return nil, fmt.Errorf("failed to start executor binary: %v", err)
	}
	c.cmd = cmd
	tmp := c
	c = nil // disable defer above
	return tmp, nil
}

func (c *command) close() {
	if c.cmd != nil {
		c.kill()
		c.cmd.Wait()
	}
	fileutil.UmountAll(c.dir)
	os.RemoveAll(c.dir)
	if c.rp != nil {
		c.rp.Close()
	}
	if c.inrp != nil {
		c.inrp.Close()
	}
	if c.outwp != nil {
		c.outwp.Close()
	}
}

func (c *command) kill() {
	// We started the process in its own process group and now kill the whole group.
	// This solves a potential problem with strace:
	// if we kill just strace, executor still runs and ReadAll below hangs.
	if c.flags&FlagNoSetpgid == 0 {
		syscall.Kill(-c.cmd.Process.Pid, syscall.SIGKILL)
	}
	syscall.Kill(c.cmd.Process.Pid, syscall.SIGKILL)
}

func (c *command) exec() (output, strace []byte, failed, hanged bool, err0 error) {
	var tmp [1]byte
	if _, err := c.outwp.Write(tmp[:]); err != nil {
		err0 = fmt.Errorf("failed to write control pipe: %v", err)
		return
	}
	done := make(chan bool)
	hang := make(chan bool)
	go func() {
		t := time.NewTimer(c.timeout)
		select {
		case <-t.C:
			c.kill()
			hang <- true
		case <-done:
			t.Stop()
			hang <- false
		}
	}()
	//!!! handle c.rp overflow
	_, readErr := c.inrp.Read(tmp[:])
	close(done)
	fileutil.UmountAll(c.dir)
	os.RemoveAll(c.dir)
	if err := os.Mkdir(c.dir, 0777); err != nil {
		<-hang
		err0 = fmt.Errorf("failed to create temp dir: %v", err)
		return
	}
	if readErr == nil {
		<-hang
		return
	}
	err0 = fmt.Errorf("executor did not answer")
	c.kill()
	var err error
	output, err = ioutil.ReadAll(c.rp)
	if err = c.cmd.Wait(); <-hang && err != nil {
		hanged = true
	}
	if err != nil {
		output = append(output, []byte(err.Error())...)
		output = append(output, '\n')
	}
	if c.cmd.ProcessState != nil {
		sys := c.cmd.ProcessState.Sys()
		if ws, ok := sys.(syscall.WaitStatus); ok {
			// Magic values returned by executor.
			if ws.ExitStatus() == 67 {
				err0 = fmt.Errorf("executor failed: %s", output)
				return
			}
			if ws.ExitStatus() == 68 {
				failed = true
			}
		}
	}
	/*
		if traceFile != "" {
			strace, err = ioutil.ReadFile(traceFile)
			if err != nil {
				err0 = fmt.Errorf("failed to read strace output: %v", err)
				return
			}
		}
	*/
	return
}
