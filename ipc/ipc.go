// Copyright 2015 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package ipc

import (
	"fmt"
	"io/ioutil"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/google/syzkaller/prog"
)

type Env struct {
	In  []byte
	Out []byte

	inFile  *os.File
	outFile *os.File
	bin     []string
	timeout time.Duration
	flags   uint64
}

const (
	FlagDebug    = uint64(1) << iota // debug output from executor
	FlagCover                        // collect coverage
	FlagThreaded                     // use multiple threads to mitigate blocked syscalls
	FlagStrace                       // run executor under strace
)

func MakeEnv(bin string, timeout time.Duration, flags uint64) (*Env, error) {
	inf, inmem, err := createMapping(1 << 20)
	if err != nil {
		return nil, err
	}
	outf, outmem, err := createMapping(16 << 20)
	if err != nil {
		closeMapping(inf, inmem)
		return nil, err
	}
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
	return env, nil
}

func (env *Env) Close() error {
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

func (env *Env) Exec(p *prog.Prog) (output, strace []byte, failed, hanged bool, err0 error) {
	if p != nil {
		progData := p.SerializeForExec()
		if len(progData) > len(env.In) {
			panic("program is too long")
		}
		copy(env.In, progData)
	}
	// Zero out the first word (ncmd), so that we don't have garbage there
	// if executor crashes before writing non-garbage there.
	for i := 0; i < 4; i++ {
		env.Out[i] = 0
	}
	dir, err := ioutil.TempDir("./", "syzkaller-testdir")
	if err != nil {
		err0 = fmt.Errorf("failed to create temp dir: %v", err)
		return
	}
	defer os.RemoveAll(dir)
	rp, wp, err := os.Pipe()
	if err != nil {
		err0 = fmt.Errorf("failed to create pipe: %v", err)
		return
	}
	defer rp.Close()
	defer wp.Close()
	cmd := exec.Command(env.bin[0], env.bin[1:]...)
	traceFile := ""
	if env.flags&FlagStrace != 0 {
		f, err := ioutil.TempFile("./", "syzkaller-strace")
		if err != nil {
			err0 = fmt.Errorf("failed to create temp file: %v", err)
			return
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
	cmd.ExtraFiles = append(cmd.ExtraFiles, env.inFile, env.outFile)
	cmd.Env = []string{}
	cmd.Dir = dir
	cmd.Stdout = wp
	cmd.Stderr = wp
	if syscall.Getuid() == 0 {
		// Running under root, more isolation is possible.
		cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true, Cloneflags: syscall.CLONE_NEWNS}
	} else {
		cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	}
	if err := cmd.Start(); err != nil {
		err0 = fmt.Errorf("failed to start executor binary: %v", err)
		return
	}
	wp.Close()
	done := make(chan bool)
	hang := make(chan bool)
	go func() {
		t := time.NewTimer(env.timeout)
		select {
		case <-t.C:
			// We started the process in its own process group and now kill the whole group.
			// This solves a potential problem with strace:
			// if we kill just strace, executor still runs and ReadAll below hangs.
			syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL)
			syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL)
			syscall.Kill(cmd.Process.Pid, syscall.SIGKILL)
			syscall.Kill(cmd.Process.Pid, syscall.SIGKILL)
			hang <- true
		case <-done:
			t.Stop()
			hang <- false
		}
	}()
	output, err = ioutil.ReadAll(rp)
	readErr := err
	close(done)
	if err = cmd.Wait(); <-hang && err != nil {
		hanged = true
		failed = true
	}
	if err != nil {
		output = append(output, []byte(err.Error())...)
		output = append(output, '\n')
	}
	if cmd.ProcessState != nil {
		sys := cmd.ProcessState.Sys()
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
	if readErr != nil {
		err0 = fmt.Errorf("failed to read executor output: %v", err)
		return
	}
	if traceFile != "" {
		strace, err = ioutil.ReadFile(traceFile)
		if err != nil {
			err0 = fmt.Errorf("failed to read strace output: %v", err)
			return
		}
	}
	return
}

func createMapping(size int) (f *os.File, mem []byte, err error) {
	f, err = ioutil.TempFile("./", "syzkaller-shm")
	if err != nil {
		return
	}
	if err = f.Truncate(int64(size)); err != nil {
		f.Close()
		os.Remove(f.Name())
		return
	}
	f.Close()
	f, err = os.OpenFile(f.Name(), os.O_RDWR, 0)
	if err != nil {
		os.Remove(f.Name())
		return
	}
	mem, err = syscall.Mmap(int(f.Fd()), 0, size, syscall.PROT_READ|syscall.PROT_WRITE, syscall.MAP_SHARED)
	if err != nil {
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
