// Copyright 2015 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package ipc

import (
	"bufio"
	"bytes"
	"io/ioutil"
	"math/rand"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"

	"github.com/google/syzkaller/prog"
)

func buildExecutor(t *testing.T) string {
	return buildProgram(t, "../executor/executor.cc")
}

func buildSource(t *testing.T, src []byte) string {
	srcf, err := ioutil.TempFile("", "syzkaller")
	if err != nil {
		t.Fatalf("failed to create temp file: %v", err)
	}
	srcf.Close()
	os.Remove(srcf.Name())
	name := srcf.Name() + ".c"
	if err := ioutil.WriteFile(name, src, 0600); err != nil {
		t.Fatalf("failed to write temp file: %v", err)
	}
	defer os.Remove(name)
	return buildProgram(t, name)
}

func buildProgram(t *testing.T, src string) string {
	bin, err := ioutil.TempFile("", "syzkaller")
	if err != nil {
		t.Fatalf("failed to create temp file: %v", err)
	}
	bin.Close()
	out, err := exec.Command("gcc", src, "-o", bin.Name(), "-lpthread", "-static", "-O1", "-g").CombinedOutput()
	if err != nil {
		os.Remove(bin.Name())
		data, _ := ioutil.ReadFile(src)
		t.Fatalf("failed to build program:\n%s\n%s", data, out)
	}
	return bin.Name()
}

func initTest(t *testing.T) (rand.Source, int) {
	iters := 100
	if testing.Short() {
		iters = 10
	}
	seed := int64(time.Now().UnixNano())
	rs := rand.NewSource(seed)
	t.Logf("seed=%v", seed)
	return rs, iters
}

func TestEmptyProg(t *testing.T) {
	bin := buildExecutor(t)
	defer os.Remove(bin)

	env, err := MakeEnv(bin, time.Second, 0)
	if err != nil {
		t.Fatalf("failed to create env: %v", err)
	}
	defer env.Close()

	p := new(prog.Prog)
	data := p.SerializeForExec()
	copy(env.In, data)

	output, strace, failed, hanged, err := env.Exec()
	if err != nil {
		t.Fatalf("failed to run executor: %v", err)
	}
	if len(output) != 0 {
		t.Fatalf("output on empty program")
	}
	if len(strace) != 0 {
		t.Fatalf("strace output when not stracing")
	}
	if failed || hanged {
		t.Fatalf("empty program failed")
	}
}

func TestStrace(t *testing.T) {
	bin := buildExecutor(t)
	defer os.Remove(bin)

	env, err := MakeEnv(bin, time.Second, FlagStrace)
	if err != nil {
		t.Fatalf("failed to create env: %v", err)
	}
	defer env.Close()

	p := new(prog.Prog)
	data := p.SerializeForExec()
	copy(env.In, data)

	_, strace, failed, hanged, err := env.Exec()
	if err != nil {
		t.Fatalf("failed to run executor: %v", err)
	}
	if len(strace) == 0 {
		t.Fatalf("no strace output")
	}
	if failed || hanged {
		t.Fatalf("empty program failed")
	}
}

func TestExecute(t *testing.T) {
	bin := buildExecutor(t)
	defer os.Remove(bin)

	rs, iters := initTest(t)
	flags := []uint64{0, FlagStrace, FlagThreaded, FlagStrace | FlagThreaded}
	for _, flag := range flags {
		env, err := MakeEnv(bin, time.Second, flag)
		if err != nil {
			t.Fatalf("failed to create env: %v", err)
		}
		defer env.Close()

		for i := 0; i < iters/len(flags); i++ {
			p := prog.Generate(rs, 10, nil)
			data := p.SerializeForExec()
			copy(env.In, data)

			_, _, _, _, err := env.Exec()
			if err != nil {
				t.Fatalf("failed to run executor: %v", err)
			}
		}
	}
}

func TestCompare(t *testing.T) {
	t.Skip("flaky")

	bin := buildExecutor(t)
	defer os.Remove(bin)

	// Sequence of syscalls that statically linked libc produces on startup.
	rawTracePrefix := []string{"execve", "uname", "brk", "brk", "arch_prctl",
		"readlink", "brk", "brk", "access"}
	executorTracePrefix := []string{"execve", "uname", "brk", "brk", "arch_prctl",
		"set_tid_address", "set_robust_list", "futex", "rt_sigaction", "rt_sigaction",
		"rt_sigprocmask", "getrlimit", "readlink", "brk", "brk", "access", "mmap", "mmap"}
	// These calls produce non-deterministic results, ignore them.
	nondet := []string{"getrusage", "msgget", "msgrcv", "msgsnd", "shmget", "semat", "io_setup", "getpgrp",
		"getpid", "getpgid", "getppid", "setsid", "ppoll", "keyctl", "ioprio_get",
		"move_pages", "kcmp"}

	env1, err := MakeEnv(bin, time.Second, FlagStrace)
	if err != nil {
		t.Fatalf("failed to create env: %v", err)
	}
	defer env1.Close()

	rs, iters := initTest(t)
	for i := 0; i < iters; i++ {
		p := prog.Generate(rs, 10, nil)
		data := p.SerializeForExec()
		copy(env1.In, data)

		_, strace1, _, _, err := env1.Exec()
		if err != nil {
			t.Fatalf("failed to run executor: %v", err)
		}

		src := p.WriteCSource()
		cprog := buildSource(t, src)
		defer os.Remove(cprog)

		env2, err := MakeEnv(cprog, time.Second, FlagStrace)
		if err != nil {
			t.Fatalf("failed to create env: %v", err)
		}
		defer env2.Close() // yes, that's defer in a loop

		_, strace2, _, _, err := env2.Exec()
		if err != nil {
			t.Fatalf("failed to run c binary: %v", err)
		}
		stripPrefix := func(data []byte, prefix []string) string {
			prefix0 := prefix
			buf := new(bytes.Buffer)
			s := bufio.NewScanner(bytes.NewReader(data))
			for s.Scan() {
				if strings.HasPrefix(s.Text(), "--- SIG") {
					// Signal parameters can contain pid and pc.
					continue
				}
				if len(prefix) == 0 {
					skip := false
					for _, c := range nondet {
						if strings.HasPrefix(s.Text(), c) {
							skip = true
							break
						}
					}
					if skip {
						continue
					}
					buf.WriteString(s.Text())
					buf.Write([]byte{'\n'})
					continue
				}
				if !strings.HasPrefix(s.Text(), prefix[0]) {
					t.Fatalf("strace output does not start with expected prefix\ngot:\n%s\nexpect prefix: %+v\ncurrent call: %v", data, prefix0, prefix[0])
				}
				prefix = prefix[1:]
			}
			if err := s.Err(); err != nil {
				t.Fatalf("failed to scan strace output: %v", err)
			}
			return buf.String()
		}
		s1 := stripPrefix(strace1, executorTracePrefix)
		s2 := stripPrefix(strace2, rawTracePrefix)
		if s1 == "" || s1 != s2 {
			t.Logf("program:\n%s\n", p.Serialize())
			t.Fatalf("strace output differs:\n%s\n\n\n%s\n", s1, s2)
		}
	}
}
