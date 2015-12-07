// Copyright 2015 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package kvm

import (
	"encoding/json"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sync"
	"time"

	"github.com/google/syzkaller/vm"
)

const hostAddr = "192.168.33.1"
const logOutput = false

func init() {
	vm.Register("kvm", ctor)
}

type kvm struct {
	params
	workdir   string
	crashdir  string
	callsFlag string
	id        int
	mgrPort   int
}

type params struct {
	Lkvm     string
	Kernel   string
	Cmdline  string
	Fuzzer   string
	Executor string
	Cpu      int
	Mem      int
}

func ctor(cfg *vm.Config, index int) (vm.Instance, error) {
	p := new(params)
	if err := json.Unmarshal(cfg.Params, p); err != nil {
		return nil, fmt.Errorf("failed to unmarshal kvm params: %v", err)
	}
	if _, err := os.Stat(p.Kernel); err != nil {
		return nil, fmt.Errorf("kernel '%v' does not exist: %v", p.Kernel, err)
	}
	if _, err := os.Stat(p.Fuzzer); err != nil {
		return nil, fmt.Errorf("fuzzer binary '%v' does not exist: %v", p.Fuzzer, err)
	}
	if _, err := os.Stat(p.Executor); err != nil {
		return nil, fmt.Errorf("executor binary '%v' does not exist: %v", p.Executor, err)
	}
	if p.Lkvm == "" {
		p.Lkvm = "lkvm"
	}
	if p.Cpu <= 0 || p.Cpu > 1024 {
		return nil, fmt.Errorf("bad kvm cpu: %v, want [1-1024]", p.Cpu)
	}
	if p.Mem < 128 || p.Mem > 1048576 {
		return nil, fmt.Errorf("bad kvm mem: %v, want [128-1048576]", p.Mem)
	}

	crashdir := filepath.Join(cfg.Workdir, "crashes")
	os.MkdirAll(crashdir, 0770)

	workdir := filepath.Join(cfg.Workdir, "kvm")
	os.MkdirAll(workdir, 0770)

	vm := &kvm{
		params:   *p,
		workdir:  workdir,
		crashdir: crashdir,
		id:       index,
		mgrPort:  cfg.ManagerPort,
	}

	if cfg.EnabledSyscalls != "" {
		vm.callsFlag = "-calls=" + cfg.EnabledSyscalls
	}

	return vm, nil
}

func (vm *kvm) Run() {
	log.Printf("kvm/%v: started\n", vm.id)
	sandbox := fmt.Sprintf("syz-%v", vm.id)
	sandboxPath := filepath.Join(os.Getenv("HOME"), ".lkvm", sandbox)
	scriptPath := filepath.Join(vm.workdir, sandbox+".sh")
	script := fmt.Sprintf("#! /bin/bash\n/syzkaller_fuzzer -name kvm/%v -executor /syzkaller_executor -manager %v:%v %v\n",
		vm.id, hostAddr, vm.mgrPort, vm.callsFlag)
	if err := ioutil.WriteFile(scriptPath, []byte(script), 0770); err != nil {
		log.Fatalf("failed to create run script: %v", err)
	}
	for run := 0; ; run++ {
		logname := filepath.Join(vm.workdir, fmt.Sprintf("log%v-%v-%v", vm.id, run, time.Now().Unix()))
		var logf *os.File
		if logOutput {
			var err error
			logf, err = os.Create(logname)
			if err != nil {
				log.Printf("failed to create log file: %v", err)
				time.Sleep(10 * time.Second)
				continue
			}
		}
		rpipe, wpipe, err := os.Pipe()
		if err != nil {
			log.Printf("failed to create pipe: %v", err)
			if logf != nil {
				logf.Close()
			}
			time.Sleep(10 * time.Second)
			continue
		}
		os.RemoveAll(sandboxPath)
		os.Remove(sandboxPath + ".sock")
		out, err := exec.Command(vm.Lkvm, "setup", sandbox).CombinedOutput()
		if err != nil {
			log.Printf("failed to lkvm setup: %v\n%s", err, out)
			if logf != nil {
				logf.Close()
			}
			rpipe.Close()
			wpipe.Close()
			time.Sleep(10 * time.Second)
			continue
		}
		if err := copyFile(vm.Fuzzer, filepath.Join(sandboxPath, "/syzkaller_fuzzer")); err != nil {
			log.Printf("failed to copy file into sandbox: %v", err)
			os.RemoveAll(sandboxPath)
			if logf != nil {
				logf.Close()
			}
			rpipe.Close()
			wpipe.Close()
			time.Sleep(10 * time.Second)
			continue
		}
		if err := copyFile(vm.Executor, filepath.Join(sandboxPath, "/syzkaller_executor")); err != nil {
			log.Printf("failed to copy file into sandbox: %v", err)
			os.RemoveAll(sandboxPath)
			if logf != nil {
				logf.Close()
			}
			rpipe.Close()
			wpipe.Close()
			time.Sleep(10 * time.Second)
			continue
		}
		os.Chmod(filepath.Join(sandboxPath, "/syzkaller_fuzzer"), 0770)
		os.Chmod(filepath.Join(sandboxPath, "/syzkaller_executor"), 0770)
		inst := &Instance{
			id:          vm.id,
			crashdir:    vm.crashdir,
			params:      vm.params,
			name:        fmt.Sprintf("kvm/%v-%v", vm.id, run),
			sandbox:     sandbox,
			sandboxPath: sandboxPath,
			scriptPath:  scriptPath,
			callsFlag:   vm.callsFlag,
			log:         logf,
			rpipe:       rpipe,
			wpipe:       wpipe,
			cmds:        make(map[*Command]bool),
		}
		inst.Run()
		inst.Shutdown()
		time.Sleep(10 * time.Second)
	}
}

type Instance struct {
	params
	sync.Mutex
	id          int
	crashdir    string
	name        string
	sandbox     string
	sandboxPath string
	scriptPath  string
	callsFlag   string
	log         *os.File
	rpipe       *os.File
	wpipe       *os.File
	cmds        map[*Command]bool
	kvm         *Command
}

type Command struct {
	sync.Mutex
	cmd    *exec.Cmd
	done   chan struct{}
	failed bool
	out    []byte
	outpos int
}

func (inst *Instance) Run() {
	var outputMu sync.Mutex
	var output []byte
	go func() {
		var buf [64 << 10]byte
		for {
			n, err := inst.rpipe.Read(buf[:])
			if n != 0 {
				outputMu.Lock()
				output = append(output, buf[:n]...)
				outputMu.Unlock()
				if inst.log != nil {
					inst.log.Write(buf[:n])
				}
			}
			if err != nil {
				break
			}
		}
	}()

	// Start the instance.
	inst.kvm = inst.CreateCommand(
		"taskset", "1",
		inst.Lkvm, "sandbox",
		"--disk", inst.sandbox,
		fmt.Sprintf("--mem=%v", inst.Mem),
		fmt.Sprintf("--cpus=%v", inst.Cpu),
		"--kernel", inst.Kernel,
		"--network", "mode=user",
		"--sandbox", inst.scriptPath,
	)

	start := time.Now()
	deadline := start.Add(time.Hour)
	lastOutput := time.Now()
	lastOutputLen := 0
	matchPos := 0
	crashRe := regexp.MustCompile("\\[ cut here \\]|Kernel panic| BUG: | WARNING: | INFO: |unable to handle kernel NULL pointer dereference|general protection fault|UBSAN:")
	const contextSize = 64 << 10
	for range time.NewTicker(5 * time.Second).C {
		outputMu.Lock()
		if lastOutputLen != len(output) {
			lastOutput = time.Now()
		}
		if loc := crashRe.FindAllIndex(output[matchPos:], -1); len(loc) != 0 {
			// Give it some time to finish writing the error message.
			outputMu.Unlock()
			time.Sleep(5 * time.Second)
			outputMu.Lock()
			loc = crashRe.FindAllIndex(output[matchPos:], -1)
			for i := range loc {
				loc[i][0] += matchPos
				loc[i][1] += matchPos
			}
			start := loc[0][0] - contextSize
			if start < 0 {
				start = 0
			}
			end := loc[len(loc)-1][1] + contextSize
			if end > len(output) {
				end = len(output)
			}
			inst.SaveCrasher(output[start:end])
		}
		if len(output) > 2*contextSize {
			copy(output, output[len(output)-contextSize:])
			output = output[:contextSize]
		}
		matchPos = len(output) - 128
		if matchPos < 0 {
			matchPos = 0
		}
		lastOutputLen = len(output)
		outputMu.Unlock()

		if time.Since(lastOutput) > 3*time.Minute {
			time.Sleep(time.Second)
			outputMu.Lock()
			output = append(output, "\nno output from fuzzer, restarting\n"...)
			inst.SaveCrasher(output)
			outputMu.Unlock()
			inst.Logf("no output from fuzzer, restarting")
			inst.kvm.cmd.Process.Kill()
			inst.kvm.cmd.Process.Kill()
			return
		}
		if inst.kvm.Exited() {
			time.Sleep(time.Second)
			outputMu.Lock()
			output = append(output, "\nfuzzer binary stopped or lost connection\n"...)
			inst.SaveCrasher(output)
			outputMu.Unlock()
			inst.Logf("fuzzer binary stopped or lost connection")
			return
		}
		if time.Now().After(deadline) {
			inst.Logf("running for long enough, restarting")
			inst.kvm.cmd.Process.Kill()
			inst.kvm.cmd.Process.Kill()
			return
		}
	}
}

func (inst *Instance) SaveCrasher(output []byte) {
	ioutil.WriteFile(filepath.Join(inst.crashdir, fmt.Sprintf("crash%v-%v", inst.id, time.Now().UnixNano())), output, 0660)
}

func (inst *Instance) Shutdown() {
	defer func() {
		os.RemoveAll(inst.sandboxPath)
		inst.rpipe.Close()
		inst.wpipe.Close()
		if inst.log != nil {
			inst.log.Close()
		}
	}()
	if inst.kvm.cmd == nil {
		// CreateCommand should have been failed very early.
		return
	}
	for try := 0; try < 10; try++ {
		inst.kvm.cmd.Process.Kill()
		time.Sleep(time.Second)
		inst.Lock()
		n := len(inst.cmds)
		inst.Unlock()
		if n == 0 {
			return
		}
	}
	inst.Logf("hanged processes after kill")
	inst.Lock()
	for cmd := range inst.cmds {
		cmd.cmd.Process.Kill()
		cmd.cmd.Process.Kill()
	}
	inst.Unlock()
	time.Sleep(3 * time.Second)
}

func (inst *Instance) CreateCommand(args ...string) *Command {
	if inst.log != nil {
		fmt.Fprintf(inst.log, "executing command: %v\n", args)
	}
	cmd := &Command{}
	cmd.done = make(chan struct{})
	cmd.cmd = exec.Command(args[0], args[1:]...)
	cmd.cmd.Stdout = inst.wpipe
	cmd.cmd.Stderr = inst.wpipe
	if err := cmd.cmd.Start(); err != nil {
		inst.Logf("failed to start command '%v': %v\n", args, err)
		cmd.failed = true
		close(cmd.done)
		return cmd
	}
	inst.Lock()
	inst.cmds[cmd] = true
	inst.Unlock()
	go func() {
		err := cmd.cmd.Wait()
		inst.Lock()
		delete(inst.cmds, cmd)
		inst.Unlock()
		if inst.log != nil {
			fmt.Fprintf(inst.log, "command '%v' exited: %v\n", args, err)
		}
		cmd.failed = err != nil
		close(cmd.done)
	}()
	return cmd
}

func (inst *Instance) Logf(str string, args ...interface{}) {
	fmt.Fprintf(inst.wpipe, str+"\n", args...)
	log.Printf("%v: "+str, append([]interface{}{inst.name}, args...)...)
}

func (cmd *Command) Wait(max time.Duration) bool {
	select {
	case <-cmd.done:
		return !cmd.failed
	case <-time.After(max):
		return false
	}
}

func (cmd *Command) Exited() bool {
	select {
	case <-cmd.done:
		return true
	default:
		return false
	}
}

func copyFile(oldfn, newfn string) error {
	oldf, err := os.Open(oldfn)
	if err != nil {
		return err
	}
	defer oldf.Close()
	newf, err := os.Create(newfn)
	if err != nil {
		return err
	}
	defer newf.Close()
	_, err = io.Copy(newf, oldf)
	if err != nil {
		return err
	}
	return nil
}
