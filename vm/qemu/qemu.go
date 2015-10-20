// Copyright 2015 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package qemu

import (
	"encoding/json"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"sync"
	"time"

	"github.com/google/syzkaller/vm"
)

const hostAddr = "10.0.2.10"
const logOutput = false

func init() {
	vm.Register("qemu", ctor)
}

type qemu struct {
	params
	workdir   string
	crashdir  string
	callsFlag string
	id        int
	mgrPort   int
}

type params struct {
	Qemu     string
	Kernel   string
	Cmdline  string
	Image    string
	Sshkey   string
	Fuzzer   string
	Executor string
	Port     int
	Cpu      int
	Mem      int
}

func ctor(cfg *vm.Config, index int) (vm.Instance, error) {
	p := new(params)
	if err := json.Unmarshal(cfg.Params, p); err != nil {
		return nil, fmt.Errorf("failed to unmarshal qemu params: %v", err)
	}
	if _, err := os.Stat(p.Image); err != nil {
		return nil, fmt.Errorf("image file '%v' does not exist: %v", p.Image, err)
	}
	if _, err := os.Stat(p.Sshkey); err != nil {
		return nil, fmt.Errorf("ssh key '%v' does not exist: %v", p.Sshkey, err)
	}
	if _, err := os.Stat(p.Fuzzer); err != nil {
		return nil, fmt.Errorf("fuzzer binary '%v' does not exist: %v", p.Fuzzer, err)
	}
	if _, err := os.Stat(p.Executor); err != nil {
		return nil, fmt.Errorf("executor binary '%v' does not exist: %v", p.Executor, err)
	}
	if p.Qemu == "" {
		p.Qemu = "qemu-system-x86_64"
	}
	if p.Port <= 1024 || p.Port >= 64<<10 {
		return nil, fmt.Errorf("bad qemu port: %v, want (1024-65536)", p.Port)
	}
	p.Port += index
	if p.Cpu <= 0 || p.Cpu > 1024 {
		return nil, fmt.Errorf("bad qemu cpu: %v, want [1-1024]", p.Cpu)
	}
	if p.Mem < 128 || p.Mem > 1048576 {
		return nil, fmt.Errorf("bad qemu mem: %v, want [128-1048576]", p.Mem)
	}

	crashdir := filepath.Join(cfg.Workdir, "crashes")
	os.MkdirAll(crashdir, 0770)

	workdir := filepath.Join(cfg.Workdir, "qemu")
	os.MkdirAll(workdir, 0770)

	q := &qemu{
		params:   *p,
		workdir:  workdir,
		crashdir: crashdir,
		id:       index,
		mgrPort:  cfg.ManagerPort,
	}

	if cfg.EnabledSyscalls != "" {
		q.callsFlag = "-calls=" + cfg.EnabledSyscalls
	}

	return q, nil
}

func (q *qemu) Run() {
	log.Printf("qemu/%v: started\n", q.id)
	imagename := filepath.Join(q.workdir, fmt.Sprintf("image%v", q.id))
	for run := 0; ; run++ {
		logname := filepath.Join(q.workdir, fmt.Sprintf("log%v-%v-%v", q.id, run, time.Now().Unix()))
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
		os.Remove(imagename)
		if err := copyFile(q.Image, imagename); err != nil {
			log.Printf("failed to copy image file: %v", err)
			if logf != nil {
				logf.Close()
			}
			rpipe.Close()
			wpipe.Close()
			time.Sleep(10 * time.Second)
			continue
		}
		inst := &Instance{
			id:        q.id,
			crashdir:  q.crashdir,
			params:    q.params,
			name:      fmt.Sprintf("qemu/%v-%v", q.id, run),
			image:     imagename,
			callsFlag: q.callsFlag,
			log:       logf,
			rpipe:     rpipe,
			wpipe:     wpipe,
			mgrPort:   q.mgrPort,
			cmds:      make(map[*Command]bool),
		}
		inst.Run()
		inst.Shutdown()
		time.Sleep(10 * time.Second)
	}
}

type Instance struct {
	params
	sync.Mutex
	id        int
	crashdir  string
	name      string
	image     string
	callsFlag string
	log       *os.File
	rpipe     *os.File
	wpipe     *os.File
	mgrPort   int
	cmds      map[*Command]bool
	qemu      *Command
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
	// TODO: ignores inst.Cpu
	args := []string{
		inst.Qemu,
		"-hda", inst.image,
		"-m", strconv.Itoa(inst.Mem),
		"-net", "nic",
		"-net", fmt.Sprintf("user,host=%v,hostfwd=tcp::%v-:22", hostAddr, inst.Port),
		"-nographic",
		"-enable-kvm",
		"-numa", "node,nodeid=0,cpus=0-1", "-numa", "node,nodeid=1,cpus=2-3",
		"-smp", "sockets=2,cores=2,threads=1",
		"-usb", "-usbdevice", "mouse", "-usbdevice", "tablet",
	}
	if inst.Kernel != "" {
		args = append(args,
			"-kernel", inst.Kernel,
			"-append", "console=ttyS0 root=/dev/sda debug earlyprintk=serial slub_debug=UZ "+inst.Cmdline,
		)
	}
	inst.qemu = inst.CreateCommand(args...)
	// Wait for ssh server.
	time.Sleep(10 * time.Second)
	start := time.Now()
	for {
		c, err := net.DialTimeout("tcp", fmt.Sprintf("localhost:%v", inst.Port), 3*time.Second)
		if err == nil {
			c.SetDeadline(time.Now().Add(3 * time.Second))
			var tmp [1]byte
			n, err := c.Read(tmp[:])
			c.Close()
			if err == nil && n > 0 {
				// ssh is up and responding.
				break
			}
			c.Close()
			time.Sleep(3 * time.Second)
		}
		if inst.qemu.Exited() {
			output = append(output, "qemu stopped\n"...)
			inst.SaveCrasher(output)
			inst.Logf("qemu stopped")
			return
		}
		if time.Since(start) > 10*time.Minute {
			outputMu.Lock()
			output = append(output, "ssh server did not start\n"...)
			inst.SaveCrasher(output)
			outputMu.Unlock()
			inst.Logf("ssh server did not start")
			return
		}
	}
	inst.Logf("started vm")

	// Copy the binaries into the instance.
	if !inst.CreateSCPCommand(inst.Fuzzer, "/syzkaller_fuzzer").Wait(1*time.Minute) ||
		!inst.CreateSCPCommand(inst.Executor, "/syzkaller_executor").Wait(1*time.Minute) {
		outputMu.Lock()
		output = append(output, "\nfailed to scp binaries into the instance\n"...)
		inst.SaveCrasher(output)
		outputMu.Unlock()
		inst.Logf("failed to scp binaries into the instance")
		return
	}

	// Disable annoying segfault dmesg messages, fuzzer is going to crash a lot.
	inst.CreateSSHCommand("echo -n 0 > /proc/sys/debug/exception-trace").Wait(10 * time.Second)

	// Run the binary.
	cmd := inst.CreateSSHCommand(fmt.Sprintf("/syzkaller_fuzzer -name %v -executor /syzkaller_executor -manager %v:%v %v",
		inst.name, hostAddr, inst.mgrPort, inst.callsFlag))

	deadline := start.Add(time.Hour)
	lastOutput := time.Now()
	lastOutputLen := 0
	matchPos := 0
	crashRe := regexp.MustCompile("\\[ cut here \\]|Kernel panic| BUG: | WARNING: | INFO: |unable to handle kernel NULL pointer dereference|general protection fault")
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
			output = output[matchPos:]
			loc = crashRe.FindAllIndex(output, -1)
			start := loc[0][0] - contextSize
			if start < 0 {
				start = 0
			}
			end := loc[len(loc)-1][1] + contextSize
			if end > len(output) {
				end = len(output)
			}
			text := append(output[start:end:end], "\n\nfound crasher:\n"...)
			text = append(text, output[loc[0][0]:loc[0][1]]...)
			inst.SaveCrasher(text)
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
			cmd.cmd.Process.Kill()
			cmd.cmd.Process.Kill()
			return
		}
		if cmd.Exited() {
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
			cmd.cmd.Process.Kill()
			cmd.cmd.Process.Kill()
			return
		}
	}
}

func (inst *Instance) SaveCrasher(output []byte) {
	ioutil.WriteFile(filepath.Join(inst.crashdir, fmt.Sprintf("crash%v-%v", inst.id, time.Now().UnixNano())), output, 0660)
}

func (inst *Instance) Shutdown() {
	defer func() {
		os.Remove(inst.image)
		inst.rpipe.Close()
		inst.wpipe.Close()
		if inst.log != nil {
			inst.log.Close()
		}
	}()
	if inst.qemu.cmd == nil {
		// CreateCommand should have been failed very early.
		return
	}
	for try := 0; try < 10; try++ {
		inst.qemu.cmd.Process.Kill()
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

func (inst *Instance) CreateSSHCommand(args ...string) *Command {
	args1 := []string{"ssh", "-i", inst.Sshkey, "-p", strconv.Itoa(inst.Port),
		"-o", "ConnectionAttempts=10", "-o", "ConnectTimeout=10",
		"-o", "BatchMode=yes", "-o", "UserKnownHostsFile=/dev/null",
		"-o", "StrictHostKeyChecking=no", "root@localhost"}
	return inst.CreateCommand(append(args1, args...)...)
}

func (inst *Instance) CreateSCPCommand(from, to string) *Command {
	return inst.CreateCommand("scp", "-i", inst.Sshkey, "-P", strconv.Itoa(inst.Port),
		"-o", "ConnectionAttempts=10", "-o", "ConnectTimeout=10",
		"-o", "BatchMode=yes", "-o", "UserKnownHostsFile=/dev/null",
		"-o", "StrictHostKeyChecking=no",
		from, "root@localhost:"+to)
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

var copySem sync.Mutex

func copyFile(oldfn, newfn string) error {
	copySem.Lock()
	defer copySem.Unlock()

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
