// Copyright 2015 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package vm

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"os"
	"regexp"
	"syscall"
	"time"

	"github.com/google/syzkaller/report"
)

// Instance represents a Linux VM or a remote physical machine.
type Instance interface {
	// Copy copies a hostSrc file into vm and returns file name in vm.
	Copy(hostSrc string) (string, error)

	// Forward setups forwarding from within VM to host port port
	// and returns address to use in VM.
	Forward(port int) (string, error)

	// Run runs cmd inside of the VM (think of ssh cmd).
	// outc receives combined cmd and kernel console output.
	// errc receives either command Wait return error or vm.TimeoutErr.
	// Command is terminated after timeout. Send on the stop chan can be used to terminate it earlier.
	Run(timeout time.Duration, stop <-chan bool, command string) (outc <-chan []byte, errc <-chan error, err error)

	// Close stops and destroys the VM.
	Close()
}

type Config struct {
	Name            string
	Index           int
	Workdir         string
	Bin             string
	BinArgs         string
	Initrd          string
	Kernel          string
	Cmdline         string
	Image           string
	Sshkey          string
	Executor        string
	Device          string
	MachineType     string
	OdroidHostAddr  string
	OdroidSlaveAddr string
	OdroidConsole   string
	OdroidHubBus    int
	OdroidHubDevice int
	OdroidHubPort   int
	Cpu             int
	Mem             int
	Debug           bool
}

type ctorFunc func(cfg *Config) (Instance, error)

var ctors = make(map[string]ctorFunc)

func Register(typ string, ctor ctorFunc) {
	ctors[typ] = ctor
}

// Close to interrupt all pending operations.
var Shutdown = make(chan struct{})

// Create creates and boots a new VM instance.
func Create(typ string, cfg *Config) (Instance, error) {
	ctor := ctors[typ]
	if ctor == nil {
		return nil, fmt.Errorf("unknown instance type '%v'", typ)
	}
	return ctor(cfg)
}

func LongPipe() (io.ReadCloser, io.WriteCloser, error) {
	r, w, err := os.Pipe()
	if err != nil {
		return nil, nil, fmt.Errorf("failed to create pipe: %v", err)
	}
	for sz := 128 << 10; sz <= 2<<20; sz *= 2 {
		syscall.Syscall(syscall.SYS_FCNTL, w.Fd(), syscall.F_SETPIPE_SZ, uintptr(sz))
	}
	return r, w, err
}

var TimeoutErr = errors.New("timeout")

func MonitorExecution(outc <-chan []byte, errc <-chan error, local, needOutput bool, ignores []*regexp.Regexp) (desc string, text, output []byte, crashed, timedout bool) {
	waitForOutput := func() {
		dur := time.Second
		if needOutput {
			dur = 10 * time.Second
		}
		timer := time.NewTimer(dur).C
		for {
			select {
			case out, ok := <-outc:
				if !ok {
					return
				}
				output = append(output, out...)
			case <-timer:
				return
			}
		}
	}

	matchPos := 0
	const (
		beforeContext = 256 << 10
		afterContext  = 128 << 10
	)
	extractError := func(defaultError string) (string, []byte, []byte, bool, bool) {
		// Give it some time to finish writing the error message.
		waitForOutput()
		if bytes.Contains(output, []byte("SYZ-FUZZER: PREEMPTED")) {
			return "preempted", nil, nil, false, true
		}
		if !report.ContainsCrash(output[matchPos:], ignores) {
			return defaultError, nil, output, defaultError != "", false
		}
		desc, text, start, end := report.Parse(output[matchPos:], ignores)
		start = start + matchPos - beforeContext
		if start < 0 {
			start = 0
		}
		end = end + matchPos + afterContext
		if end > len(output) {
			end = len(output)
		}
		return desc, text, output[start:end], true, false
	}

	lastExecuteTime := time.Now()
	ticker := time.NewTimer(3 * time.Minute)
	tickerFired := false
	for {
		if !tickerFired && !ticker.Stop() {
			<-ticker.C
		}
		tickerFired = false
		ticker.Reset(3 * time.Minute)
		select {
		case err := <-errc:
			switch err {
			case nil:
				// The program has exited without errors,
				// but wait for kernel output in case there is some delayed oops.
				return extractError("")
			case TimeoutErr:
				return err.Error(), nil, nil, false, true
			default:
				// Note: connection lost can race with a kernel oops message.
				// In such case we want to return the kernel oops.
				return extractError("lost connection to test machine")
			}
		case out := <-outc:
			output = append(output, out...)
			if bytes.Index(output[matchPos:], []byte("executing program")) != -1 { // syz-fuzzer output
				lastExecuteTime = time.Now()
			}
			if bytes.Index(output[matchPos:], []byte("executed programs:")) != -1 { // syz-execprog output
				lastExecuteTime = time.Now()
			}
			if report.ContainsCrash(output[matchPos:], ignores) {
				return extractError("unknown error")
			}
			if len(output) > 2*beforeContext {
				copy(output, output[len(output)-beforeContext:])
				output = output[:beforeContext]
			}
			matchPos = len(output) - 128
			if matchPos < 0 {
				matchPos = 0
			}
			// In some cases kernel constantly prints something to console,
			// but fuzzer is not actually executing programs.
			if !local && time.Since(lastExecuteTime) > 3*time.Minute {
				return "test machine is not executing programs", nil, output, true, false
			}
		case <-ticker.C:
			tickerFired = true
			if !local {
				return "no output from test machine", nil, output, true, false
			}
		case <-Shutdown:
			return "", nil, nil, false, false
		}
	}
}

// Sleep for d.
// If shutdown is in progress, return false prematurely.
func SleepInterruptible(d time.Duration) bool {
	select {
	case <-time.After(d):
		return true
	case <-Shutdown:
		return false
	}
}
