// Copyright 2015 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package vm

import (
	"errors"
	"fmt"
	"io"
	"os"
	"syscall"
	"time"
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
	Run(timeout time.Duration, command string) (outc <-chan []byte, errc <-chan error, err error)

	// Close stops and destroys the VM.
	Close()
}

type Config struct {
	Name     string
	Index    int
	Workdir  string
	Bin      string
	Initrd   string
	Kernel   string
	Cmdline  string
	Image    string
	Sshkey   string
	Executor string
	Device   string
	Cpu      int
	Mem      int
	Debug    bool
}

type ctorFunc func(cfg *Config) (Instance, error)

var ctors = make(map[string]ctorFunc)

func Register(typ string, ctor ctorFunc) {
	ctors[typ] = ctor
}

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
