// Copyright 2015 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package vm

import (
	"errors"
	"fmt"
	"regexp"
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
	Name       string
	Index      int
	Workdir    string
	Bin        string
	Kernel     string
	Cmdline    string
	Image      string
	Sshkey     string
	ConsoleDev string
	Cpu        int
	Mem        int
	Debug      bool
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

var (
	CrashRe    = regexp.MustCompile("Kernel panic[^\r\n]*|BUG:[^\r\n]*|kernel BUG[^\r\n]*|WARNING:[^\r\n]*|INFO:[^\r\n]*|unable to handle|general protection fault|UBSAN:[^\r\n]*|unreferenced object[^\r\n]*")
	TimeoutErr = errors.New("timeout")
)
