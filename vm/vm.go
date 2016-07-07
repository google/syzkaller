// Copyright 2015 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package vm

import (
	"bytes"
	"errors"
	"fmt"
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
	Initrd	   string
	Kernel     string
	Cmdline    string
	Image      string
	Sshkey     string
	Executor   string
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

// FindCrash searches kernel console output for oops messages.
// Desc contains a more-or-less representative description of the first oops,
// start and end denote region of output with oops message(s).
func FindCrash(output []byte) (desc string, start int, end int, found bool) {
	for pos := 0; pos < len(output); {
		next := bytes.IndexByte(output[pos:], '\n')
		if next != -1 {
			next += pos
		} else {
			next = len(output)
		}
		for _, oops := range oopses {
			match := bytes.Index(output[pos:next], oops)
			if match == -1 {
				continue
			}
			if !found {
				found = true
				start = pos
				desc = string(output[pos+match : next])
				if desc[len(desc)-1] == '\r' {
					desc = desc[:len(desc)-1]
				}
			}
			end = next
		}
		pos = next + 1
	}
	return
}

var (
	oopses = [][]byte{
		[]byte("Kernel panic"),
		[]byte("BUG:"),
		[]byte("kernel BUG"),
		[]byte("WARNING:"),
		[]byte("INFO:"),
		[]byte("unable to handle"),
		[]byte("Unable to handle kernel"),
		[]byte("general protection fault"),
		[]byte("UBSAN:"),
		[]byte("unreferenced object"),
	}

	TimeoutErr = errors.New("timeout")
)
