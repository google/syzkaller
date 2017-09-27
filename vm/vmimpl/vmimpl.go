// Copyright 2017 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

// Package vmimpl provides an abstract test machine (VM, physical machine, etc)
// interface for the rest of the system. For convenience test machines are subsequently
// collectively called VMs.
// The package also provides various utility functions for VM implementations.
package vmimpl

import (
	"errors"
	"fmt"
	"time"
)

// Pool represents a set of test machines (VMs, physical devices, etc) of particular type.
type Pool interface {
	// Count returns total number of VMs in the pool.
	Count() int

	// Create creates and boots a new VM instance.
	Create(workdir string, index int) (Instance, error)
}

// Instance represents a single VM.
type Instance interface {
	// Copy copies a hostSrc file into VM and returns file name in VM.
	Copy(hostSrc string) (string, error)

	// Forward setups forwarding from within VM to host port port
	// and returns address to use in VM.
	Forward(port int) (string, error)

	// Run runs cmd inside of the VM (think of ssh cmd).
	// outc receives combined cmd and kernel console output.
	// errc receives either command Wait return error or vmimpl.TimeoutErr.
	// Command is terminated after timeout. Send on the stop chan can be used to terminate it earlier.
	Run(timeout time.Duration, stop <-chan bool, command string) (outc <-chan []byte, errc <-chan error, err error)

	// Close stops and destroys the VM.
	Close()
}

// Env contains global constant parameters for a pool of VMs.
type Env struct {
	// Unique name
	// Can be used for VM name collision resolution if several pools share global name space.
	Name    string
	OS      string // target OS
	Arch    string // target arch
	Workdir string
	Image   string
	SshKey  string
	SshUser string
	Debug   bool
	Config  []byte // json-serialized VM-type-specific config
}

// Create creates a VM type that can be used to create individual VMs.
func Create(typ string, env *Env) (Pool, error) {
	ctor := ctors[typ]
	if ctor == nil {
		return nil, fmt.Errorf("unknown instance type '%v'", typ)
	}
	return ctor(env)
}

// Register registers a new VM type within the package.
func Register(typ string, ctor ctorFunc) {
	ctors[typ] = ctor
}

var (
	// Close to interrupt all pending operations in all VMs.
	Shutdown   = make(chan struct{})
	TimeoutErr = errors.New("timeout")

	ctors = make(map[string]ctorFunc)
)

type ctorFunc func(env *Env) (Pool, error)
