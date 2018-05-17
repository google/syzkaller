// Copyright 2017 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package csource

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
)

// Options control various aspects of source generation.
// Dashboard also provides serialized Options along with syzkaller reproducers.
type Options struct {
	Threaded bool   `json:"threaded,omitempty"`
	Collide  bool   `json:"collide,omitempty"`
	Repeat   bool   `json:"repeat,omitempty"`
	Procs    int    `json:"procs"`
	Sandbox  string `json:"sandbox"`

	Fault     bool `json:"fault,omitempty"` // inject fault into FaultCall/FaultNth
	FaultCall int  `json:"fault_call,omitempty"`
	FaultNth  int  `json:"fault_nth,omitempty"`

	// These options allow for a more fine-tuned control over the generated C code.
	EnableTun     bool `json:"tun,omitempty"`
	UseTmpDir     bool `json:"tmpdir,omitempty"`
	EnableCgroups bool `json:"cgroups,omitempty"`
	EnableNetdev  bool `json:"netdev,omitempty"`
	ResetNet      bool `json:"resetnet,omitempty"`
	HandleSegv    bool `json:"segv,omitempty"`
	WaitRepeat    bool `json:"waitrepeat,omitempty"`
	Debug         bool `json:"debug,omitempty"`

	// Generate code for use with repro package to prints log messages,
	// which allows to distinguish between a hang and an absent crash.
	Repro bool `json:"repro,omitempty"`
}

// Check checks if the opts combination is valid or not.
// For example, Collide without Threaded is not valid.
// Invalid combinations must not be passed to Write.
func (opts Options) Check() error {
	if !opts.Threaded && opts.Collide {
		// Collide requires threaded.
		return errors.New("Collide without Threaded")
	}
	if !opts.Repeat && opts.Procs > 1 {
		// This does not affect generated code.
		return errors.New("Procs>1 without Repeat")
	}
	if !opts.Repeat && opts.WaitRepeat {
		return errors.New("WaitRepeat without Repeat")
	}
	if opts.Sandbox == "namespace" && !opts.UseTmpDir {
		// This is borken and never worked.
		// This tries to create syz-tmp dir in cwd,
		// which will fail if procs>1 and on second run of the program.
		return errors.New("Sandbox=namespace without UseTmpDir")
	}
	if opts.EnableTun && opts.Sandbox == "" {
		return errors.New("EnableTun without sandbox")
	}
	if opts.EnableCgroups && opts.Sandbox == "" {
		return errors.New("EnableCgroups without sandbox")
	}
	if opts.EnableCgroups && !opts.UseTmpDir {
		return errors.New("EnableCgroups without UseTmpDir")
	}
	if opts.EnableCgroups && !opts.WaitRepeat {
		return errors.New("EnableCgroups without WaitRepeat")
	}
	if opts.EnableNetdev && opts.Sandbox == "" {
		return errors.New("EnableNetdev without sandbox")
	}
	if opts.ResetNet && opts.Sandbox == "" {
		return errors.New("ResetNet without sandbox")
	}
	if opts.ResetNet && !opts.WaitRepeat {
		return errors.New("ResetNet without WaitRepeat")
	}
	return nil
}

func (opts Options) Serialize() []byte {
	data, err := json.Marshal(opts)
	if err != nil {
		panic(err)
	}
	return data
}

func DeserializeOptions(data []byte) (Options, error) {
	var opts Options
	if err := json.Unmarshal(data, &opts); err == nil {
		return opts, nil
	}
	// Support for legacy formats.
	data = bytes.Replace(data, []byte("Sandbox: "), []byte("Sandbox:empty "), -1)
	n, err := fmt.Sscanf(string(data),
		"{Threaded:%t Collide:%t Repeat:%t Procs:%d Sandbox:%s"+
			" Fault:%t FaultCall:%d FaultNth:%d EnableTun:%t UseTmpDir:%t"+
			" HandleSegv:%t WaitRepeat:%t Debug:%t Repro:%t}",
		&opts.Threaded, &opts.Collide, &opts.Repeat, &opts.Procs, &opts.Sandbox,
		&opts.Fault, &opts.FaultCall, &opts.FaultNth, &opts.EnableTun, &opts.UseTmpDir,
		&opts.HandleSegv, &opts.WaitRepeat, &opts.Debug, &opts.Repro)
	if err == nil {
		if want := 14; n != want {
			return opts, fmt.Errorf("failed to parse repro options: got %v fields, want %v", n, want)
		}
		if opts.Sandbox == "empty" {
			opts.Sandbox = ""
		}
		return opts, nil
	}
	n, err = fmt.Sscanf(string(data),
		"{Threaded:%t Collide:%t Repeat:%t Procs:%d Sandbox:%s"+
			" Fault:%t FaultCall:%d FaultNth:%d EnableTun:%t UseTmpDir:%t"+
			" EnableCgroups:%t HandleSegv:%t WaitRepeat:%t Debug:%t Repro:%t}",
		&opts.Threaded, &opts.Collide, &opts.Repeat, &opts.Procs, &opts.Sandbox,
		&opts.Fault, &opts.FaultCall, &opts.FaultNth, &opts.EnableTun, &opts.UseTmpDir,
		&opts.EnableCgroups, &opts.HandleSegv, &opts.WaitRepeat, &opts.Debug, &opts.Repro)
	if err == nil {
		if want := 15; n != want {
			return opts, fmt.Errorf("failed to parse repro options: got %v fields, want %v", n, want)
		}
		if opts.Sandbox == "empty" {
			opts.Sandbox = ""
		}
		return opts, nil
	}
	return opts, err
}
