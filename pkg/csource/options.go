// Copyright 2017 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package csource

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/google/syzkaller/syz-manager/mgrconfig"
)

// Options control various aspects of source generation.
// Dashboard also provides serialized Options along with syzkaller reproducers.
type Options struct {
	Threaded    bool   `json:"threaded,omitempty"`
	Collide     bool   `json:"collide,omitempty"`
	Repeat      bool   `json:"repeat,omitempty"`
	RepeatTimes int    `json:"repeat_times,omitempty"` // if non-0, repeat that many times
	Procs       int    `json:"procs"`
	Sandbox     string `json:"sandbox"`

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

	// Generate code for use with repro package to prints log messages,
	// which allows to detect hangs.
	Repro bool `json:"repro,omitempty"`
	Trace bool `json:"trace,omitempty"`
}

// Check checks if the opts combination is valid or not.
// For example, Collide without Threaded is not valid.
// Invalid combinations must not be passed to Write.
func (opts Options) Check(OS string) error {
	switch OS {
	case fuchsia, akaros:
		if opts.Fault {
			return fmt.Errorf("Fault is not supported on %v", OS)
		}
		if opts.EnableTun {
			return fmt.Errorf("EnableTun is not supported on %v", OS)
		}
		if opts.EnableCgroups {
			return fmt.Errorf("EnableCgroups is not supported on %v", OS)
		}
		if opts.EnableNetdev {
			return fmt.Errorf("EnableNetdev is not supported on %v", OS)
		}
		if opts.ResetNet {
			return fmt.Errorf("ResetNet is not supported on %v", OS)
		}
		if opts.Sandbox != "" && opts.Sandbox != sandboxNone {
			return fmt.Errorf("Sandbox=%v is not supported on %v", opts.Sandbox, OS)
		}
	}
	if OS != linux && (opts.Sandbox == sandboxNamespace || opts.Sandbox == sandboxSetuid) {
		return fmt.Errorf("Sandbox=%v is not supported on %v", opts.Sandbox, OS)
	}
	if OS != linux && opts.Fault {
		return fmt.Errorf("Fault is not supported on %v", OS)
	}
	if !opts.Threaded && opts.Collide {
		// Collide requires threaded.
		return errors.New("Collide without Threaded")
	}
	if !opts.Repeat && opts.Procs > 1 {
		// This does not affect generated code.
		return errors.New("Procs>1 without Repeat")
	}
	if opts.Sandbox == sandboxNamespace && !opts.UseTmpDir {
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
	if opts.EnableNetdev && opts.Sandbox == "" {
		return errors.New("EnableNetdev without sandbox")
	}
	if opts.ResetNet && opts.Sandbox == "" {
		return errors.New("ResetNet without sandbox")
	}
	if opts.ResetNet && !opts.Repeat {
		return errors.New("ResetNet without Repeat")
	}
	if !opts.Repeat && opts.RepeatTimes != 0 && opts.RepeatTimes != 1 {
		return errors.New("RepeatTimes without Repeat")
	}
	return nil
}

func DefaultOpts(cfg *mgrconfig.Config) Options {
	opts := Options{
		Threaded:      true,
		Collide:       true,
		Repeat:        true,
		Procs:         cfg.Procs,
		Sandbox:       cfg.Sandbox,
		EnableTun:     true,
		EnableCgroups: true,
		EnableNetdev:  true,
		ResetNet:      true,
		UseTmpDir:     true,
		HandleSegv:    true,
		Repro:         true,
	}
	if cfg.TargetOS != linux {
		opts.EnableTun = false
		opts.EnableCgroups = false
		opts.EnableNetdev = false
		opts.ResetNet = false
	}
	if err := opts.Check(cfg.TargetOS); err != nil {
		panic(fmt.Sprintf("DefaultOpts created bad opts: %v", err))
	}
	return opts
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
	waitRepeat, debug := false, false
	n, err := fmt.Sscanf(string(data),
		"{Threaded:%t Collide:%t Repeat:%t Procs:%d Sandbox:%s"+
			" Fault:%t FaultCall:%d FaultNth:%d EnableTun:%t UseTmpDir:%t"+
			" HandleSegv:%t WaitRepeat:%t Debug:%t Repro:%t}",
		&opts.Threaded, &opts.Collide, &opts.Repeat, &opts.Procs, &opts.Sandbox,
		&opts.Fault, &opts.FaultCall, &opts.FaultNth, &opts.EnableTun, &opts.UseTmpDir,
		&opts.HandleSegv, &waitRepeat, &debug, &opts.Repro)
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
		&opts.EnableCgroups, &opts.HandleSegv, &waitRepeat, &debug, &opts.Repro)
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
