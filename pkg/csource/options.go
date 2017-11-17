// Copyright 2017 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package csource

import (
	"bytes"
	"errors"
	"fmt"
)

// Options control various aspects of source generation.
// Dashboard also provides serialized Options along with syzkaller reproducers.
type Options struct {
	Threaded bool
	Collide  bool
	Repeat   bool
	Procs    int
	Sandbox  string

	Fault     bool // inject fault into FaultCall/FaultNth
	FaultCall int
	FaultNth  int

	// These options allow for a more fine-tuned control over the generated C code.
	EnableTun  bool
	UseTmpDir  bool
	HandleSegv bool
	WaitRepeat bool
	Debug      bool

	// Generate code for use with repro package to prints log messages,
	// which allows to distinguish between a hang and an absent crash.
	Repro bool
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
	if opts.Sandbox == "namespace" && !opts.UseTmpDir {
		// This is borken and never worked.
		// This tries to create syz-tmp dir in cwd,
		// which will fail if procs>1 and on second run of the program.
		return errors.New("Sandbox=namespace without UseTmpDir")
	}
	return nil
}

func (opts Options) Serialize() []byte {
	return []byte(fmt.Sprintf("%+v", opts))
}

func DeserializeOptions(data []byte) (Options, error) {
	data = bytes.Replace(data, []byte("Sandbox: "), []byte("Sandbox:empty "), -1)
	var opts Options
	n, err := fmt.Sscanf(string(data),
		"{Threaded:%t Collide:%t Repeat:%t Procs:%d Sandbox:%s"+
			" Fault:%t FaultCall:%d FaultNth:%d EnableTun:%t UseTmpDir:%t"+
			" HandleSegv:%t WaitRepeat:%t Debug:%t Repro:%t}",
		&opts.Threaded, &opts.Collide, &opts.Repeat, &opts.Procs, &opts.Sandbox,
		&opts.Fault, &opts.FaultCall, &opts.FaultNth, &opts.EnableTun, &opts.UseTmpDir,
		&opts.HandleSegv, &opts.WaitRepeat, &opts.Debug, &opts.Repro)
	if err != nil {
		return opts, fmt.Errorf("failed to parse repro options: %v", err)
	}
	if want := 14; n != want {
		return opts, fmt.Errorf("failed to parse repro options: got %v fields, want %v", n, want)
	}
	if opts.Sandbox == "empty" {
		opts.Sandbox = ""
	}
	return opts, nil
}
