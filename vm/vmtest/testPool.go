// Copyright 2024 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package vmtest

import (
	"time"

	"github.com/google/syzkaller/pkg/report"
	"github.com/google/syzkaller/vm/vmimpl"
)

// TestPool is a mock struct for vmPool unit tests.
type TestPool struct {
}

func (pool *TestPool) Count() int {
	return 1
}

func (pool *TestPool) Create(workdir string, index int) (vmimpl.Instance, error) {
	return &TestInstance{
		Outc: make(chan []byte, 10),
		Errc: make(chan error, 1),
	}, nil
}

func (pool *TestPool) Close() error {
	return nil
}

type TestInstance struct {
	Outc           chan []byte
	Errc           chan error
	DiagnoseBug    bool
	DiagnoseNoWait bool
}

func (inst *TestInstance) Copy(hostSrc string) (string, error) {
	return "", nil
}

func (inst *TestInstance) Forward(port int) (string, error) {
	return "", nil
}

func (inst *TestInstance) Run(timeout time.Duration, stop <-chan bool, command string) (
	Outc <-chan []byte, Errc <-chan error, err error) {
	return inst.Outc, inst.Errc, nil
}

func (inst *TestInstance) Diagnose(rep *report.Report) ([]byte, bool) {
	var diag []byte
	if inst.DiagnoseBug {
		diag = []byte("BUG: DIAGNOSE\n")
	} else {
		diag = []byte("DIAGNOSE\n")
	}

	if inst.DiagnoseNoWait {
		return diag, false
	}

	inst.Outc <- diag
	return nil, true
}

func (inst *TestInstance) Close() error {
	return nil
}
