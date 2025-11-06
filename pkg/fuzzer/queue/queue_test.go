// Copyright 2024 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package queue

import (
	"testing"

	"github.com/google/syzkaller/pkg/flatrpc"
	"github.com/google/syzkaller/prog"
	"github.com/stretchr/testify/assert"
)

func TestPlainQueue(t *testing.T) {
	pq := Plain()

	req1, req2, req3 := &Request{}, &Request{}, &Request{}

	pq.Submit(req1)
	pq.Submit(req2)
	assert.Equal(t, req1, pq.Next())
	assert.Equal(t, req2, pq.Next())
	pq.Submit(req3)
	assert.Equal(t, req3, pq.Next())
	assert.Nil(t, pq.Next())
}

func TestPrioQueue(t *testing.T) {
	req1, req2, req3, req4 :=
		&Request{}, &Request{}, &Request{}, &Request{}
	pq := DynamicOrder()

	pq1 := pq.Append()
	pq2 := pq.Append()
	pq3 := pq.Append()

	pq2.Submit(req2)
	pq3.Submit(req3)
	assert.Equal(t, req2, pq.Next())

	pq1.Submit(req1)
	assert.Equal(t, req1, pq.Next())

	pq2.Submit(req4)
	assert.Equal(t, req4, pq.Next())
	assert.Equal(t, req3, pq.Next())
}

func TestGlobFiles(t *testing.T) {
	r := &Result{}
	assert.Equal(t, r.GlobFiles(), []string(nil))
	r.Output = []byte{'a', 'b', 0, 'c', 0}
	assert.Equal(t, r.GlobFiles(), []string{"ab", "c"})
}

func TestTee(t *testing.T) {
	base, dup := Plain(), Plain()

	tee := Tee(base, dup)
	req := &Request{
		Prog:        &prog.Prog{},
		Type:        flatrpc.RequestTypeProgram,
		ExecOpts:    flatrpc.ExecOpts{SandboxArg: 10},
		BinaryFile:  "file",
		GlobPattern: "pattern",
		// These must be ignored.
		ReturnOutput: true,
		Important:    true,
	}
	base.Submit(req)

	origReq := tee.Next()
	assert.Equal(t, req, origReq)
	copy := dup.Next()
	assert.Equal(t, req.Type, copy.Type)
	assert.Equal(t, req.ExecOpts, copy.ExecOpts)
	assert.Equal(t, req.BinaryFile, copy.BinaryFile)
	assert.Equal(t, req.GlobPattern, copy.GlobPattern)
	assert.Empty(t, copy.ReturnOutput)
	assert.Empty(t, copy.Important)
}
