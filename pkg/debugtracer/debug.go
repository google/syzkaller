// Copyright 2020 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package debugtracer

import (
	"fmt"
	"io"
	"path/filepath"
	"testing"

	"github.com/google/syzkaller/pkg/osutil"
)

type DebugTracer interface {
	Log(msg string, args ...interface{})
	SaveFile(filename string, data []byte)
}

type GenericTracer struct {
	TraceWriter io.Writer
	OutDir      string
}

type TestTracer struct {
	T *testing.T
}

type NullTracer struct {
}

func (gt *GenericTracer) Log(msg string, args ...interface{}) {
	fmt.Fprintf(gt.TraceWriter, msg+"\n", args...)
}

func (gt *GenericTracer) SaveFile(filename string, data []byte) {
	if gt.OutDir == "" {
		return
	}
	osutil.MkdirAll(gt.OutDir)
	osutil.WriteFile(filepath.Join(gt.OutDir, filename), data)
}

func (tt *TestTracer) Log(msg string, args ...interface{}) {
	tt.T.Log(msg, args)
}

func (tt *TestTracer) SaveFile(filename string, data []byte) {
	// Not implemented.
}

func (nt *NullTracer) Log(msg string, args ...interface{}) {
	// Not implemented.
}

func (nt *NullTracer) SaveFile(filename string, data []byte) {
	// Not implemented.
}
