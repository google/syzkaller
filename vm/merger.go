// Copyright 2016 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package vm

import (
	"bytes"
	"io"
	"sync"
)

type OutputMerger struct {
	Output chan []byte
	tee    io.Writer
	wg     sync.WaitGroup
}

func NewOutputMerger(tee io.Writer) *OutputMerger {
	return &OutputMerger{
		Output: make(chan []byte, 1000),
		tee:    tee,
	}
}

func (merger *OutputMerger) Wait() {
	merger.wg.Wait()
	close(merger.Output)
}

func (merger *OutputMerger) Add(r io.ReadCloser) {
	merger.wg.Add(1)
	go func() {
		var pending []byte
		var buf [4 << 10]byte
		for {
			n, err := r.Read(buf[:])
			if n != 0 {
				pending = append(pending, buf[:n]...)
				if pos := bytes.LastIndexByte(pending, '\n'); pos != -1 {
					out := pending[:pos+1]
					if merger.tee != nil {
						merger.tee.Write(out)
					}
					merger.Output <- append([]byte{}, out...)
					r := copy(pending[:], pending[pos+1:])
					pending = pending[:r]
				}
			}
			if err != nil {
				if len(pending) != 0 {
					pending = append(pending, '\n')
					if merger.tee != nil {
						merger.tee.Write(pending)
					}
					merger.Output <- pending
				}
				r.Close()
				merger.wg.Done()
				return
			}
		}
	}()
}
