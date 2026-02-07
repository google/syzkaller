// Copyright 2016 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package vmimpl

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"sync"

	"golang.org/x/sync/errgroup"
)

type OutputType int

const (
	OutputConsole OutputType = iota
	OutputStdout
	OutputStderr
)

type Chunk struct {
	Data []byte
	Type OutputType
}

type decoderState struct {
	done chan struct{} // Closed when the decoder exits.
	err  error
}

type OutputMerger struct {
	Output     chan Chunk
	decoderErr map[string]*decoderState
	teeMu      sync.Mutex
	tee        io.Writer
	wg         sync.WaitGroup
}

type MergerError struct {
	Name string
	R    io.ReadCloser
	Err  error
}

func (err MergerError) Error() string {
	return fmt.Sprintf("failed to read from %v: %v", err.Name, err.Err)
}

func NewOutputMerger(tee io.Writer) *OutputMerger {
	return &OutputMerger{
		Output:     make(chan Chunk, 1000),
		decoderErr: map[string]*decoderState{},
		tee:        tee,
	}
}

func (merger *OutputMerger) Wait() {
	merger.wg.Wait()
	close(merger.Output)
}

// Errors returns a channel that will receive errors from the curretly active decoderErr.
func (merger *OutputMerger) Errors(ctx context.Context) <-chan error {
	eg, egCtx := errgroup.WithContext(ctx)
	for _, decoder := range merger.decoderErr {
		eg.Go(func() error {
			select {
			case <-egCtx.Done():
				return nil
			case <-decoder.done:
				return decoder.err
			}
		})
	}
	ret := make(chan error, 1)
	go func() {
		err := eg.Wait()
		if err != nil {
			ret <- err
		}
		close(ret)
	}()
	return ret
}

func (merger *OutputMerger) Add(name string, typ OutputType, r io.ReadCloser) {
	merger.AddDecoder(name, typ, r, nil)
}

func (merger *OutputMerger) AddDecoder(name string, typ OutputType, r io.ReadCloser,
	decoder func(data []byte) (start, size int, decoded []byte)) {
	state := &decoderState{
		done: make(chan struct{}),
	}
	merger.decoderErr[name] = state
	merger.wg.Add(1)
	go func() {
		defer merger.wg.Done()
		defer close(state.done)
		err := merger.runDecoder(typ, r, decoder)
		state.err = MergerError{name, r, err}
	}()
}
func (merger *OutputMerger) runDecoder(typ OutputType, r io.ReadCloser,
	decoder func(data []byte) (start, size int, decoded []byte)) error {
	var pending []byte
	var proto []byte
	var buf [4 << 10]byte
	for {
		n, err := r.Read(buf[:])
		if n != 0 {
			if decoder != nil {
				proto = append(proto, buf[:n]...)
				start, size, decoded := decoder(proto)
				proto = proto[start+size:]
				if len(decoded) != 0 {
					merger.Output <- Chunk{decoded, typ} // note: this can block
				}
			}
			// Remove all carriage returns.
			buf := buf[:n]
			if bytes.IndexByte(buf, '\r') != -1 {
				buf = bytes.ReplaceAll(buf, []byte("\r"), nil)
			}
			pending = append(pending, buf...)
			if pos := bytes.LastIndexByte(pending, '\n'); pos != -1 {
				out := pending[:pos+1]
				if merger.tee != nil {
					merger.teeMu.Lock()
					merger.tee.Write(out)
					merger.teeMu.Unlock()
				}
				select {
				case merger.Output <- Chunk{append([]byte{}, out...), typ}:
					r := copy(pending, pending[pos+1:])
					pending = pending[:r]
				default:
				}
			}
		}
		if err != nil {
			if len(pending) != 0 {
				pending = append(pending, '\n')
				if merger.tee != nil {
					merger.teeMu.Lock()
					merger.tee.Write(pending)
					merger.teeMu.Unlock()
				}
				select {
				case merger.Output <- Chunk{pending, typ}:
				default:
				}
			}
			r.Close()
			return err
		}
	}
}
