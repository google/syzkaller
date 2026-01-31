// Copyright 2026 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package vmimpl

import (
	"bytes"
	"io"
	"sync"
)

// FanOut allows to share a single reader between multiple readers.
type FanOut struct {
	r    io.ReadCloser
	mu   sync.Mutex
	tees map[*FanOutReader]bool
	done chan struct{}
	err  error
}

func NewFanOut(r io.ReadCloser) *FanOut {
	c := &FanOut{
		r:    r,
		tees: make(map[*FanOutReader]bool),
		done: make(chan struct{}),
	}
	go c.loop()
	return c
}

func (c *FanOut) Close() error {
	return c.r.Close()
}

// NewReader creates a new reader that will receive all future data from the source.
func (c *FanOut) NewReader() *FanOutReader {
	tee := &FanOutReader{
		c:    c,
		data: make(chan []byte, 1024),
	}
	c.mu.Lock()
	if c.err != nil {
		tee.err = c.err
		close(tee.data)
	} else {
		c.tees[tee] = true
	}
	c.mu.Unlock()
	return tee
}

func (c *FanOut) loop() {
	var buf [4096]byte
	for {
		n, err := c.r.Read(buf[:])
		if n > 0 {
			c.mu.Lock()
			for tee := range c.tees {
				// If the reader is too slow, just drop the data to avoid blocking the source.
				select {
				case tee.data <- append([]byte{}, buf[:n]...):
				default:
					// Buffer full. Drop old data to make space for new data.
					select {
					case <-tee.data:
					default:
					}
					select {
					case tee.data <- append([]byte{}, buf[:n]...):
					default:
					}
				}
			}
			c.mu.Unlock()
		}
		if err != nil {
			c.mu.Lock()
			c.err = err
			for tee := range c.tees {
				tee.err = err
				close(tee.data)
			}
			close(c.done)
			c.mu.Unlock()
			return
		}
	}
}

func (c *FanOut) Wait() <-chan struct{} {
	return c.done
}

func (c *FanOut) Error() error {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.err
}

type FanOutReader struct {
	c    *FanOut
	data chan []byte
	buf  bytes.Buffer
	err  error
}

func (t *FanOutReader) Read(p []byte) (int, error) {
	if t.buf.Len() > 0 {
		return t.buf.Read(p)
	}
	data, ok := <-t.data
	if !ok {
		// Data is only closed after err is set, so we don't need mutex here.
		return 0, t.err
	}
	t.buf.Write(data)
	return t.buf.Read(p)
}

func (t *FanOutReader) ReadAll() ([]byte, error) {
	for {
		select {
		case data, ok := <-t.data:
			if !ok {
				res := make([]byte, t.buf.Len())
				copy(res, t.buf.Bytes())
				t.buf.Reset()
				return res, t.err
			}
			t.buf.Write(data)
		default:
			res := make([]byte, t.buf.Len())
			copy(res, t.buf.Bytes())
			t.buf.Reset()
			return res, nil
		}
	}
}

func (t *FanOutReader) Close() error {
	t.c.mu.Lock()
	if t.c.tees != nil {
		delete(t.c.tees, t)
	}
	t.c.mu.Unlock()
	return nil
}
