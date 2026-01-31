// Copyright 2026 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package vmimpl

import (
	"fmt"
	"io"
	"testing"
	"time"

	"github.com/google/syzkaller/pkg/osutil"
	"github.com/stretchr/testify/assert"
)

func TestFanOutMultiple(t *testing.T) {
	r, w, err := osutil.LongPipe()
	assert.NoError(t, err)
	defer w.Close()
	c := NewFanOut(r)
	defer c.Close()

	t1 := c.NewReader()
	defer t1.Close()
	t2 := c.NewReader()
	defer t2.Close()

	w.Write([]byte("bar"))

	buf := make([]byte, 100)
	n, err := t1.Read(buf)
	assert.NoError(t, err)
	assert.Equal(t, "bar", string(buf[:n]))

	n, err = t2.Read(buf)
	assert.NoError(t, err)
	assert.Equal(t, "bar", string(buf[:n]))
}

func TestFanOutDynamic(t *testing.T) {
	r, w, err := osutil.LongPipe()
	assert.NoError(t, err)
	defer w.Close()
	c := NewFanOut(r)
	defer c.Close()

	t1 := c.NewReader()
	w.Write([]byte("1"))
	buf := make([]byte, 100)
	t1.Read(buf)
	t1.Close()

	t2 := c.NewReader()
	defer t2.Close()
	w.Write([]byte("2"))

	n, err := t2.Read(buf)
	assert.NoError(t, err)
	assert.Equal(t, "2", string(buf[:n]))
}

func TestFanOutOverflow(t *testing.T) {
	r, w, err := osutil.LongPipe()
	assert.NoError(t, err)
	defer w.Close()
	c := NewFanOut(r)
	defer c.Close()

	tFast := c.NewReader()
	defer tFast.Close()
	tSlow := c.NewReader()
	defer tSlow.Close()

	done := make(chan bool)
	go func() {
		// Write more than buffer size (1024).
		for i := 0; i < 2000; i++ {
			w.Write([]byte("a"))
		}
		close(done)
	}()

	select {
	case <-done:
	case <-time.After(30 * time.Second):
		t.Fatal("Source blocked")
	}

	buf := make([]byte, 100)
	n, err := tFast.Read(buf)
	assert.NoError(t, err)
	assert.NotZero(t, n, "data should have been buffered")
}

func TestFanOutSourceError(t *testing.T) {
	r, w := io.Pipe()
	c := NewFanOut(r)
	defer c.Close()
	t1 := c.NewReader()
	defer t1.Close()

	w.CloseWithError(fmt.Errorf("source failed"))
	buf := make([]byte, 100)
	_, err := t1.Read(buf)
	for err == nil {
		_, err = t1.Read(buf)
	}
	assert.ErrorContains(t, err, "source failed")

	// Verify new reader gets error immediately.
	t2 := c.NewReader()
	defer t2.Close()
	data, err := t2.ReadAll()
	assert.Empty(t, data)
	assert.ErrorContains(t, err, "source failed")
}

func TestFanOutReadAll(t *testing.T) {
	r, w, err := osutil.LongPipe()
	assert.NoError(t, err)
	defer w.Close()
	c := NewFanOut(r)
	defer c.Close()

	t1 := c.NewReader()
	defer t1.Close()

	// Use a second reader to synchronize.
	// When t2 receives data, we know FanOut has processed it, so t1 must have it too.
	t2 := c.NewReader()
	defer t2.Close()

	w.Write([]byte("foo"))
	w.Write([]byte("bar"))

	// Read from t2 until we get all data.
	buf := make([]byte, 10)
	got := 0
	for got < 6 {
		n, err := t2.Read(buf)
		assert.NoError(t, err)
		got += n
	}
	assert.Equal(t, 6, got)

	// Now t1 must have the data buffered.
	data, err := t1.ReadAll()
	assert.NoError(t, err)
	assert.Equal(t, "foobar", string(data))

	// Should be empty now.
	data, err = t1.ReadAll()
	assert.NoError(t, err)
	assert.Empty(t, data)
}

func TestFanOutWait(t *testing.T) {
	r, w := io.Pipe()
	c := NewFanOut(r)
	defer c.Close()

	done := make(chan error)
	go func() {
		<-c.Wait()
		done <- c.Error()
	}()

	w.CloseWithError(fmt.Errorf("foo"))
	select {
	case err := <-done:
		assert.ErrorContains(t, err, "foo")
	case <-time.After(30 * time.Second):
		t.Fatal("Wait did not return")
	}
}
