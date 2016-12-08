// Copyright 2016 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package vm

import (
	"bytes"
	"testing"
	"time"
)

func TestMerger(t *testing.T) {
	tee := new(bytes.Buffer)
	merger := NewOutputMerger(tee)

	rp1, wp1, err := LongPipe()
	if err != nil {
		t.Fatal(err)
	}
	defer wp1.Close()
	merger.Add("pipe1", rp1)

	rp2, wp2, err := LongPipe()
	if err != nil {
		t.Fatal(err)
	}
	defer wp2.Close()
	merger.Add("pipe2", rp2)

	wp1.Write([]byte("111"))
	select {
	case <-merger.Output:
		t.Fatalf("merger produced incomplete line")
	case <-time.After(10 * time.Millisecond):
	}

	wp2.Write([]byte("222"))
	select {
	case <-merger.Output:
		t.Fatalf("merger produced incomplete line")
	case <-time.After(10 * time.Millisecond):
	}

	wp1.Write([]byte("333\n444"))
	got := string(<-merger.Output)
	if want := "111333\n"; got != want {
		t.Fatalf("bad line: '%s', want '%s'", got, want)
	}

	wp2.Write([]byte("555\n666\n777"))
	got = string(<-merger.Output)
	if want := "222555\n666\n"; got != want {
		t.Fatalf("bad line: '%s', want '%s'", got, want)
	}

	wp1.Close()
	got = string(<-merger.Output)
	if want := "444\n"; got != want {
		t.Fatalf("bad line: '%s', want '%s'", got, want)
	}

	if err := <-merger.Err; err == nil || err.Error() != "failed to read from pipe1: EOF" {
		t.Fatalf("merger did not produce io.EOF: %v", err)
	}

	wp2.Close()
	got = string(<-merger.Output)
	if want := "777\n"; got != want {
		t.Fatalf("bad line: '%s', want '%s'", got, want)
	}

	merger.Wait()
	want := "111333\n222555\n666\n444\n777\n"
	if got := string(tee.Bytes()); got != want {
		t.Fatalf("bad tee: '%s', want '%s'", got, want)
	}
}
