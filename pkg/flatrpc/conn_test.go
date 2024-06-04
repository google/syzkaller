// Copyright 2024 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package flatrpc

import (
	"net"
	"os"
	"syscall"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

func TestConn(t *testing.T) {
	connectReq := &ConnectRequest{
		Name:        "foo",
		Arch:        "arch",
		GitRevision: "rev1",
		SyzRevision: "rev2",
	}
	connectReply := &ConnectReply{
		LeakFrames: []string{"foo", "bar"},
		RaceFrames: []string{"bar", "baz"},
		Features:   FeatureCoverage | FeatureLeak,
		Files:      []string{"file1"},
		Globs:      []string{"glob1"},
	}
	executorMsg := &ExecutorMessage{
		Msg: &ExecutorMessages{
			Type: ExecutorMessagesRawExecuting,
			Value: &ExecutingMessage{
				Id:     1,
				ProcId: 2,
				Try:    3,
			},
		},
	}

	done := make(chan bool)
	defer func() {
		<-done
	}()
	serv, err := ListenAndServe(":0", func(c *Conn) {
		defer close(done)
		connectReqGot, err := Recv[*ConnectRequestRaw](c)
		if err != nil {
			t.Fatal(err)
		}
		assert.Equal(t, connectReq, connectReqGot)

		if err := Send(c, connectReply); err != nil {
			t.Fatal(err)
		}

		for i := 0; i < 10; i++ {
			got, err := Recv[*ExecutorMessageRaw](c)
			if err != nil {
				t.Fatal(err)
			}
			assert.Equal(t, executorMsg, got)
		}
	})
	if err != nil {
		t.Fatal(err)
	}
	defer serv.Close()

	c := dial(t, serv.Addr.String())
	defer c.Close()

	if err := Send(c, connectReq); err != nil {
		t.Fatal(err)
	}

	connectReplyGot, err := Recv[*ConnectReplyRaw](c)
	if err != nil {
		t.Fatal(err)
	}
	assert.Equal(t, connectReply, connectReplyGot)

	for i := 0; i < 10; i++ {
		if err := Send(c, executorMsg); err != nil {
			t.Fatal(err)
		}
	}
}

func BenchmarkConn(b *testing.B) {
	connectReq := &ConnectRequest{
		Name:        "foo",
		Arch:        "arch",
		GitRevision: "rev1",
		SyzRevision: "rev2",
	}
	connectReply := &ConnectReply{
		LeakFrames: []string{"foo", "bar"},
		RaceFrames: []string{"bar", "baz"},
		Features:   FeatureCoverage | FeatureLeak,
		Files:      []string{"file1"},
		Globs:      []string{"glob1"},
	}

	done := make(chan bool)
	defer func() {
		<-done
	}()
	serv, err := ListenAndServe(":0", func(c *Conn) {
		defer close(done)
		for i := 0; i < b.N; i++ {
			_, err := Recv[*ConnectRequestRaw](c)
			if err != nil {
				b.Fatal(err)
			}
			if err := Send(c, connectReply); err != nil {
				b.Fatal(err)
			}
		}
	})
	if err != nil {
		b.Fatal(err)
	}
	defer serv.Close()

	c := dial(b, serv.Addr.String())
	defer c.Close()

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if err := Send(c, connectReq); err != nil {
			b.Fatal(err)
		}
		_, err := Recv[*ConnectReplyRaw](c)
		if err != nil {
			b.Fatal(err)
		}
	}
}

func dial(t testing.TB, addr string) *Conn {
	conn, err := net.DialTimeout("tcp", addr, time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	return NewConn(conn)
}

func FuzzRecv(f *testing.F) {
	f.Fuzz(func(t *testing.T, data []byte) {
		data = data[:min(len(data), 1<<10)]
		fds, err := syscall.Socketpair(syscall.AF_LOCAL, syscall.SOCK_STREAM, 0)
		if err != nil {
			t.Fatal(err)
		}
		w := os.NewFile(uintptr(fds[0]), "")
		r := os.NewFile(uintptr(fds[1]), "")
		defer w.Close()
		defer r.Close()
		if _, err := w.Write(data); err != nil {
			t.Fatal(err)
		}
		w.Close()
		n, err := net.FileConn(r)
		if err != nil {
			t.Fatal(err)
		}
		c := NewConn(n)
		for {
			_, err := Recv[*ExecutorMessageRaw](c)
			if err != nil {
				break
			}
		}
	})
}
