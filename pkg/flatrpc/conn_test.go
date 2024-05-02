// Copyright 2024 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package flatrpc

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestConn(t *testing.T) {
	connectReq := &ConnectRequestT{
		Name:        "foo",
		Arch:        "arch",
		GitRevision: "rev1",
		SyzRevision: "rev2",
	}
	connectReply := &ConnectReplyT{
		LeakFrames: []string{"foo", "bar"},
		RaceFrames: []string{"bar", "baz"},
		Features:   FeatureCoverage | FeatureLeak,
		Files:      []string{"file1"},
		Globs:      []string{"glob1"},
	}
	executorMsg := &ExecutorMessageT{
		Msg: &ExecutorMessagesT{
			Type: ExecutorMessagesExecuting,
			Value: &ExecutingMessageT{
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
		connectReqGot, err := Recv[ConnectRequest](c)
		if err != nil {
			t.Fatal(err)
		}
		assert.Equal(t, connectReq, connectReqGot.UnPack())

		if err := Send(c, connectReply); err != nil {
			t.Fatal(err)
		}

		for i := 0; i < 10; i++ {
			got, err := Recv[ExecutorMessage](c)
			if err != nil {
				t.Fatal(err)
			}
			assert.Equal(t, executorMsg, got.UnPack())
		}
	})
	if err != nil {
		t.Fatal(err)
	}
	defer serv.Close()

	c, err := Dial(serv.Addr.String(), 1)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()

	if err := Send(c, connectReq); err != nil {
		t.Fatal(err)
	}

	connectReplyGot, err := Recv[ConnectReply](c)
	if err != nil {
		t.Fatal(err)
	}
	assert.Equal(t, connectReply, connectReplyGot.UnPack())

	for i := 0; i < 10; i++ {
		if err := Send(c, executorMsg); err != nil {
			t.Fatal(err)
		}
	}
}

func BenchmarkConn(b *testing.B) {
	connectReq := &ConnectRequestT{
		Name:        "foo",
		Arch:        "arch",
		GitRevision: "rev1",
		SyzRevision: "rev2",
	}
	connectReply := &ConnectReplyT{
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
			_, err := Recv[ConnectRequest](c)
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

	c, err := Dial(serv.Addr.String(), 1)
	if err != nil {
		b.Fatal(err)
	}
	defer c.Close()

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if err := Send(c, connectReq); err != nil {
			b.Fatal(err)
		}
		_, err := Recv[ConnectReply](c)
		if err != nil {
			b.Fatal(err)
		}
	}
}
