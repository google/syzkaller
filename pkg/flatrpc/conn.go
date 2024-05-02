// Copyright 2024 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package flatrpc

import (
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"slices"
	"sync"
	"time"

	flatbuffers "github.com/google/flatbuffers/go"
	"github.com/google/syzkaller/pkg/log"
	"github.com/google/syzkaller/pkg/stats"
)

var (
	statSent = stats.Create("rpc sent", "Outbound RPC traffic",
		stats.Graph("traffic"), stats.Rate{}, stats.FormatMB)
	statRecv = stats.Create("rpc recv", "Inbound RPC traffic",
		stats.Graph("traffic"), stats.Rate{}, stats.FormatMB)
)

type Serv struct {
	Addr *net.TCPAddr
	ln   net.Listener
}

func ListenAndServe(addr string, handler func(*Conn)) (*Serv, error) {
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return nil, err
	}
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				if errors.Is(err, net.ErrClosed) {
					break
				}
				var netErr *net.OpError
				if errors.As(err, &netErr) && !netErr.Temporary() {
					log.Fatalf("flatrpc: failed to accept: %v", err)
				}
				log.Logf(0, "flatrpc: failed to accept: %v", err)
				continue
			}
			go func() {
				c := newConn(conn)
				defer c.Close()
				handler(c)
			}()
		}
	}()
	return &Serv{
		Addr: ln.Addr().(*net.TCPAddr),
		ln:   ln,
	}, nil
}

func (s *Serv) Close() error {
	return s.ln.Close()
}

type Conn struct {
	conn net.Conn

	sendMu  sync.Mutex
	builder *flatbuffers.Builder

	data    []byte
	hasData int
	lastMsg int
}

func Dial(addr string, timeScale time.Duration) (*Conn, error) {
	var conn net.Conn
	var err error
	if addr == "stdin" {
		// This is used by vm/gvisor which passes us a unix socket connection in stdin.
		conn, err = net.FileConn(os.Stdin)
	} else {
		conn, err = net.DialTimeout("tcp", addr, time.Minute*timeScale)
	}
	if err != nil {
		return nil, err
	}
	return newConn(conn), nil
}

func newConn(conn net.Conn) *Conn {
	return &Conn{
		conn:    conn,
		builder: flatbuffers.NewBuilder(0),
	}
}

func (c *Conn) Close() error {
	return c.conn.Close()
}

type sendMsg interface {
	Pack(*flatbuffers.Builder) flatbuffers.UOffsetT
}

// Send sends an RPC message.
// The type T is supposed to be an "object API" type ending with T (e.g. ConnectRequestT).
// Sending can be done from multiple goroutines concurrently.
func Send[T sendMsg](c *Conn, msg T) error {
	c.sendMu.Lock()
	defer c.sendMu.Unlock()
	off := msg.Pack(c.builder)
	c.builder.FinishSizePrefixed(off)
	data := c.builder.FinishedBytes()
	_, err := c.conn.Write(data)
	c.builder.Reset()
	statSent.Add(len(data))
	if err != nil {
		return fmt.Errorf("failed to send %T: %w", msg, err)
	}
	return nil
}

// Recv received an RPC message.
// The type T is supposed to be a normal flatbuffers type (not ending with T, e.g. ConnectRequest).
// Receiving should be done from a single goroutine, the received message is valid
// only until the next Recv call (messages share the same underlying receive buffer).
func Recv[T any, PT interface {
	*T
	flatbuffers.FlatBuffer
}](c *Conn) (*T, error) {
	// First, discard the previous message.
	// For simplicity we copy any data from the next message to the beginning of the buffer.
	// Theoretically we could something more efficient, e.g. don't copy if we already
	// have a full next message.
	if c.hasData > c.lastMsg {
		copy(c.data, c.data[c.lastMsg:c.hasData])
	}
	c.hasData -= c.lastMsg
	c.lastMsg = 0
	const (
		sizePrefixSize = flatbuffers.SizeUint32
		maxMessageSize = 64 << 20
	)
	msg := PT(new(T))
	// Then, receive at least the size prefix (4 bytes).
	// And then the full message, if we have not got it yet.
	if err := c.recv(sizePrefixSize); err != nil {
		return nil, fmt.Errorf("failed to recv %T: %w", msg, err)
	}
	size := int(flatbuffers.GetSizePrefix(c.data, 0))
	if size > maxMessageSize {
		return nil, fmt.Errorf("message %T has too large size %v", msg, size)
	}
	c.lastMsg = sizePrefixSize + size
	if err := c.recv(c.lastMsg); err != nil {
		return nil, fmt.Errorf("failed to recv %T: %w", msg, err)
	}
	statRecv.Add(c.lastMsg)
	data := c.data[sizePrefixSize:c.lastMsg]
	msg.Init(data, flatbuffers.GetUOffsetT(data))
	return msg, nil
}

// recv ensures that we have at least 'size' bytes received in c.data.
func (c *Conn) recv(size int) error {
	need := size - c.hasData
	if need <= 0 {
		return nil
	}
	if grow := size - len(c.data) + c.hasData; grow > 0 {
		c.data = slices.Grow(c.data, grow)[:len(c.data)+grow]
	}
	n, err := io.ReadAtLeast(c.conn, c.data[c.hasData:], need)
	if err != nil {
		return err
	}
	c.hasData += n
	return nil
}
