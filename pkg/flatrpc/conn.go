// Copyright 2024 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package flatrpc

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"reflect"
	"slices"
	"sync"
	"unsafe"

	flatbuffers "github.com/google/flatbuffers/go"
	"github.com/google/syzkaller/pkg/log"
	"github.com/google/syzkaller/pkg/stat"
	"golang.org/x/sync/errgroup"
)

var (
	statSent = stat.New("rpc sent", "Outbound RPC traffic",
		stat.Graph("traffic"), stat.Rate{}, stat.FormatMB)
	statRecv = stat.New("rpc recv", "Inbound RPC traffic",
		stat.Graph("traffic"), stat.Rate{}, stat.FormatMB)
)

type Serv struct {
	Addr *net.TCPAddr
	ln   net.Listener
}

func Listen(addr string) (*Serv, error) {
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return nil, err
	}
	return &Serv{
		Addr: ln.Addr().(*net.TCPAddr),
		ln:   ln,
	}, nil
}

// Serve accepts incoming connections and calls handler for each of them.
// An error returned from the handler stops the server and aborts the whole processing.
func (s *Serv) Serve(baseCtx context.Context, handler func(context.Context, *Conn) error) error {
	eg, ctx := errgroup.WithContext(baseCtx)
	go func() {
		// If the context is cancelled, stop the server.
		<-ctx.Done()
		s.Close()
	}()
	for {
		conn, err := s.ln.Accept()
		if err != nil && errors.Is(err, net.ErrClosed) {
			break
		}
		if err != nil {
			var netErr *net.OpError
			if errors.As(err, &netErr) && !netErr.Temporary() {
				return fmt.Errorf("flatrpc: failed to accept: %w", err)
			}
			log.Logf(0, "flatrpc: failed to accept: %v", err)
			continue
		}
		eg.Go(func() error {
			connCtx, cancel := context.WithCancel(ctx)
			defer cancel()

			c := NewConn(conn)
			// Closing the server does not automatically close all the connections.
			go func() {
				<-connCtx.Done()
				c.Close()
			}()
			return handler(connCtx, c)
		})
	}
	return eg.Wait()
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

func NewConn(conn net.Conn) *Conn {
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

type RecvType[T any] interface {
	UnPack() *T
	flatbuffers.FlatBuffer
}

// Recv receives an RPC message.
// The type T is supposed to be a pointer to a normal flatbuffers type (not ending with T, e.g. *ConnectRequestRaw).
// Receiving should be done from a single goroutine, the received message is valid
// only until the next Recv call (messages share the same underlying receive buffer).
func Recv[Raw RecvType[T], T any](c *Conn) (res *T, err0 error) {
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
	// Then, receive at least the size prefix (4 bytes).
	// And then the full message, if we have not got it yet.
	if err := c.recv(sizePrefixSize); err != nil {
		return nil, fmt.Errorf("failed to recv %T: %w", (*T)(nil), err)
	}
	size := int(flatbuffers.GetSizePrefix(c.data, 0))
	if size > maxMessageSize {
		return nil, fmt.Errorf("message %T has too large size %v", (*T)(nil), size)
	}
	c.lastMsg = sizePrefixSize + size
	if err := c.recv(c.lastMsg); err != nil {
		return nil, fmt.Errorf("failed to recv %T: %w", (*T)(nil), err)
	}
	return Parse[Raw](c.data[sizePrefixSize:c.lastMsg])
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

func Parse[Raw RecvType[T], T any](data []byte) (res *T, err0 error) {
	defer func() {
		if err := recover(); err != nil {
			err0 = fmt.Errorf("%v", err)
		}
	}()
	statRecv.Add(len(data))
	// This probably can be expressed w/o reflect as "new U" where U is *T,
	// but I failed to express that as generic constraints.
	var msg Raw
	msg = reflect.New(reflect.TypeOf(msg).Elem()).Interface().(Raw)
	msg.Init(data, flatbuffers.GetUOffsetT(data))
	if err := verify(msg, len(data)); err != nil {
		return nil, err
	}
	return msg.UnPack(), nil
}

func verify(raw any, rawSize int) error {
	switch msg := raw.(type) {
	case *ExecutorMessageRaw:
		return verifyExecutorMessage(msg, rawSize)
	}
	return nil
}

func verifyExecutorMessage(raw *ExecutorMessageRaw, rawSize int) error {
	// We receive the message into raw (non object API) type and carefully verify
	// because the message from the test machine can be corrupted in all possible ways.
	// Recovering from panics handles most corruptions (since flatbuffers does not use unsafe
	// and panics on any OOB references). But it's still possible that UnPack may try to allocate
	// unbounded amount of memory and crash with OOM. To prevent that we check that arrays have
	// reasonable size. We don't need to check []byte/string b/c for them flatbuffers use
	// Table.ByteVector which directly references the underlying byte slice and also panics
	// if size is OOB. But we need to check all other arrays b/c for them flatbuffers will
	// first do make([]T, size), filling that array later will panic, but it's already too late
	// since the make will kill the process with OOM.
	switch typ := raw.MsgType(); typ {
	case ExecutorMessagesRawExecResult,
		ExecutorMessagesRawExecuting,
		ExecutorMessagesRawState:
	default:
		return fmt.Errorf("bad executor message type %v", typ)
	}
	var tab flatbuffers.Table
	if !raw.Msg(&tab) {
		return errors.New("received no message")
	}
	// Only ExecResult has arrays.
	if raw.MsgType() == ExecutorMessagesRawExecResult {
		var res ExecResultRaw
		res.Init(tab.Bytes, tab.Pos)
		return verifyExecResult(&res, rawSize)
	}
	return nil
}

func verifyExecResult(res *ExecResultRaw, rawSize int) error {
	info := res.Info(nil)
	if info == nil {
		return nil
	}
	var tmp ComparisonRaw
	// It's hard to impose good limit on each individual signal/cover/comps array,
	// so instead we count total memory size for all calls and check that it's not
	// larger than the total message size.
	callSize := func(call *CallInfoRaw) int {
		// Cap array size at 1G to prevent overflows during multiplication by size and addition.
		const maxSize = 1 << 30
		size := 0
		if call.SignalLength() != 0 {
			size += min(maxSize, call.SignalLength()) * int(unsafe.Sizeof(call.Signal(0)))
		}
		if call.CoverLength() != 0 {
			size += min(maxSize, call.CoverLength()) * int(unsafe.Sizeof(call.Cover(0)))
		}
		if call.CompsLength() != 0 {
			size += min(maxSize, call.CompsLength()) * int(unsafe.Sizeof(call.Comps(&tmp, 0)))
		}
		return size
	}
	size := 0
	var call CallInfoRaw
	for i := 0; i < info.CallsLength(); i++ {
		if info.Calls(&call, i) {
			size += callSize(&call)
		}
	}
	for i := 0; i < info.ExtraRawLength(); i++ {
		if info.ExtraRaw(&call, i) {
			size += callSize(&call)
		}
	}
	if info.Extra(&call) != nil {
		size += callSize(&call)
	}
	if size > rawSize {
		return fmt.Errorf("corrupted message: total size %v, size of elements %v",
			rawSize, size)
	}
	return nil
}
