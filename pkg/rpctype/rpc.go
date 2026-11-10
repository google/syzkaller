// Copyright 2017 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package rpctype

import (
	"compress/flate"
	"errors"
	"fmt"
	"io"
	"net"
	"net/rpc"
	"time"

	"github.com/google/syzkaller/pkg/log"
)

type RPCServer struct {
	ln net.Listener
	s  *rpc.Server
}

func NewRPCServer(addr, name string, receiver any) (*RPCServer, error) {
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return nil, fmt.Errorf("failed to listen on %v: %w", addr, err)
	}
	s := rpc.NewServer()
	if err := s.RegisterName(name, receiver); err != nil {
		ln.Close()
		return nil, err
	}
	serv := &RPCServer{
		ln: ln,
		s:  s,
	}
	return serv, nil
}

func (serv *RPCServer) Serve() {
	for {
		conn, err := serv.ln.Accept()
		if err != nil {
			if errors.Is(err, net.ErrClosed) {
				break
			}
			log.Logf(0, "failed to accept an rpc connection: %v", err)
			continue
		}
		setupKeepAlive(conn, time.Minute)
		go serv.s.ServeConn(newFlateConn(conn))
	}
}

func (serv *RPCServer) Addr() net.Addr {
	return serv.ln.Addr()
}

func (serv *RPCServer) Close() error {
	return serv.ln.Close()
}

type RPCClient struct {
	conn net.Conn
	c    *rpc.Client
}

func NewRPCClient(addr string) (*RPCClient, error) {
	conn, err := net.DialTimeout("tcp", addr, 3*time.Minute)
	if err != nil {
		return nil, err
	}
	setupKeepAlive(conn, time.Minute)
	cli := &RPCClient{
		conn: conn,
		c:    rpc.NewClient(newFlateConn(conn)),
	}
	return cli, nil
}

func (cli *RPCClient) Call(method string, args, reply any) error {
	// Note: SetDeadline is not implemented on fuchsia, so don't fail on error.
	cli.conn.SetDeadline(time.Now().Add(10 * time.Minute))
	defer cli.conn.SetDeadline(time.Time{})
	return cli.c.Call(method, args, reply)
}

func (cli *RPCClient) Close() {
	cli.c.Close()
}

func setupKeepAlive(conn net.Conn, keepAlive time.Duration) {
	conn.(*net.TCPConn).SetKeepAlive(true)
	conn.(*net.TCPConn).SetKeepAlivePeriod(keepAlive)
}

// Limit the decompression ratio to defend against compressed-data
// amplification: an unauthenticated peer can otherwise send a few hundred KB
// that inflate to hundreds of MB, which encoding/gob buffers in full before
// the RPC method (and thus any authentication check) runs. Legitimate
// syzkaller traffic (serialized progs) compresses well under this ratio.
const (
	maxDecompressRatio = int64(100)
	minRatioCheckBytes = int64(1 << 20)
)

type countingReader struct {
	r io.Reader
	n int64
}

func (cr *countingReader) Read(p []byte) (int, error) {
	n, err := cr.r.Read(p)
	cr.n += int64(n)
	return n, err
}

// flateConn wraps net.Conn in flate.Reader/Writer for compressed traffic.
type flateConn struct {
	r              io.ReadCloser
	w              *flate.Writer
	c              io.Closer
	compressed     *countingReader
	lastCompressed int64
	decompressed   int64
	excess         int64
}

func newFlateConn(conn io.ReadWriteCloser) io.ReadWriteCloser {
	w, err := flate.NewWriter(conn, 9)
	if err != nil {
		panic(err)
	}
	compressed := &countingReader{r: conn}
	return &flateConn{
		r:          flate.NewReader(compressed),
		w:          w,
		c:          conn,
		compressed: compressed,
	}
}

func (fc *flateConn) Read(data []byte) (int, error) {
	n, err := fc.r.Read(data)
	fc.decompressed += int64(n)
	deltaIn := fc.compressed.n - fc.lastCompressed
	fc.lastCompressed = fc.compressed.n
	// Clamp the credit that incompressible data can bank to minRatioCheckBytes so
	// an attacker cannot send incompressible data first to bypass the ratio limit.
	fc.excess = max(-minRatioCheckBytes, fc.excess+int64(n)-deltaIn*maxDecompressRatio)
	if fc.excess > minRatioCheckBytes {
		_ = fc.c.Close()
		return 0, fmt.Errorf("rpctype: decompression ratio too high (%d -> %d bytes)", fc.compressed.n, fc.decompressed)
	}
	return n, err
}

func (fc *flateConn) Write(data []byte) (int, error) {
	n, err := fc.w.Write(data)
	if err != nil {
		return n, err
	}
	if err := fc.w.Flush(); err != nil {
		return n, err
	}
	return n, nil
}

func (fc *flateConn) Close() error {
	var err0 error
	if err := fc.r.Close(); err != nil {
		err0 = err
	}
	if err := fc.w.Close(); err != nil {
		err0 = err
	}
	if err := fc.c.Close(); err != nil {
		err0 = err
	}
	return err0
}
