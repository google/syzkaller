// Copyright 2017 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package rpctype

import (
	"compress/flate"
	"fmt"
	"io"
	"net"
	"net/rpc"
	"os"
	"time"

	"github.com/google/syzkaller/pkg/log"
	"github.com/google/syzkaller/pkg/stats"
)

type RPCServer struct {
	ln             net.Listener
	s              *rpc.Server
	useCompression bool
	statSent       *stats.Val
	statRecv       *stats.Val
}

func NewRPCServer(addr, name string, receiver interface{}, useCompression bool) (*RPCServer, error) {
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return nil, fmt.Errorf("failed to listen on %v: %w", addr, err)
	}
	s := rpc.NewServer()
	if err := s.RegisterName(name, receiver); err != nil {
		return nil, err
	}
	serv := &RPCServer{
		ln:             ln,
		s:              s,
		useCompression: useCompression,
		statSent: stats.Create("rpc sent", "Uncompressed outbound RPC traffic",
			stats.Graph("traffic"), stats.Rate{}, stats.FormatMB),
		statRecv: stats.Create("rpc recv", "Uncompressed inbound RPC traffic",
			stats.Graph("traffic"), stats.Rate{}, stats.FormatMB),
	}
	return serv, nil
}

func (serv *RPCServer) Serve() {
	for {
		conn, err := serv.ln.Accept()
		if err != nil {
			log.Logf(0, "failed to accept an rpc connection: %v", err)
			continue
		}
		setupKeepAlive(conn, time.Minute)
		go serv.s.ServeConn(maybeFlateConn(newCountedConn(serv, conn), serv.useCompression))
	}
}

func (serv *RPCServer) Addr() net.Addr {
	return serv.ln.Addr()
}

type RPCClient struct {
	conn           net.Conn
	c              *rpc.Client
	timeScale      time.Duration
	useTimeouts    bool
	useCompression bool
}

func Dial(addr string, timeScale time.Duration) (net.Conn, error) {
	if timeScale <= 0 {
		return nil, fmt.Errorf("bad rpc time scale %v", timeScale)
	}
	var conn net.Conn
	var err error
	if addr == "stdin" {
		// This is used by vm/gvisor which passes us a unix socket connection in stdin.
		return net.FileConn(os.Stdin)
	}
	if conn, err = net.DialTimeout("tcp", addr, time.Minute*timeScale); err != nil {
		return nil, err
	}
	setupKeepAlive(conn, time.Minute*timeScale)
	return conn, nil
}

func NewRPCClient(addr string, timeScale time.Duration, useTimeouts, useCompression bool) (*RPCClient, error) {
	conn, err := Dial(addr, timeScale)
	if err != nil {
		return nil, err
	}
	cli := &RPCClient{
		conn:           conn,
		c:              rpc.NewClient(maybeFlateConn(conn, useCompression)),
		timeScale:      timeScale,
		useTimeouts:    useTimeouts,
		useCompression: useCompression,
	}
	return cli, nil
}

func (cli *RPCClient) Call(method string, args, reply interface{}) error {
	if cli.useTimeouts {
		// Note: SetDeadline is not implemented on fuchsia, so don't fail on error.
		cli.conn.SetDeadline(time.Now().Add(3 * time.Minute * cli.timeScale))
		defer cli.conn.SetDeadline(time.Time{})
	}
	return cli.c.Call(method, args, reply)
}

func (cli *RPCClient) AsyncCall(method string, args interface{}) {
	cli.c.Go(method, args, nil, nil)
}

func (cli *RPCClient) Close() {
	cli.c.Close()
}

func setupKeepAlive(conn net.Conn, keepAlive time.Duration) {
	conn.(*net.TCPConn).SetKeepAlive(true)
	conn.(*net.TCPConn).SetKeepAlivePeriod(keepAlive)
}

// flateConn wraps net.Conn in flate.Reader/Writer for compressed traffic.
type flateConn struct {
	r io.ReadCloser
	w *flate.Writer
	c io.Closer
}

func maybeFlateConn(conn io.ReadWriteCloser, useCompression bool) io.ReadWriteCloser {
	if !useCompression {
		return conn
	}
	w, err := flate.NewWriter(conn, 9)
	if err != nil {
		panic(err)
	}
	return &flateConn{
		r: flate.NewReader(conn),
		w: w,
		c: conn,
	}
}

func (fc *flateConn) Read(data []byte) (int, error) {
	return fc.r.Read(data)
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

// countedConn wraps net.Conn to record the transferred bytes.
type countedConn struct {
	io.ReadWriteCloser
	server *RPCServer
}

func newCountedConn(server *RPCServer,
	conn io.ReadWriteCloser) io.ReadWriteCloser {
	return &countedConn{
		ReadWriteCloser: conn,
		server:          server,
	}
}

func (cc countedConn) Read(p []byte) (n int, err error) {
	n, err = cc.ReadWriteCloser.Read(p)
	cc.server.statRecv.Add(n)
	return
}

func (cc countedConn) Write(b []byte) (n int, err error) {
	n, err = cc.ReadWriteCloser.Write(b)
	cc.server.statSent.Add(n)
	return
}
