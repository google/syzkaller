// Copyright 2017 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package rpctype

import (
	"cmp"
	"compress/flate"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/rpc"
	"time"

	"github.com/google/syzkaller/pkg/log"
)

type RPCServer struct {
	ln   net.Listener
	s    *rpc.Server
	auth AuthChecker
}

func NewRPCServer(addr, name string, receiver AuthChecker) (*RPCServer, error) {
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return nil, fmt.Errorf("failed to listen on %v: %w", addr, err)
	}
	s := rpc.NewServer()
	if err := s.RegisterName(name, receiver); err != nil {
		ln.Close()
		return nil, err
	}
	return &RPCServer{
		ln:   ln,
		s:    s,
		auth: receiver,
	}, nil
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
		go serv.handleConn(conn)
	}
}

func (serv *RPCServer) handleConn(conn net.Conn) {
	conn.SetDeadline(time.Now().Add(time.Minute))
	var req rpcAuthReq
	if err := readPreAuthMsg(conn, &req); err != nil {
		conn.Close()
		return
	}
	if err := serv.auth.CheckAuth(req.Client, req.Key, req.Manager); err != nil {
		_ = writePreAuthMsg(conn, &rpcAuthRes{Error: cmp.Or(err.Error(), "unauthorized")})
		conn.Close()
		return
	}
	if err := writePreAuthMsg(conn, &rpcAuthRes{}); err != nil {
		conn.Close()
		return
	}
	conn.SetDeadline(time.Time{})
	serv.s.ServeConn(newFlateConn(conn))
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

func NewRPCClient(addr, client, key, manager string) (*RPCClient, error) {
	conn, err := net.DialTimeout("tcp", addr, 3*time.Minute)
	if err != nil {
		return nil, err
	}
	setupKeepAlive(conn, time.Minute)
	conn.SetDeadline(time.Now().Add(time.Minute))
	req := &rpcAuthReq{Client: client, Key: key, Manager: manager}
	var res rpcAuthRes
	if err := writePreAuthMsg(conn, req); err != nil {
		conn.Close()
		return nil, err
	}
	if err := readPreAuthMsg(conn, &res); err != nil {
		conn.Close()
		return nil, err
	}
	if res.Error != "" {
		conn.Close()
		return nil, errors.New(res.Error)
	}
	conn.SetDeadline(time.Time{})
	return &RPCClient{
		conn: conn,
		c:    rpc.NewClient(newFlateConn(conn)),
	}, nil
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

const maxPreAuthBytes = 4 << 10

type rpcAuthReq struct {
	Client  string
	Key     string
	Manager string
}

type rpcAuthRes struct {
	Error string `json:",omitempty"`
}

func writePreAuthMsg(w io.Writer, msg any) error {
	data, err := json.Marshal(msg)
	if err != nil {
		return err
	}
	if len(data) > maxPreAuthBytes {
		return fmt.Errorf("pre-auth message too large (%d bytes)", len(data))
	}
	raw := make([]byte, 4+len(data))
	binary.BigEndian.PutUint32(raw[:4], uint32(len(data)))
	copy(raw[4:], data)
	_, err = w.Write(raw)
	return err
}

func readPreAuthMsg(r io.Reader, msg any) error {
	var hdr [4]byte
	if _, err := io.ReadFull(r, hdr[:]); err != nil {
		return err
	}
	size := binary.BigEndian.Uint32(hdr[:])
	if size > maxPreAuthBytes {
		return fmt.Errorf("pre-auth message too large (%d bytes)", size)
	}
	buf := make([]byte, size)
	if _, err := io.ReadFull(r, buf); err != nil {
		return err
	}
	return json.Unmarshal(buf, msg)
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

func newFlateConn(conn io.ReadWriteCloser) io.ReadWriteCloser {
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
