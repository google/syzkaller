// Copyright 2017 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package rpctype

import (
	"fmt"
	"net"
	"net/rpc"
	"time"

	"github.com/google/syzkaller/pkg/log"
)

type RPCServer struct {
	ln net.Listener
	s  *rpc.Server
}

func NewRPCServer(addr string, receiver interface{}) (*RPCServer, error) {
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return nil, fmt.Errorf("failed to listen on %v: %v", addr, err)
	}
	s := rpc.NewServer()
	s.Register(receiver)
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
			log.Logf(0, "failed to accept an rpc connection: %v", err)
			continue
		}
		conn.(*net.TCPConn).SetKeepAlive(true)
		conn.(*net.TCPConn).SetKeepAlivePeriod(time.Minute)
		go serv.s.ServeConn(conn)
	}
}

func (serv *RPCServer) Addr() net.Addr {
	return serv.ln.Addr()
}

type RPCClient struct {
	conn net.Conn
	c    *rpc.Client
}

func NewRPCClient(addr string) (*RPCClient, error) {
	conn, err := net.DialTimeout("tcp", addr, 60*time.Second)
	if err != nil {
		return nil, err
	}
	conn.(*net.TCPConn).SetKeepAlive(true)
	conn.(*net.TCPConn).SetKeepAlivePeriod(time.Minute)
	cli := &RPCClient{
		conn: conn,
		c:    rpc.NewClient(conn),
	}
	return cli, nil
}

func (cli *RPCClient) Call(method string, args, reply interface{}) error {
	cli.conn.SetDeadline(time.Now().Add(5 * 60 * time.Second))
	err := cli.c.Call(method, args, reply)
	cli.conn.SetDeadline(time.Time{})
	return err
}

func (cli *RPCClient) Close() {
	cli.c.Close()
}

func RPCCall(addr, method string, args, reply interface{}) error {
	c, err := NewRPCClient(addr)
	if err != nil {
		return err
	}
	defer c.Close()
	return c.Call(method, args, reply)
}
