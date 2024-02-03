package main

import (
	"github.com/google/syzkaller/pkg/log"
	"github.com/google/syzkaller/pkg/rpctype"
	"net"
)

type RPCServer struct {
	analyzer PoolInfo
	port     int
}

func createRPCServer(addr string, analyzer PoolInfo) (*RPCServer, error) {
	server := &RPCServer{
		analyzer: analyzer,
	}
	rpc, err := rpctype.NewRPCServer(addr, "Analyzer", server)
	if err != nil {
		return nil, err
	}
	server.port = rpc.Addr().(*net.TCPAddr).Port

	go rpc.Serve()
	return server, nil
}

func (server *RPCServer) NextProgram(args *rpctype.NextExchangeArgs, res *rpctype.NextExchangeRes) error {
	log.Logf(0, "program %d of %d-%d machine results: %v", args.ExecTaskID, args.Pool, args.VM, args.Hanged)
	res.Prog = server.analyzer.programs[0].Serialize()
	return nil
}
