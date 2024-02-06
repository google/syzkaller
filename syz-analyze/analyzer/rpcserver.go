package main

import (
	"github.com/google/syzkaller/pkg/log"
	"github.com/google/syzkaller/pkg/rpctype"
	"github.com/google/syzkaller/syz-analyze"
	"net"
)

type RPCServer struct {
	analyzer    Analyzer
	port        int
	currentTask map[int]int
}

func createRPCServer(addr string, analyzer Analyzer) (*RPCServer, error) {
	currentTask := make(map[int]int)
	server := &RPCServer{
		analyzer:    analyzer,
		currentTask: currentTask,
	}
	rpc, err := rpctype.NewRPCServer(addr, "Analyzer", server)
	if err != nil {
		return nil, err
	}
	server.port = rpc.Addr().(*net.TCPAddr).Port

	go rpc.Serve()
	return server, nil
}

func (server *RPCServer) NextProgram(args *syz_analyze.ProgramArgs, res *syz_analyze.ProgramResults) error {
	log.Logf(0, "program %d of %d-%d machine results: %s\n", args.ExecTaskID, args.Pool, args.VM, args.Error)
	nextProgramID := server.currentTask[vmKey(args.Pool, args.VM)]
	if nextProgramID < len(server.analyzer.programs) {
		res.ID = int64(nextProgramID)
		res.Prog = server.analyzer.programs[nextProgramID].Serialize()
		server.currentTask[vmKey(args.Pool, args.VM)] += 1
	}
	return nil
}

func vmKey(poolID, vmID int) int {
	return poolID*1000 + vmID
}
