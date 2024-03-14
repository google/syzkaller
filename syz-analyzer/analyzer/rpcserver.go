package main

import (
	"github.com/google/syzkaller/pkg/log"
	"github.com/google/syzkaller/pkg/rpctype"
	"github.com/google/syzkaller/syz-analyzer"
	"net"
)

type RPCServer struct {
	analyzer   *Analyzer
	port       int
	tasksQueue *TasksQueue
}

func createRPCServer(addr string, analyzer *Analyzer) (*RPCServer, error) {
	tasksQueue := &TasksQueue{queue: make(map[int][]int)}

	server := &RPCServer{
		analyzer:   analyzer,
		tasksQueue: tasksQueue,
	}
	rpc, err := rpctype.NewRPCServer(addr, "Analyzer", server)
	if err != nil {
		return nil, err
	}
	server.port = rpc.Addr().(*net.TCPAddr).Port

	go rpc.Serve()
	return server, nil
}

func (server *RPCServer) NextProgram(args *syz_analyzer.ProgramArgs, res *syz_analyzer.ProgramResults) error {
	if args.Error != nil {
		log.Logf(0, "program %d of %d-%d machine results: %s\n", args.TaskID, args.Pool, args.VM, args.Error)
	}

	if server.tasksQueue.isEmpty(vmKey(args.Pool, args.VM)) {
		return nil
	}
	nextProgramID, err := server.tasksQueue.getAndPop(vmKey(args.Pool, args.VM))

	if err != nil {
		return err
	}

	if nextProgramID < len(server.analyzer.programs) {
		res.ID = int64(nextProgramID)
		res.Prog = server.analyzer.programs[nextProgramID].Serialize()
	}

	return nil
}

func vmKey(poolID, vmID int) int {
	return poolID*1000 + vmID
}
