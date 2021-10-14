// Copyright 2021 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package main

import (
	"net"
	"os"
	"sync"

	"github.com/google/syzkaller/pkg/log"
	"github.com/google/syzkaller/pkg/rpctype"
)

// RPCServer is a wrapper around the rpc.Server. It communicates with  Runners,
// generates programs and sends complete Results for verification.
type RPCServer struct {
	vrf             *Verifier
	port            int
	mu              sync.Mutex
	cond            *sync.Cond
	pools           map[int]*poolInfo
	progs           map[int]*progInfo
	notChecked      int
	rerunsAvailable *sync.Cond
}

func startRPCServer(vrf *Verifier) (*RPCServer, error) {
	srv := &RPCServer{
		vrf:        vrf,
		pools:      vrf.pools,
		progs:      make(map[int]*progInfo),
		notChecked: len(vrf.pools),
	}
	srv.cond = sync.NewCond(&srv.mu)
	srv.rerunsAvailable = sync.NewCond(&srv.mu)

	s, err := rpctype.NewRPCServer(vrf.addr, "Verifier", srv)
	if err != nil {
		return nil, err
	}

	log.Logf(0, "serving rpc on tcp://%v", s.Addr())
	srv.port = s.Addr().(*net.TCPAddr).Port

	go s.Serve()
	return srv, nil
}

// Connect notifies the RPCServer that a new Runner was started.
func (srv *RPCServer) Connect(a *rpctype.RunnerConnectArgs, r *rpctype.RunnerConnectRes) error {
	srv.mu.Lock()
	defer srv.mu.Unlock()
	pool, vm := a.Pool, a.VM
	srv.pools[pool].runners[vm] = make(runnerProgs)
	r.CheckUnsupportedCalls = !srv.pools[pool].checked
	return nil
}

// UpdateUnsupported communicates to the server the list of system calls not
// supported by the kernel corresponding to this pool and updates the list of
// enabled system calls. This function is called once for each kernel.
// When all kernels have reported the list of unsupported system calls, the
// choice table will be created using only the system calls supported by all
// kernels.
func (srv *RPCServer) UpdateUnsupported(a *rpctype.UpdateUnsupportedArgs, r *int) error {
	srv.mu.Lock()
	defer srv.mu.Unlock()
	if srv.pools[a.Pool].checked {
		return nil
	}
	srv.pools[a.Pool].checked = true
	vrf := srv.vrf

	for _, unsupported := range a.UnsupportedCalls {
		if c := vrf.target.Syscalls[unsupported.ID]; vrf.calls[c] {
			vrf.reasons[c] = unsupported.Reason
		}
	}

	srv.notChecked--
	if srv.notChecked == 0 {
		vrf.finalizeCallSet(os.Stdout)

		vrf.stats = InitStats(vrf.calls)
		vrf.SetPrintStatAtSIGINT()

		vrf.choiceTable = vrf.target.BuildChoiceTable(nil, vrf.calls)
		srv.cond.Signal()
	}
	return nil
}

// NextExchange is called when a Runner requests a new program to execute and,
// potentially, wants to send a new Result to the RPCServer.
func (srv *RPCServer) NextExchange(a *rpctype.NextExchangeArgs, r *rpctype.NextExchangeRes) error {
	srv.mu.Lock()
	defer srv.mu.Unlock()

	var res *ExecResult
	var prog *progInfo
	if a.Info.Calls != nil {
		res = &ExecResult{
			Pool:   a.Pool,
			Hanged: a.Hanged,
			Info:   a.Info,
			RunIdx: a.RunIdx,
		}

		prog = srv.progs[a.ProgIdx]
		if prog == nil {
			// This case can happen if both conditions are true:
			// 1. a Runner calls Verifier.NextExchange, then crashes,
			// its corresponding Pool being the only one that hasn't
			// sent results for the program yet
			// 2.the cleanup call for the crash got the server's mutex before
			// the NextExchange call.
			// As the pool was the only one that hasn't sent the result, the
			// cleanup call has already removed prog from srv.progs by the time
			// the NextExchange call gets the server's mutex, which is why the
			// variable is nil. As the results for this program have already
			// been sent for verification, we discard this one.
			return nil
		}

		delete(srv.pools[a.Pool].runners[a.VM], prog.idx)
		if srv.newResult(res, prog) {
			if srv.vrf.processResults(prog) {
				delete(srv.progs, prog.idx)
			}
		}
	}

	if srv.notChecked > 0 {
		// Runner is blocked until the choice table is created.
		srv.cond.Wait()
	}

	newProg, pi, ri := srv.newProgram(a.Pool, a.VM)
	r.RPCProg = rpctype.RPCProg{Prog: newProg, ProgIdx: pi, RunIdx: ri}
	return nil
}

// newResult is called when a Runner sends a new Result. It returns true if all
// Results from the corresponding programs have been received and they can be
// sent for verification. Otherwise, it returns false.
func (srv *RPCServer) newResult(res *ExecResult, prog *progInfo) bool {
	ri := prog.runIdx
	if prog.res[ri][res.Pool] != nil {
		return false
	}
	prog.res[ri][res.Pool] = res
	prog.received++
	return prog.received == len(srv.pools)
}

func (srv *RPCServer) newRun(p *progInfo) {
	p.runIdx++
	p.received = 0
	p.res[p.runIdx] = make([]*ExecResult, len(srv.pools))
	for _, pool := range srv.pools {
		pool.toRerun = append(pool.toRerun, p)
	}
}

// newProgram returns a new program for the Runner identified by poolIdx and
// vmIdx and the program's index.
func (srv *RPCServer) newProgram(poolIdx, vmIdx int) ([]byte, int, int) {
	pool := srv.pools[poolIdx]

	if len(pool.toRerun) != 0 {
		p := pool.toRerun[0]
		pool.runners[vmIdx][p.idx] = p
		pool.toRerun = pool.toRerun[1:]
		return p.serialized, p.idx, p.runIdx
	}

	if len(pool.progs) == 0 {
		prog, progIdx := srv.vrf.generate()
		pi := &progInfo{
			prog:       prog,
			idx:        progIdx,
			serialized: prog.Serialize(),
			res:        make([][]*ExecResult, srv.vrf.reruns),
		}
		pi.res[0] = make([]*ExecResult, len(srv.pools))
		for _, pool := range srv.pools {
			pool.progs = append(pool.progs, pi)
		}
		srv.progs[progIdx] = pi
	}
	p := pool.progs[0]
	pool.runners[vmIdx][p.idx] = p
	pool.progs = pool.progs[1:]
	return p.serialized, p.idx, p.runIdx
}

// cleanup is called when a vm.Instance crashes.
func (srv *RPCServer) cleanup(poolIdx, vmIdx int) {
	srv.mu.Lock()
	defer srv.mu.Unlock()
	progs := srv.pools[poolIdx].runners[vmIdx]

	for _, prog := range progs {
		if srv.newResult(&ExecResult{Pool: poolIdx, Crashed: true}, prog) {
			srv.vrf.processResults(prog)
			delete(srv.progs, prog.idx)
			delete(srv.pools[poolIdx].runners[vmIdx], prog.idx)
			continue
		}
	}
}
