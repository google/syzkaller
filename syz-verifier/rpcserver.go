// Copyright 2021 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package main

import (
	"errors"
	"net"
	"os"
	"sync"

	"github.com/google/syzkaller/pkg/log"
	"github.com/google/syzkaller/pkg/rpctype"
)

// RPCServer is a wrapper around the rpc.Server. It communicates with  Runners,
// generates programs and sends complete Results for verification.
type RPCServer struct {
	vrf  *Verifier
	port int

	// protects next variables
	mu sync.Mutex
	// used to count the pools w/o UnsupportedCalls result
	notChecked int
	// vmTasks store the per-VM currently assigned tasks Ids
	vmTasksInProgress map[int]map[int64]bool
}

func startRPCServer(vrf *Verifier) (*RPCServer, error) {
	srv := &RPCServer{
		vrf:        vrf,
		notChecked: len(vrf.pools),
	}

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
	r.CheckUnsupportedCalls = !srv.vrf.pools[a.Pool].checked
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

	if srv.vrf.pools[a.Pool].checked {
		return nil
	}
	srv.vrf.pools[a.Pool].checked = true
	vrf := srv.vrf

	for _, unsupported := range a.UnsupportedCalls {
		if c := vrf.target.Syscalls[unsupported.ID]; vrf.calls[c] {
			vrf.reasons[c] = unsupported.Reason
		}
	}

	srv.notChecked--
	if srv.notChecked == 0 {
		vrf.finalizeCallSet(os.Stdout)

		vrf.stats.SetSyscallMask(vrf.calls)
		vrf.SetPrintStatAtSIGINT()

		vrf.choiceTable = vrf.target.BuildChoiceTable(nil, vrf.calls)
		vrf.progGeneratorInit.Done()
	}
	return nil
}

// NextExchange is called when a Runner requests a new program to execute and,
// potentially, wants to send a new Result to the RPCServer.
func (srv *RPCServer) NextExchange(a *rpctype.NextExchangeArgs, r *rpctype.NextExchangeRes) error {
	if a.Info.Calls != nil {
		srv.stopWaitResult(a.Pool, a.VM, a.ExecTaskID)
		srv.vrf.PutExecResult(&ExecResult{
			Pool:       a.Pool,
			Hanged:     a.Hanged,
			Info:       a.Info,
			ExecTaskID: a.ExecTaskID,
		})
	}

	// TODO: NewEnvironment is the currently hardcoded logic. Relax it.
	task := srv.vrf.GetRunnerTask(a.Pool, NewEnvironment)
	srv.startWaitResult(a.Pool, a.VM, task.ID)
	r.ExecTask = *task

	return nil
}

func vmTasksKey(poolID, vmID int) int {
	return poolID*1000 + vmID
}

func (srv *RPCServer) startWaitResult(poolID, vmID int, taskID int64) {
	srv.mu.Lock()
	defer srv.mu.Unlock()

	if srv.vmTasksInProgress == nil {
		srv.vmTasksInProgress = make(map[int]map[int64]bool)
	}

	if srv.vmTasksInProgress[vmTasksKey(poolID, vmID)] == nil {
		srv.vmTasksInProgress[vmTasksKey(poolID, vmID)] =
			make(map[int64]bool)
	}

	srv.vmTasksInProgress[vmTasksKey(poolID, vmID)][taskID] = true
}

func (srv *RPCServer) stopWaitResult(poolID, vmID int, taskID int64) {
	srv.mu.Lock()
	defer srv.mu.Unlock()
	delete(srv.vmTasksInProgress[vmTasksKey(poolID, vmID)], taskID)
}

// cleanup is called when a vm.Instance crashes.
func (srv *RPCServer) cleanup(poolID, vmID int) {
	srv.mu.Lock()
	defer srv.mu.Unlock()

	// Signal error for every VM related task and let upper level logic to process it.
	for taskID := range srv.vmTasksInProgress[vmTasksKey(poolID, vmID)] {
		srv.vrf.PutExecResult(&ExecResult{
			Pool:       poolID,
			ExecTaskID: taskID,
			Crashed:    true,
			Error:      errors.New("VM crashed during the task execution"),
		})
	}
	delete(srv.vmTasksInProgress, vmTasksKey(poolID, vmID))
}
