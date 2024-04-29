// Copyright 2015 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

// Package rpctype contains types of message passed via net/rpc connections
// between various parts of the system.
package rpctype

import (
	"math"
	"time"

	"github.com/google/syzkaller/pkg/host"
	"github.com/google/syzkaller/pkg/ipc"
	"github.com/google/syzkaller/pkg/signal"
)

// ExecutionRequest describes the task of executing a particular program.
// Corresponds to Fuzzer.Request.
type ExecutionRequest struct {
	ID               int64
	ProgData         []byte
	ExecOpts         ipc.ExecOpts
	NewSignal        bool
	SignalFilter     signal.Signal
	SignalFilterCall int
}

// ExecutionResult is sent after ExecutionRequest is completed.
type ExecutionResult struct {
	ID     int64
	ProcID int
	Try    int
	Info   ipc.ProgInfo
}

// ExchangeInfoRequest is periodically sent by syz-fuzzer to syz-manager.
type ExchangeInfoRequest struct {
	Name       string
	NeedProgs  int
	StatsDelta map[string]uint64
	Results    []ExecutionResult
	Latency    time.Duration // latency of the previous ExchangeInfo request
}

// ExchangeInfoReply is a reply to ExchangeInfoRequest.
type ExchangeInfoReply struct {
	Requests      []ExecutionRequest
	NewMaxSignal  []uint32
	DropMaxSignal []uint32
}

// ExecutingRequest is notification from the fuzzer that it started executing
// the program ProgID. We want this request to be as small and as fast as possible
// b/c we want it to reach manager (or at least leave the VM) before it crashes
// executing this program.
type ExecutingRequest struct {
	Name   string
	ID     int64
	ProcID int
	Try    int
}

// TODO: merge ExecutionRequest and ExecTask.
type ExecTask struct {
	Prog []byte
	ID   int64
}

type ConnectArgs struct {
	Name                string
	GitRevision         string
	SyzRevision         string
	ExecutorArch        string
	ExecutorGitRevision string
	ExecutorSyzRevision string
}

type ConnectRes struct {
	EnabledCalls     []int
	MemoryLeakFrames []string
	DataRaceFrames   []string
	AllSandboxes     bool
	// This is forwarded from CheckArgs, if checking was already done.
	Features *host.Features
	// Fuzzer reads these files inside of the VM and returns contents in CheckArgs.Files.
	ReadFiles []string
	ReadGlobs []string
}

type CheckArgs struct {
	Name          string
	Error         string
	EnabledCalls  map[string][]int
	DisabledCalls map[string][]SyscallReason
	Features      *host.Features
	Globs         map[string][]string
	Files         []host.FileInfo
}

type CheckRes struct {
	CoverFilterBitmap []byte
}

type SyscallReason struct {
	ID     int
	Reason string
}

type RunnerConnectArgs struct {
	Pool, VM int
}

type RunnerConnectRes struct {
	// CheckUnsupportedCalls is set to true if the Runner needs to query the kernel
	// for unsupported system calls and report them back to the server.
	CheckUnsupportedCalls bool
}

// UpdateUnsupportedArgs contains the data passed from client to server in an
// UpdateSupported call, namely the system calls not supported by the client's
// kernel.
type UpdateUnsupportedArgs struct {
	// Pool is used to identify the checked kernel.
	Pool int
	// UnsupportedCalls contains the ID's of system calls not supported by the
	// client and the reason for this.
	UnsupportedCalls []SyscallReason
}

// NextExchangeArgs contains the data passed from client to server namely
// identification information of the VM and program execution results.
type NextExchangeArgs struct {
	// Pool/VM are used to identify the instance on which the client is running.
	Pool, VM int
	// ExecTaskID is used to uniquely identify the program for which the client is
	// sending results.
	ExecTaskID int64
	// Hanged is set to true if the program for which we are sending results
	// was killed due to hanging.
	Hanged bool
	// Info contains information about the execution of each system call in the
	// program.
	Info ipc.ProgInfo
}

// NextExchaneRes contains the data passed from server to client namely
// programs  to execute on the VM.
type NextExchangeRes struct {
	ExecTask
}

const (
	NoTask int64 = math.MaxInt64
)

type HubConnectArgs struct {
	// Client/Key are used for authentication.
	Client string
	// The key may be a secret password or the oauth token prefixed by "Bearer ".
	Key string
	// Manager name, must start with Client.
	Manager string
	// See pkg/mgrconfig.Config.HubDomain.
	Domain string
	// Manager has started with an empty corpus and requests whole hub corpus.
	Fresh bool
	// Set of system call names supported by this manager.
	// Used to filter out programs with unsupported calls.
	Calls []string
	// Current manager corpus.
	Corpus [][]byte
}

type HubSyncArgs struct {
	// see HubConnectArgs.
	Client     string
	Key        string
	Manager    string
	NeedRepros bool
	// Programs added to corpus since last sync or connect.
	Add [][]byte
	// Hashes of programs removed from corpus since last sync or connect.
	Del []string
	// Repros found since last sync.
	Repros [][]byte
}

type HubSyncRes struct {
	// Set of inputs from other managers.
	Inputs []HubInput
	// Same as Inputs but for legacy managers that don't understand new format (remove later).
	Progs [][]byte
	// Set of repros from other managers.
	Repros [][]byte
	// Number of remaining pending programs,
	// if >0 manager should do sync again.
	More int
}

type HubInput struct {
	// Domain of the source manager.
	Domain string
	Prog   []byte
}

type RunTestPollReq struct {
	Name string
}

type RunTestPollRes struct {
	ID     int
	Bin    []byte
	Prog   []byte
	Cfg    *ipc.Config
	Opts   *ipc.ExecOpts
	Repeat int
}

type RunTestDoneArgs struct {
	Name   string
	ID     int
	Output []byte
	Info   []*ipc.ProgInfo
	Error  string
}
