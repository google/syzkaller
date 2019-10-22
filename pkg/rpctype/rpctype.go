// Copyright 2015 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

// Package rpctype contains types of message passed via net/rpc connections
// between various parts of the system.
package rpctype

import (
	"github.com/google/syzkaller/pkg/host"
	"github.com/google/syzkaller/pkg/ipc"
	"github.com/google/syzkaller/pkg/signal"
)

type RPCInput struct {
	Call   string
	Prog   []byte
	Signal signal.Serial
	Cover  []uint32
}

type RPCCandidate struct {
	Prog      []byte
	Minimized bool
	Smashed   bool
}

type ConnectArgs struct {
	Name string
}

type ConnectRes struct {
	EnabledCalls     []int
	GitRevision      string
	TargetRevision   string
	AllSandboxes     bool
	CheckResult      *CheckArgs
	MemoryLeakFrames []string
	DataRaceFrames   []string
}

type CheckArgs struct {
	Name          string
	Error         string
	EnabledCalls  map[string][]int
	DisabledCalls map[string][]SyscallReason
	Features      *host.Features
}

type SyscallReason struct {
	ID     int
	Reason string
}

type NewInputArgs struct {
	Name string
	RPCInput
}

type PollArgs struct {
	Name           string
	NeedCandidates bool
	MaxSignal      signal.Serial
	Stats          map[string]uint64
}

type PollRes struct {
	Candidates []RPCCandidate
	NewInputs  []RPCInput
	MaxSignal  signal.Serial
}

type HubConnectArgs struct {
	// Client/Key are used for authentication.
	Client string
	Key    string
	// Manager name, must start with Client.
	Manager string
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
	// Set of programs from other managers.
	Progs [][]byte
	// Set of repros from other managers.
	Repros [][]byte
	// Number of remaining pending programs,
	// if >0 manager should do sync again.
	More int
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
