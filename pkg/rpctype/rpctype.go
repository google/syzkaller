// Copyright 2015 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

// Package rpctype contains types of message passed via net/rpc connections
// between various parts of the system.
package rpctype

type RpcInput struct {
	Call   string
	Prog   []byte
	Signal []uint32
	Cover  []uint32
}

type RpcCandidate struct {
	Prog      []byte
	Minimized bool
}

type ConnectArgs struct {
	Name string
}

type ConnectRes struct {
	Prios        [][]float32
	Inputs       []RpcInput
	MaxSignal    []uint32
	Candidates   []RpcCandidate
	EnabledCalls string
	NeedCheck    bool
}

type CheckArgs struct {
	Name           string
	Kcov           bool
	Leak           bool
	Fault          bool
	UserNamespaces bool
	CompsSupported bool
	Calls          []string
	FuzzerGitRev   string
	FuzzerSyzRev   string
	ExecutorGitRev string
	ExecutorSyzRev string
	ExecutorArch   string
}

type NewInputArgs struct {
	Name string
	RpcInput
}

type PollArgs struct {
	Name           string
	NeedCandidates bool
	MaxSignal      []uint32
	Stats          map[string]uint64
}

type PollRes struct {
	Candidates []RpcCandidate
	NewInputs  []RpcInput
	MaxSignal  []uint32
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
