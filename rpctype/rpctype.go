// Copyright 2015 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

// Package rpctype contains types of message passed via net/rpc connections
// between various parts of the system.
package rpctype

type RpcInput struct {
	Call      string
	Prog      []byte
	CallIndex int
	Signal    []uint32
	Cover     []uint32
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
	Name  string
	Kcov  bool
	Calls []string
}

type NewInputArgs struct {
	Name string
	RpcInput
}

type PollArgs struct {
	Name      string
	MaxSignal []uint32
	Stats     map[string]uint64
}

type PollRes struct {
	Candidates []RpcCandidate
	NewInputs  []RpcInput
	MaxSignal  []uint32
}

type HubConnectArgs struct {
	Name   string
	Key    string
	Fresh  bool
	Calls  []string
	Corpus [][]byte
}

type HubSyncArgs struct {
	Name string
	Key  string
	Add  [][]byte
	Del  []string
}

type HubSyncRes struct {
	Inputs [][]byte
}
