// Copyright 2015 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

// Package rpctype contains types of message passed via net/rpc connections
// between various parts of the system.
package rpctype

type RpcInput struct {
	Call      string
	Prog      []byte
	CallIndex int
	Cover     []uint32
}

type MasterConnectArgs struct {
	Name string
	Http string
}

type MasterConnectRes struct {
	Http string
}

type NewMasterInputArgs struct {
	Name string
	Prog []byte
}

type MasterPollArgs struct {
	Name string
}

type MasterPollRes struct {
	Inputs [][]byte
}

type ManagerConnectArgs struct {
	Name string
}

type ManagerConnectRes struct {
	Prios [][]float32
}

type NewManagerInputArgs struct {
	Name string
	RpcInput
}

type ManagerPollArgs struct {
	Name string
}

type ManagerPollRes struct {
	Candidates [][]byte
	NewInputs  []RpcInput
}
