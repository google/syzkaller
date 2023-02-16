// Copyright 2022 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package proxyrpc

// ProxyAppInterface is the interface you need to implement.
type ProxyAppInterface interface {
	CreatePool(in CreatePoolParams, out *CreatePoolResult) error
	CreateInstance(in CreateInstanceParams, out *CreateInstanceResult) error
	Diagnose(in DiagnoseParams, out *DiagnoseReply) error
	Copy(in CopyParams, out *CopyResult) error
	Forward(in ForwardParams, out *ForwardResult) error
	RunStart(in RunStartParams, out *RunStartReply) error
	RunStop(in RunStopParams, out *RunStopReply) error
	RunReadProgress(in RunReadProgressParams, out *RunReadProgressReply) error
	Close(in CloseParams, out *CloseReply) error
	PoolLogs(in PoolLogsParam, out *PoolLogsReply) error
}

type CreatePoolParams struct {
	Debug     bool
	Param     string
	Image     string
	ImageData []byte
}

type CreatePoolResult struct {
	Count int // signal the created pool size
}

type CreateInstanceParams struct {
	Workdir     string
	Index       int
	WorkdirData map[string][]byte
}

type CreateInstanceResult struct {
	ID string // allocated instance id
}

type CopyParams struct {
	ID      string
	HostSrc string
	Data    []byte
}

type CopyResult struct {
	VMFileName string
}

type ForwardParams struct {
	ID   string
	Port int
}

type ForwardResult struct {
	ManagerAddress string
}

type RunStartParams struct {
	ID      string
	Command string
}

type RunStartReply struct {
	RunID string
}

type RunStopParams struct {
	ID    string
	RunID string
}

type RunStopReply struct {
}

type RunReadProgressParams struct {
	ID    string
	RunID string
}

type RunReadProgressReply struct {
	StdoutChunk     string
	StderrChunk     string
	ConsoleOutChunk string
	Error           string
	Finished        bool
}

type CloseParams struct {
	ID string
}

type CloseReply struct {
}

type DiagnoseParams struct {
	ID          string
	ReasonTitle string
}

type DiagnoseReply struct {
	Diagnosis string
}

type PoolLogsParam struct {
}

type PoolLogsReply struct {
	Log string
	// Verbosity follows pkg/log rules.
	// Messages with Verbosity 0 are printed by default.
	// The higher is this value - the lower is importance of the message.
	Verbosity int
}
