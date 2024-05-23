// Copyright 2024 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package flatrpc

import (
	"slices"
	"syscall"
)

const AllFeatures = ^Feature(0)

// Flatbuffers compiler adds T suffix to object API types, which are actual structs representing types.
// This leads to non-idiomatic Go code, e.g. we would have to use []FileInfoT in Go code.
// So we use Raw suffix for all flatbuffers tables and rename object API types here to idiomatic names.
type ConnectRequest = ConnectRequestRawT
type ConnectReply = ConnectReplyRawT
type InfoRequest = InfoRequestRawT
type InfoReply = InfoReplyRawT
type FileInfo = FileInfoRawT
type GlobInfo = GlobInfoRawT
type FeatureInfo = FeatureInfoRawT
type HostMessages = HostMessagesRawT
type HostMessage = HostMessageRawT
type ExecutorMessages = ExecutorMessagesRawT
type ExecutorMessage = ExecutorMessageRawT
type ExecRequest = ExecRequestRawT
type SignalUpdate = SignalUpdateRawT
type StartLeakChecks = StartLeakChecksRawT
type ExecutingMessage = ExecutingMessageRawT
type CallInfo = CallInfoRawT
type Comparison = ComparisonRawT
type ExecOpts = ExecOptsRawT
type ProgInfo = ProgInfoRawT
type ExecResult = ExecResultRawT

func (pi *ProgInfo) Clone() *ProgInfo {
	if pi == nil {
		return nil
	}
	ret := *pi
	ret.Extra = ret.Extra.clone()
	ret.Calls = make([]*CallInfo, len(pi.Calls))
	for i, call := range pi.Calls {
		ret.Calls[i] = call.clone()
	}
	return &ret
}

func (ci *CallInfo) clone() *CallInfo {
	if ci == nil {
		return nil
	}
	ret := *ci
	ret.Signal = slices.Clone(ret.Signal)
	ret.Cover = slices.Clone(ret.Cover)
	ret.Comps = slices.Clone(ret.Comps)
	return &ret
}

func EmptyProgInfo(calls int) *ProgInfo {
	info := &ProgInfo{}
	for i := 0; i < calls; i++ {
		info.Calls = append(info.Calls, &CallInfo{
			// Store some unsuccessful errno in the case we won't get any result.
			// It also won't have CallExecuted flag, but it's handy to make it
			// look failed based on errno as well.
			Error: int32(syscall.ENOSYS),
		})
	}
	return info
}

func (eo ExecOpts) MergeFlags(diff ExecOpts) ExecOpts {
	ret := eo
	ret.ExecFlags |= diff.ExecFlags
	ret.EnvFlags |= diff.EnvFlags
	return ret
}
