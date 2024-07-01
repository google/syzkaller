// Copyright 2024 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package flatrpc

import (
	"fmt"
	"slices"
	"sync/atomic"
	"syscall"
	"unsafe"

	"github.com/google/syzkaller/prog"
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
type StateRequest = StateRequestRawT
type SignalUpdate = SignalUpdateRawT
type CorpusTriaged = CorpusTriagedRawT
type ExecutingMessage = ExecutingMessageRawT
type CallInfo = CallInfoRawT
type Comparison = ComparisonRawT
type ExecOpts = ExecOptsRawT
type ProgInfo = ProgInfoRawT
type ExecResult = ExecResultRawT
type StateResult = StateResultRawT

func init() {
	var req ExecRequest
	if prog.MaxPids > unsafe.Sizeof(req.Avoid)*8 {
		panic("all procs won't fit ito ExecRequest.Avoid")
	}
}

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

func SandboxToFlags(sandbox string) (ExecEnv, error) {
	switch sandbox {
	case "none":
		return ExecEnvSandboxNone, nil
	case "setuid":
		return ExecEnvSandboxSetuid, nil
	case "namespace":
		return ExecEnvSandboxNamespace, nil
	case "android":
		return ExecEnvSandboxAndroid, nil
	default:
		return 0, fmt.Errorf("sandbox must contain one of none/setuid/namespace/android")
	}
}

func FlagsToSandbox(flags ExecEnv) string {
	if flags&ExecEnvSandboxNone != 0 {
		return "none"
	} else if flags&ExecEnvSandboxSetuid != 0 {
		return "setuid"
	} else if flags&ExecEnvSandboxNamespace != 0 {
		return "namespace"
	} else if flags&ExecEnvSandboxAndroid != 0 {
		return "android"
	}
	panic("no sandbox flags present")
}

func (hdr *SnapshotHeaderT) UpdateState(state SnapshotState) {
	atomic.StoreUint64((*uint64)(unsafe.Pointer(&hdr.State)), uint64(state))
}

func (hdr *SnapshotHeaderT) LoadState() SnapshotState {
	return SnapshotState(atomic.LoadUint64((*uint64)(unsafe.Pointer(&hdr.State))))
}
