// Copyright 2024 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package flatrpc

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
type ExecutingMessage = ExecutingMessageRawT
type StatsMessage = StatsMessageRawT
type CallInfo = CallInfoRawT
type Comparison = ComparisonRawT
type ProgInfo = ProgInfoRawT
type ExecResult = ExecResultRawT
