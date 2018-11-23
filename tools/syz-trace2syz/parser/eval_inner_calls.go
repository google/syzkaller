// Copyright 2018 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package parser

import (
	"bytes"
	"encoding/binary"
	"net"

	"github.com/google/syzkaller/pkg/log"
	"github.com/google/syzkaller/prog"
)

func EvalCalls(target *prog.Target, call *Call) uint64 {
	switch call.CallName {
	case "htons":
		return htons(target, call)
	case "htonl":
		return htonl(target, call)
	case "inet_addr":
		return inetAddr(call)
	case "inet_pton":
		return inetPton(call)
	case "if_nametoindex":
		return ifnametoindex(call)
	case "makedev":
		return makedev(target, call)
	case "KERNEL_VERSION":
		return kernelVersion(target, call)
	case "_IOC":
		return ioc(target, call)
	case "_IO":
		return io(target, call)
	case "QCMD":
		return qcmd(target, call)
	default:
		log.Fatalf("Unsupported call: %s", call.CallName)
	}
	return 0
}

func checkInnerCall(name string, expectedArgs, numArgs int) {
	if numArgs == expectedArgs {
		return
	}
	log.Fatalf("%s expects %d arguments. Got: %d", name, expectedArgs, numArgs)
}

func inetAddr(call *Call) uint64 {
	var ip string
	checkInnerCall(call.CallName, 1, len(call.Args))
	switch a := call.Args[0].(type) {
	case *BufferType:
		ip = string(bytes.Trim([]byte(a.Val), "\x00"))
	default:
		log.Fatalf("ip expected to be buffer type. Got: %#v", a)
	}
	return uint64(binary.BigEndian.Uint32(net.ParseIP(ip).To4()))
}

func htons(target *prog.Target, call *Call) uint64 {
	checkInnerCall(call.CallName, 1, len(call.Args))
	var b uint16
	switch a := call.Args[0].(type) {
	case Expression:
		b = uint16(a.Eval(target))
		b = (b&0xff)<<8 | (b&0xff00)>>8
	}

	return uint64(b)
}

func htonl(target *prog.Target, call *Call) uint64 {
	checkInnerCall(call.CallName, 1, len(call.Args))
	var b uint32
	switch a := call.Args[0].(type) {
	case Expression:
		b = uint32(a.Eval(target))
	}
	b = (b&0xff)<<24 | (b&0xff00)<<8 | (b&0xff0000)>>8 | (b&0xff000000)>>24
	return uint64(b)
}

func inetPton(call *Call) uint64 {
	checkInnerCall(call.CallName, 3, len(call.Args))
	var ip string
	switch a := call.Args[1].(type) {
	case *BufferType:
		ip = string(bytes.Trim([]byte(a.Val), "\x00"))
	}
	dst := net.ParseIP(ip).To16()
	if binary.BigEndian.Uint64(dst[:8]) == 0 {
		return binary.BigEndian.Uint64(dst[8:])
	}
	return binary.BigEndian.Uint64(dst)
}

func makedev(target *prog.Target, call *Call) uint64 {
	checkInnerCall(call.CallName, 2, len(call.Args))
	var major, minor, id int64

	arg1 := call.Args[0].(Expression)
	arg2 := call.Args[1].(Expression)
	major = int64(arg1.Eval(target))
	minor = int64(arg2.Eval(target))

	id = ((minor & 0xff) | ((major & 0xfff) << 8) | ((minor & ^0xff) << 12) | ((major & ^0xfff) << 32))
	return uint64(id)
}

func ifnametoindex(call *Call) uint64 {
	return 0
}

func kernelVersion(target *prog.Target, call *Call) uint64 {
	checkInnerCall(call.CallName, 3, len(call.Args))
	a1 := call.Args[0].(Expression)
	a2 := call.Args[1].(Expression)
	a3 := call.Args[2].(Expression)
	return (a1.Eval(target) << 16) + (a2.Eval(target) << 8) + a3.Eval(target)
}

func ioc(target *prog.Target, call *Call) uint64 {
	checkInnerCall(call.CallName, 4, len(call.Args))
	dir := call.Args[0].(Expression).Eval(target) << target.ConstMap["_IOC_DIRSHIFT"]
	typ := call.Args[1].(Expression).Eval(target) << target.ConstMap["_IOC_TYPESHIFT"]
	nr := call.Args[2].(Expression).Eval(target) << target.ConstMap["_IOC_NRSHIFT"]
	sz := call.Args[3].(Expression).Eval(target) << target.ConstMap["_IOC_SIZESHIFT"]
	return dir | typ | nr | sz
}

func io(target *prog.Target, call *Call) uint64 {
	checkInnerCall(call.CallName, 3, len(call.Args))
	dir := target.ConstMap["_IOC_NONE"] << target.ConstMap["_IOC_DIRSHIFT"]
	typ := call.Args[1].(Expression).Eval(target) << target.ConstMap["_IOC_TYPESHIFT"]
	nr := call.Args[2].(Expression).Eval(target) << target.ConstMap["_IOC_NRSHIFT"]
	return dir | typ | nr
}

func qcmd(target *prog.Target, call *Call) uint64 {
	checkInnerCall(call.CallName, 2, len(call.Args))
	qcmd := call.Args[0].(Expression).Eval(target)
	qtype := call.Args[1].(Expression).Eval(target)
	return (qcmd << target.ConstMap["SUBCMDSHIFT"]) | (qtype & target.ConstMap["SUBCMDMASK"])
}
