// Copyright 2024 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package declextract

import (
	"slices"
)

type Interface struct {
	Type               string
	Name               string
	IdentifyingConst   string
	Files              []string
	Func               string
	Access             string
	Subsystems         []string
	ManualDescriptions bool
	AutoDescriptions   bool
}

const (
	IfaceSyscall   = "SYSCALL"
	IfaceNetlinkOp = "NETLINK"
	IfaceIouring   = "IOURING"

	AccessUnknown = "unknown"
	AccessUser    = "user"
	AccessNsAdmin = "ns_admin"
	AccessAdmin   = "admin"
)

func (ctx *context) noteInterface(iface *Interface) {
	ctx.interfaces = append(ctx.interfaces, iface)
}

func (ctx *context) finishInterfaces() {
	for _, iface := range ctx.interfaces {
		slices.Sort(iface.Files)
		iface.Files = slices.Compact(iface.Files)
		if iface.Access == "" {
			iface.Access = AccessUnknown
		}
	}
	ctx.interfaces = sortAndDedupSlice(ctx.interfaces)
}
