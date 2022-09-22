// Copyright 2022 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package proxyapp

//go:generate ../../tools/mockery.sh --name subProcessCmd --exported
//go:generate ../../tools/mockery.sh --name ProxyAppInterface -r

import (
	"github.com/google/syzkaller/vm/proxyapp/proxyrpc"
)

var (
	_ subProcessCmd              = &mocks.SubProcessCmd{}
	_ proxyrpc.ProxyAppInterface = &mocks.ProxyAppInterface{}
)
