// Copyright 2020 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

// +build amd64 386 arm64 arm mips64le ppc64le riscv64

package prog

import "encoding/binary"

var HostEndian = binary.LittleEndian
