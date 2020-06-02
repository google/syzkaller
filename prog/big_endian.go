// Copyright 2020 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

// +build s390x

package prog

import "encoding/binary"

var HostEndian = binary.BigEndian
