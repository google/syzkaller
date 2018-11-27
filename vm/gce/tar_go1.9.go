// Copyright 2018 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

// +build !go1.10

package gce

import (
	"archive/tar"
)

func setGNUFormat(hdr *tar.Header) {
	// This is hacky but we actually need these large uids.
	// GCE understands only the old GNU tar format and prior to Go 1.10
	// there is no direct way to force tar package to use GNU format.
	// But these large numbers force tar to switch to GNU format.
	hdr.Uid = 100000000
	hdr.Gid = 100000000
}
