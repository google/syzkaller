// Copyright 2018 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

//go:build go1.10
// +build go1.10

package gce

import (
	"archive/tar"
)

func setGNUFormat(hdr *tar.Header) {
	hdr.Format = tar.FormatGNU
}
