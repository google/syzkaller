// Copyright 2017 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package adb

// ppc64le does not have golang.org/x/sys/unix.TCGETS2 const required for console.go.
// so adb is currently turned off on ppc64le, this empty file is just to make build succeed.
