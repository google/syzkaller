// Copyright 2017 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

// +build !appengine

package osutil

import (
	"io/ioutil"
	"path/filepath"
	"syscall"
	"unsafe"
)

// UmountAll recurusively unmounts all mounts in dir.
func UmountAll(dir string) {
	files, _ := ioutil.ReadDir(dir)
	for _, f := range files {
		name := filepath.Join(dir, f.Name())
		if f.IsDir() {
			UmountAll(name)
		}
		fn := []byte(name + "\x00")
		syscall.Syscall(syscall.SYS_UMOUNT2, uintptr(unsafe.Pointer(&fn[0])), syscall.MNT_FORCE, 0)
	}
}
