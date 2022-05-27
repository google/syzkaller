// Copyright 2021 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

//go:build linux
// +build linux

package osutil

import (
	"fmt"
	"os"

	"golang.org/x/sys/unix"
)

// In the case of Linux, we can just use the memfd_create syscall.
func CreateSharedMemFile(size int) (f *os.File, err error) {
	// The name is actually irrelevant and can even be the same for all such files.
	fd, err := unix.MemfdCreate("syz-shared-mem", unix.MFD_CLOEXEC)
	if err != nil {
		err = fmt.Errorf("failed to do memfd_create: %v", err)
		return
	}
	f = os.NewFile(uintptr(fd), fmt.Sprintf("/proc/self/fd/%d", fd))
	return
}

func CloseSharedMemFile(f *os.File) error {
	return f.Close()
}
