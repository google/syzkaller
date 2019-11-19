// Copyright 2017 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

// +build !appengine

package osutil

import (
	"fmt"
	"io/ioutil"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"
	"unsafe"
)

// RemoveAll is similar to os.RemoveAll, but can handle more cases.
func RemoveAll(dir string) error {
	files, _ := ioutil.ReadDir(dir)
	for _, f := range files {
		name := filepath.Join(dir, f.Name())
		if f.IsDir() {
			RemoveAll(name)
		}
		fn := []byte(name + "\x00")
		syscall.Syscall(syscall.SYS_UMOUNT2, uintptr(unsafe.Pointer(&fn[0])), syscall.MNT_FORCE, 0)
	}
	if err := os.RemoveAll(dir); err != nil {
		removeImmutable(dir)
		return os.RemoveAll(dir)
	}
	return nil
}

func SystemMemorySize() uint64 {
	var info syscall.Sysinfo_t
	syscall.Sysinfo(&info)
	return uint64(info.Totalram) //nolint:unconvert
}

func removeImmutable(fname string) error {
	// Reset FS_XFLAG_IMMUTABLE/FS_XFLAG_APPEND.
	fd, err := syscall.Open(fname, syscall.O_RDONLY, 0)
	if err != nil {
		return err
	}
	defer syscall.Close(fd)
	flags := 0
	var cmd uint64 // FS_IOC_SETFLAGS
	switch runtime.GOARCH {
	case "386", "arm":
		cmd = 1074030082
	case "amd64", "arm64":
		cmd = 1074292226
	case "ppc64le", "mips64le":
		cmd = 2148034050
	default:
		panic("unknown arch")
	}
	_, _, errno := syscall.Syscall(syscall.SYS_IOCTL, uintptr(fd), uintptr(cmd), uintptr(unsafe.Pointer(&flags)))
	return errno
}

func Sandbox(cmd *exec.Cmd, user, net bool) error {
	enabled, uid, gid, err := initSandbox()
	if err != nil || !enabled {
		return err
	}
	if cmd.SysProcAttr == nil {
		cmd.SysProcAttr = new(syscall.SysProcAttr)
	}
	if net {
		cmd.SysProcAttr.Cloneflags = syscall.CLONE_NEWNET | syscall.CLONE_NEWIPC |
			syscall.CLONE_NEWNS | syscall.CLONE_NEWUTS | syscall.CLONE_NEWPID
	}
	if user {
		cmd.SysProcAttr.Credential = &syscall.Credential{
			Uid: uid,
			Gid: gid,
		}
	}
	return nil
}

func SandboxChown(file string) error {
	enabled, uid, gid, err := initSandbox()
	if err != nil || !enabled {
		return err
	}
	return os.Chown(file, int(uid), int(gid))
}

var (
	sandboxOnce     sync.Once
	sandboxEnabled  = true
	sandboxUsername = "syzkaller"
	sandboxUID      = ^uint32(0)
	sandboxGID      = ^uint32(0)
)

func initSandbox() (bool, uint32, uint32, error) {
	sandboxOnce.Do(func() {
		if syscall.Getuid() != 0 || os.Getenv("SYZ_DISABLE_SANDBOXING") == "yes" {
			sandboxEnabled = false
			return
		}
		uid, err := usernameToID("-u")
		if err != nil {
			return
		}
		gid, err := usernameToID("-g")
		if err != nil {
			return
		}
		sandboxUID = uid
		sandboxGID = gid
	})
	if sandboxEnabled && sandboxUID == ^uint32(0) {
		return false, 0, 0, fmt.Errorf("user %q is not found, can't sandbox command", sandboxUsername)
	}
	return sandboxEnabled, sandboxUID, sandboxGID, nil
}

func usernameToID(what string) (uint32, error) {
	out, err := RunCmd(time.Minute, "", "id", what, sandboxUsername)
	if err != nil {
		return 0, err
	}
	str := strings.Trim(string(out), " \t\n")
	id, err := strconv.ParseUint(str, 10, 32)
	if err != nil {
		return 0, err
	}
	return uint32(id), nil
}

func setPdeathsig(cmd *exec.Cmd) {
	if cmd.SysProcAttr == nil {
		cmd.SysProcAttr = new(syscall.SysProcAttr)
	}
	cmd.SysProcAttr.Pdeathsig = syscall.SIGKILL
	// We will kill the whole process group.
	cmd.SysProcAttr.Setpgid = true
}

func killPgroup(cmd *exec.Cmd) {
	syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL)
}

func prolongPipe(r, w *os.File) {
	for sz := 128 << 10; sz <= 2<<20; sz *= 2 {
		syscall.Syscall(syscall.SYS_FCNTL, w.Fd(), syscall.F_SETPIPE_SZ, uintptr(sz))
	}
}
