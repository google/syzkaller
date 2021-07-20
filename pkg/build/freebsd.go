// Copyright 2019 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package build

import (
	"fmt"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"time"

	"github.com/google/syzkaller/pkg/osutil"
)

type freebsd struct{}

func (ctx freebsd) build(params Params) (ImageDetails, error) {
	confDir := fmt.Sprintf("%v/sys/%v/conf/", params.KernelDir, params.TargetArch)
	confFile := "SYZKALLER"

	config := params.Config
	if config == nil {
		config = []byte(`
include "./GENERIC"

ident		SYZKALLER
options 	COVERAGE
options 	KCOV
options 	KASAN

options 	TCPHPTS
options 	RATELIMIT

options 	DEBUG_VFS_LOCKS
options 	DIAGNOSTIC
`)
	}
	if err := osutil.WriteFile(filepath.Join(confDir, confFile), config); err != nil {
		return ImageDetails{}, err
	}

	objPrefix := filepath.Join(params.KernelDir, "obj")
	if err := ctx.make(params.KernelDir, objPrefix, "kernel-toolchain", "-DNO_CLEAN"); err != nil {
		return ImageDetails{}, err
	}
	if err := ctx.make(params.KernelDir, objPrefix, "buildkernel", "WITH_EXTRA_TCP_STACKS=",
		fmt.Sprintf("KERNCONF=%v", confFile)); err != nil {
		return ImageDetails{}, err
	}

	kernelObjDir := filepath.Join(objPrefix, params.KernelDir,
		fmt.Sprintf("%v.%v", params.TargetArch, params.TargetArch), "sys", confFile)
	for _, s := range []struct{ dir, src, dst string }{
		{params.UserspaceDir, "image", "image"},
		{params.UserspaceDir, "key", "key"},
		{kernelObjDir, "kernel.full", "obj/kernel.full"},
	} {
		fullSrc := filepath.Join(s.dir, s.src)
		fullDst := filepath.Join(params.OutputDir, s.dst)
		if err := osutil.CopyFile(fullSrc, fullDst); err != nil {
			return ImageDetails{}, fmt.Errorf("failed to copy %v -> %v: %v", fullSrc, fullDst, err)
		}
	}

	script := fmt.Sprintf(`
set -eux
md=$(sudo mdconfig -a -t vnode image)
partn=$(gpart show /dev/${md} | awk '/freebsd-ufs/{print $3}' | head -n 1)
tmpdir=$(mktemp -d)
sudo mount /dev/${md}p${partn} $tmpdir

sudo MAKEOBJDIRPREFIX=%s make -C %s installkernel WITH_EXTRA_TCP_STACKS= KERNCONF=%s DESTDIR=$tmpdir

cat | sudo tee ${tmpdir}/boot/loader.conf.local <<__EOF__
ipsec_load="YES"
pf_load="YES"
sctp_load="YES"
tcp_bbr_load="YES"
tcp_rack_load="YES"
sem_load="YES"
mqueuefs_load="YES"
cryptodev_load="YES"
cc_cdg_load="YES"
cc_chd_load="YES"
cc_cubic_load="YES"
cc_dctcp_load="YES"
cc_hd_load="YES"
cc_htcp_load="YES"
cc_vegas_load="YES"

kern.ipc.tls.enable="1"
vm.panic_on_oom="1"
__EOF__

cat | sudo tee -a ${tmpdir}/etc/sysctl.conf <<__EOF__
net.inet.sctp.udp_tunneling_port=9899
net.inet.tcp.udp_tunneling_port=9811
vm.redzone.panic=1
__EOF__

sudo umount $tmpdir
sudo mdconfig -d -u ${md#md}
`, objPrefix, params.KernelDir, confFile)

	if debugOut, err := osutil.RunCmd(10*time.Minute, params.OutputDir, "/bin/sh", "-c", script); err != nil {
		return ImageDetails{}, fmt.Errorf("error copying kernel: %v\n%v", err, debugOut)
	}
	return ImageDetails{}, nil
}

func (ctx freebsd) clean(kernelDir, targetArch string) error {
	objPrefix := filepath.Join(kernelDir, "obj")
	return ctx.make(kernelDir, objPrefix, "cleanworld")
}

func (ctx freebsd) make(kernelDir, objPrefix string, makeArgs ...string) error {
	args := append([]string{
		fmt.Sprintf("MAKEOBJDIRPREFIX=%v", objPrefix),
		"make",
		"-C", kernelDir,
		"-j", strconv.Itoa(runtime.NumCPU()),
	}, makeArgs...)
	_, err := osutil.RunCmd(3*time.Hour, kernelDir, "sh", "-c", strings.Join(args, " "))
	return err
}
