// Copyright 2019 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package build

import (
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"text/template"
	"time"

	"github.com/google/syzkaller/pkg/osutil"
	"github.com/google/syzkaller/sys/targets"
)

type freebsd struct{}

const freebsdDefaultConfig = `
include "./GENERIC"

ident		SYZKALLER
options 	COVERAGE
options 	KCOV
options 	KASAN

options 	TCPHPTS
options 	RATELIMIT

options 	DIAGNOSTIC
`

const freebsdLoaderConf = `autoboot_delay="-1"
console="comconsole"
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
filemon_load="YES"

kern.ipc.tls.enable="1"
vm.panic_on_oom="1"
`

const freebsdSysctlConf = `net.inet.sctp.udp_tunneling_port=9899
net.inet.tcp.udp_tunneling_port=9811
net.inet.tcp.bb.log_auto_all=1
net.inet.tcp.bb.log_auto_ratio=1
net.inet.tcp.bb.log_auto_mode=1
vm.redzone.panic=1
`

func (ctx freebsd) build(params Params) (ImageDetails, error) {
	params.KernelDir = osutil.Abs(params.KernelDir)
	config, err := bsdEnsureConfig(params, freebsdDefaultConfig)
	if err != nil {
		return ImageDetails{}, err
	}
	if runtime.GOOS != targets.FreeBSD {
		return ctx.buildInVM(params, config)
	}
	return ctx.buildNative(params, config)
}

func (ctx freebsd) buildInVM(params Params, config []byte) (ImageDetails, error) {
	const confFile = "SYZKALLER"

	sysctlConf := freebsdSysctlConf
	if params.SysctlFile != "" {
		extraSysctl, err := os.ReadFile(params.SysctlFile)
		if err != nil {
			return ImageDetails{}, fmt.Errorf("failed to read sysctl file: %w", err)
		}
		sysctlConf += "\n" + string(extraSysctl) + "\n"
	}
	loaderConf := freebsdLoaderConf
	if params.CmdlineFile != "" {
		extraLoader, err := os.ReadFile(params.CmdlineFile)
		if err != nil {
			return ImageDetails{}, fmt.Errorf("failed to read cmdline file: %w", err)
		}
		loaderConf += "\n" + string(extraLoader) + "\n"
	}

	cpus := bsdBuildCPUs(params.BuildCPUs)
	script, err := freebsdVMBuildScript(freebsdScriptData{
		ConfFile:        confFile,
		HostSrcQuoted:   shellQuote(params.KernelDir),
		CPUs:            cpus,
		CompilerIDEntry: bsdCompilerIDEntry,
		LoaderConf:      strings.TrimSpace(loaderConf),
		SysctlConf:      strings.TrimSpace(sysctlConf),
	})
	if err != nil {
		return ImageDetails{}, err
	}
	return bsdVMBuild(params, bsdVMBuildSpec{
		ScratchGB: 40,
		// The output disk is a sparse file, so be generous: kernel.full with KASAN/COVERAGE
		// and full debug info can exceed 1 GiB and a too-small disk only fails with an opaque
		// "tar: write error" inside the guest.
		OutTarMB: 8192,
		Config:   config,
		ExpectedOutputs: map[string]string{
			"kernel.full": "obj/kernel.full",
		},
		BuildScript: script,
	})
}

type freebsdScriptData struct {
	ConfFile string
	// Absolute host path of the kernel tree, already shell-quoted.
	HostSrcQuoted   string
	CPUs            int
	CompilerIDEntry string
	LoaderConf      string
	SysctlConf      string
}

// Disk layout inside the builder VM (see buildBSDMgrConfig):
// vtbd0 - builder/userspace boot image (snapshot=on), vtbd1 - scratch, vtbd2 - src.tar,
// vtbd3 - out.tar, vtbd4 - target image that receives the kernel.
//
// The kernel is compiled from a nullfs mount of /build/src at the host KernelDir path (when that
// path is free inside the guest), so that DWARF paths and __FILE__ strings match the host tree
// as seen by syz-manager (kernel_src) for symbolization and coverage. Unlike the OpenBSD builder,
// we don't rely on -ffile-prefix-map here: FreeBSD takes kernel compiler flags from the kernel
// config (makeoptions), which is user-supplied, and injecting flags there is more intrusive than
// mirroring the path. If the mount is not possible, the build still works with /build/src paths.
var freebsdVMBuildTemplate = template.Must(template.New("freebsd-vm-build.sh").Parse(`set -eu
mkdir -p /build
newfs -U /dev/vtbd1 >/dev/null
mount -o async,noatime /dev/vtbd1 /build
mkdir -p /build/src /build/obj
tar -C /build/src -xf /dev/vtbd2
mkdir -p /build/src/sys/amd64/conf
rm -f /build/src/sys/amd64/conf/{{.ConfFile}}
cp "$1" /build/src/sys/amd64/conf/{{.ConfFile}}

SRC_DIR=/build/src
NULLFS_CLEAN_ROOT=""
HOST_SRC={{.HostSrcQuoted}}
case "$HOST_SRC" in
	*[[:space:]]*)
		;;
	/bin*|/sbin*|/lib*|/libexec*|/etc*|/boot*|/dev*|/build*|/mnt*|/proc*|/root*|/tmp*|/var*)
		;;
	/usr/bin*|/usr/sbin*|/usr/lib*|/usr/include*|/usr/share*)
		;;
	/*)
		if [ ! -e "$HOST_SRC" ]; then
			CUR="$HOST_SRC"
			while [ "$CUR" != "/" ] && [ ! -e "$CUR" ]; do
				NULLFS_CLEAN_ROOT="$CUR"
				CUR=$(dirname "$CUR")
			done
			mkdir -p "$HOST_SRC"
			if mount -t nullfs /build/src "$HOST_SRC" 2>/dev/null; then
				SRC_DIR="$HOST_SRC"
			elif [ -n "$NULLFS_CLEAN_ROOT" ]; then
				rm -rf "$NULLFS_CLEAN_ROOT"
				NULLFS_CLEAN_ROOT=""
			fi
		fi
		;;
esac

MAKEOBJDIRPREFIX=/build/obj make -C "$SRC_DIR" -j {{.CPUs}} TARGET=amd64 TARGET_ARCH=amd64 kernel-toolchain
MAKEOBJDIRPREFIX=/build/obj make -C "$SRC_DIR" -j {{.CPUs}} TARGET=amd64 TARGET_ARCH=amd64 \
	buildkernel WITH_EXTRA_TCP_STACKS= KERNCONF={{.ConfFile}}

XCC="/build/obj${SRC_DIR}/amd64.amd64/tmp/usr/bin/cc"
if [ ! -x "$XCC" ]; then
	XCC="/usr/bin/cc"
fi
KERN_OBJ_DIR="/build/obj${SRC_DIR}/amd64.amd64/sys/{{.ConfFile}}"
"$XCC" --version | head -n 1 > "${KERN_OBJ_DIR}/{{.CompilerIDEntry}}"

TARGET_PART=$(gpart show /dev/vtbd4 2>/dev/null |
	awk '$4 == "freebsd-ufs" { print "/dev/vtbd4p" $3; exit }')
if [ -z "$TARGET_PART" ] && [ -c /dev/vtbd4s1a ]; then
	TARGET_PART=/dev/vtbd4s1a
fi
if [ -z "$TARGET_PART" ] && [ -c /dev/vtbd4 ]; then
	TARGET_PART=/dev/vtbd4
fi
mkdir -p /mnt/target
mount -o noatime "$TARGET_PART" /mnt/target

chflags -R noschg /mnt/target/boot/kernel.old \
	/mnt/target/usr/lib/debug/boot/kernel \
	/mnt/target/usr/lib/debug/boot/kernel.old 2>/dev/null || true
rm -rf /mnt/target/boot/kernel.old \
	/mnt/target/usr/lib/debug/boot/kernel \
	/mnt/target/usr/lib/debug/boot/kernel.old

MAKEOBJDIRPREFIX=/build/obj make -C "$SRC_DIR" TARGET=amd64 TARGET_ARCH=amd64 \
	installkernel WITHOUT_KERNEL_SYMBOLS=yes WITH_EXTRA_TCP_STACKS= KERNCONF={{.ConfFile}} DESTDIR=/mnt/target
chflags -R noschg /mnt/target/boot/kernel.old 2>/dev/null || true
rm -rf /mnt/target/boot/kernel.old

cat > /mnt/target/boot/loader.conf.local <<'__SYZ_LOADER_EOF__'
{{.LoaderConf}}
__SYZ_LOADER_EOF__

cat >> /mnt/target/etc/sysctl.conf <<'__SYZ_SYSCTL_EOF__'
{{.SysctlConf}}
__SYZ_SYSCTL_EOF__

tar -cf /dev/vtbd3 -C "$KERN_OBJ_DIR" kernel.full {{.CompilerIDEntry}}

cd /
umount /mnt/target
if [ "$SRC_DIR" != "/build/src" ]; then
	umount "$SRC_DIR" || true
fi
if [ -n "$NULLFS_CLEAN_ROOT" ]; then
	rm -rf "$NULLFS_CLEAN_ROOT" || true
fi
umount /build
sync
sync
`))

func freebsdVMBuildScript(data freebsdScriptData) (string, error) {
	return renderBSDScript(freebsdVMBuildTemplate, data)
}

func (ctx freebsd) buildNative(params Params, config []byte) (ImageDetails, error) {
	confDir := fmt.Sprintf("%v/sys/%v/conf/", params.KernelDir, params.TargetArch)
	confFile := "SYZKALLER"

	if err := osutil.WriteFile(filepath.Join(confDir, confFile), config); err != nil {
		return ImageDetails{}, err
	}

	if _, err := osutil.RunCmd(10*time.Minute, params.KernelDir, "rm", "-rf", "obj"); err != nil {
		return ImageDetails{}, err
	}
	objPrefix := filepath.Join(params.KernelDir, "obj")
	output, err := ctx.make(params.KernelDir, objPrefix, params.BuildCPUs, "kernel-toolchain")
	if err != nil {
		return ImageDetails{}, err
	}
	if _, err := ctx.make(params.KernelDir, objPrefix, params.BuildCPUs, "buildkernel",
		"WITH_EXTRA_TCP_STACKS=", fmt.Sprintf("KERNCONF=%v", confFile)); err != nil {
		// The kernel-toolchain make target has to be built separately
		// because FreeBSD's build doesn't correctly order the two
		// targets. Its output is useful for debugging though, so
		// include it here.
		return ImageDetails{}, fmt.Errorf("%s: %w", string(output), err)
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
			return ImageDetails{}, fmt.Errorf("failed to copy %v -> %v: %w", fullSrc, fullDst, err)
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
%s
__EOF__

cat | sudo tee -a ${tmpdir}/etc/sysctl.conf <<__EOF__
%s
__EOF__

sudo umount $tmpdir
sudo mdconfig -d -u ${md#md}
`, objPrefix, params.KernelDir, confFile, freebsdLoaderConf, freebsdSysctlConf)

	if debugOut, err := osutil.RunCmd(10*time.Minute, params.OutputDir, "/bin/sh", "-c", script); err != nil {
		return ImageDetails{}, fmt.Errorf("error copying kernel: %w\n%v", err, debugOut)
	}
	return ImageDetails{}, nil
}

func (ctx freebsd) clean(params Params) error {
	if runtime.GOOS != targets.FreeBSD {
		// Ephemeral VM builds never modify params.KernelDir on the host.
		return nil
	}
	objPrefix := filepath.Join(params.KernelDir, "obj")
	_, err := ctx.make(params.KernelDir, objPrefix, params.BuildCPUs, "cleanworld")
	return err
}

func (ctx freebsd) make(kernelDir, objPrefix string, jobs int, makeArgs ...string) ([]byte, error) {
	args := append([]string{
		fmt.Sprintf("MAKEOBJDIRPREFIX=%v", objPrefix),
		"make",
		"-C", kernelDir,
		"-j", strconv.Itoa(jobs),
	}, makeArgs...)
	output, err := osutil.RunCmd(3*time.Hour, kernelDir, "sh", "-c", strings.Join(args, " "))
	return output, err
}
