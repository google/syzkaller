// Copyright 2018 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package build

import (
	"encoding/base64"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"text/template"
	"time"

	"github.com/google/syzkaller/pkg/osutil"
)

type openbsd struct{}

func openbsdDefaultConfig(arch string) string {
	return fmt.Sprintf(`include "arch/%v/conf/GENERIC.MP"

pseudo-device kcov 1

option KQUEUE_DEBUG
option SPLASSERT_WATCH
option VFSLCKDEBUG
option WITNESS
option WITNESS_LOCKTRACE
option WITNESS_WATCH
`, arch)
}

func (ctx openbsd) build(params Params) (ImageDetails, error) {
	params.KernelDir = osutil.Abs(params.KernelDir)
	config, err := bsdEnsureConfig(params, openbsdDefaultConfig(params.TargetArch))
	if err != nil {
		return ImageDetails{}, err
	}
	if bsdBuildsInVM(params) {
		return ctx.buildInVM(params, config)
	}
	return ctx.buildNative(params, config)
}

func (ctx openbsd) buildInVM(params Params, config []byte) (ImageDetails, error) {
	if params.CmdlineFile != "" {
		return ImageDetails{}, fmt.Errorf("cmdline file is not supported for openbsd kernel builds")
	}
	const kernelName = "SYZKALLER"

	var extraSysctl string
	if params.SysctlFile != "" {
		data, err := os.ReadFile(params.SysctlFile)
		if err != nil {
			return ImageDetails{}, fmt.Errorf("failed to read sysctl file: %w", err)
		}
		extraSysctl = strings.TrimSpace(string(data))
	}
	overlayB64, err := openbsdEncodeOverlay(params.UserspaceDir)
	if err != nil {
		return ImageDetails{}, err
	}
	// OpenBSD's KERNEL_LOCK contends heavily at high vCPU counts (e.g. 14m25s at 64 vCPUs vs
	// 4m27s at 12 vCPUs), so cap VM build parallelism to 12 vCPUs.
	cpus := min(bsdBuildCPUs(params.BuildCPUs), 12)
	params.BuildCPUs = cpus

	script, err := openbsdVMBuildScript(openbsdScriptData{
		KernelName:      kernelName,
		CPUs:            cpus,
		PrefixMapLine:   openbsdPrefixMapLine(params.KernelDir),
		CompilerIDEntry: bsdCompilerIDEntry,
		OverlayB64:      overlayB64,
		ExtraSysctl:     extraSysctl,
	})
	if err != nil {
		return ImageDetails{}, err
	}
	return bsdVMBuild(params, bsdVMBuildSpec{
		ScratchGB: 10,
		OutTarMB:  8192,
		// OpenBSD's src repo includes the full base userland and LLVM (~94k files);
		// kernel builds only read sys/, so archiving just sys/ avoids untarring ~83k unrelated files on FFS.
		SourceSubdir: "sys",
		Config:       config,
		// Note: we don't extract bsd as OutputDir/kernel, the kernel is installed into the image
		// and is booted by the OpenBSD boot loader. If OutputDir/kernel existed,
		// instance.SetConfigImage would make QEMU direct-boot it, which does not work for OpenBSD.
		ExpectedOutputs: map[string]string{
			"bsd.gdb": "obj/bsd.gdb",
		},
		BuildScript: script,
	})
}

var openbsdSafePathRe = regexp.MustCompile(`^[-_A-Za-z0-9/.]+$`)

// openbsdPrefixMapLine returns a make variable assignment that remaps /build/src paths in debug
// info to the host kernel directory, or "" if the path can't be safely passed through make.
// The line is appended to the config(8)-generated kernel Makefile, after the makeoptions from
// the kernel config, so it extends COPTS instead of replacing it (passing COPTS on the make
// command line would discard the kernel config's makeoptions COPTS).
func openbsdPrefixMapLine(hostKernelDir string) string {
	if !openbsdSafePathRe.MatchString(hostKernelDir) {
		return ""
	}
	return "COPTS+= -ffile-prefix-map=/build/src=" + hostKernelDir
}

func openbsdEncodeOverlay(userspaceDir string) (string, error) {
	info, err := os.Stat(userspaceDir)
	if err != nil || !info.IsDir() {
		return "", nil
	}
	overlayDir := filepath.Join(userspaceDir, "overlay")
	if _, err := os.Stat(overlayDir); err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return "", nil
		}
		return "", fmt.Errorf("failed to stat userspace overlay: %w", err)
	}
	tmpFile, err := os.CreateTemp("", "openbsd-overlay-*.tar")
	if err != nil {
		return "", err
	}
	tmpPath := tmpFile.Name()
	tmpFile.Close()
	defer os.Remove(tmpPath)

	if err := writeKernelSourceTar(tmpPath, overlayDir, ""); err != nil {
		return "", fmt.Errorf("failed to archive userspace overlay: %w", err)
	}
	data, err := os.ReadFile(tmpPath)
	if err != nil {
		return "", err
	}
	return base64.StdEncoding.EncodeToString(data), nil
}

type openbsdScriptData struct {
	KernelName string
	CPUs       int
	// Either "" or a make variable assignment, see openbsdPrefixMapLine.
	PrefixMapLine   string
	CompilerIDEntry string
	// Base64-encoded tar of the userspace overlay, or "" if there is none.
	OverlayB64 string
	// Extra lines to append to /etc/sysctl.conf on the target image, or "".
	ExtraSysctl string
}

// Disk layout inside the builder VM (see buildBSDMgrConfig):
// sd0 - builder boot image (snapshot=on), sd1 - scratch, sd2 - src.tar, sd3 - out.tar,
// sd4 - target image that receives the kernel.
var openbsdVMBuildTemplate = template.Must(template.New("openbsd-vm-build.sh").Parse(`set -eu
if [ ! -x /usr/bin/cc ]; then
	echo "missing /usr/bin/cc in builder VM (pass builder.raw via -builder_image / kernel_builder_image)" >&2
	exit 1
fi
mkdir -p /build
printf '/ *\n' > /tmp/syz.disklabel
fdisk -iy sd1 >/dev/null
disklabel -Aw -T /tmp/syz.disklabel sd1 >/dev/null
newfs /dev/rsd1a >/dev/null
mount -o async,noatime /dev/sd1a /build
mkdir -p /build/src /build/obj
tar -C /build/src -xf /dev/rsd2c

CONF_DIR=/build/src/sys/arch/amd64/conf
COMPILE_DIR=/build/src/sys/arch/amd64/compile/{{.KernelName}}
rm -f "${CONF_DIR}/{{.KernelName}}"
cp "$1" "${CONF_DIR}/{{.KernelName}}"
mkdir -p "$COMPILE_DIR"
printf '.include "../Makefile.inc"\n' > "${COMPILE_DIR}/Makefile"

echo ` + bsdKernelBuildBegin + `
(
	cd "$COMPILE_DIR"
	export BSDSRCDIR=/build/src BSDOBJDIR=/build/obj BUILDUSER=root
	for tgt in clean obj config; do
		make -j {{.CPUs}} "$tgt"
	done
{{- if .PrefixMapLine}}
	echo '{{.PrefixMapLine}}' >> obj/Makefile
{{- end}}
	make -j {{.CPUs}} all
)
echo ` + bsdKernelBuildEnd + `

KERN_OBJ_DIR="${COMPILE_DIR}/obj"
/usr/bin/cc --version | head -n 1 > "${KERN_OBJ_DIR}/{{.CompilerIDEntry}}"

mkdir -p /mnt/target
mount -o noatime /dev/sd4a /mnt/target
install -F -m 700 "${KERN_OBJ_DIR}/bsd" /mnt/target/bsd
sha256 /mnt/target/bsd | (umask 077; sed 's,/mnt/target,,' > /mnt/target/var/db/kernel.SHA256) || true
{{if .OverlayB64 -}}
b64decode -r <<'__SYZ_OVERLAY_EOF__' | tar -C /mnt/target -xf -
{{.OverlayB64}}
__SYZ_OVERLAY_EOF__
{{end -}}
{{if .ExtraSysctl -}}
cat >> /mnt/target/etc/sysctl.conf <<'__SYZ_SYSCTL_EOF__'
{{.ExtraSysctl}}
__SYZ_SYSCTL_EOF__
{{end -}}
tar -cf /dev/rsd3c -C "$KERN_OBJ_DIR" bsd.gdb {{.CompilerIDEntry}}

cd /
umount /mnt/target
umount /build
sync
sync
`))

func openbsdVMBuildScript(data openbsdScriptData) (string, error) {
	return renderBSDScript(openbsdVMBuildTemplate, data)
}

func (ctx openbsd) buildNative(params Params, config []byte) (ImageDetails, error) {
	const kernelName = "SYZKALLER"
	confDir := fmt.Sprintf("%v/sys/arch/%v/conf", params.KernelDir, params.TargetArch)
	compileDir := fmt.Sprintf("%v/sys/arch/%v/compile/%v", params.KernelDir, params.TargetArch, kernelName)

	if err := osutil.WriteFile(filepath.Join(confDir, kernelName), config); err != nil {
		return ImageDetails{}, err
	}

	if err := osutil.MkdirAll(compileDir); err != nil {
		return ImageDetails{}, err
	}
	makefile := []byte(".include \"../Makefile.inc\"\n")
	if err := osutil.WriteFile(filepath.Join(compileDir, "Makefile"), makefile); err != nil {
		return ImageDetails{}, err
	}
	for _, tgt := range []string{"clean", "obj", "config", "all"} {
		if err := ctx.make(compileDir, params.BuildCPUs, tgt); err != nil {
			return ImageDetails{}, err
		}
	}
	for _, s := range []struct{ dir, src, dst string }{
		{compileDir, "obj/bsd", "kernel"},
		{compileDir, "obj/bsd.gdb", "obj/bsd.gdb"},
		{params.UserspaceDir, "image", "image"},
		{params.UserspaceDir, "key", "key"},
	} {
		fullSrc := filepath.Join(s.dir, s.src)
		fullDst := filepath.Join(params.OutputDir, s.dst)
		if err := osutil.CopyFile(fullSrc, fullDst); err != nil {
			return ImageDetails{}, fmt.Errorf("failed to copy %v -> %v: %w", fullSrc, fullDst, err)
		}
	}
	if params.VMType == "gce" {
		return ImageDetails{}, ctx.copyFilesToImage(
			filepath.Join(params.UserspaceDir, "overlay"), params.OutputDir)
	}
	return ImageDetails{}, nil
}

func (ctx openbsd) clean(params Params) error {
	// Building clean is fast enough and incremental builds in face of
	// changing config files don't work. Instead of optimizing for the
	// case where humans have to think, let's bludgeon it with a
	// machine.
	return nil
}

func (ctx openbsd) make(kernelDir string, jobs int, args ...string) error {
	args = append([]string{"-j", strconv.Itoa(jobs)}, args...)
	_, err := osutil.RunCmd(10*time.Minute, kernelDir, "make", args...)
	return err
}

// copyFilesToImage populates the filesystem image in outputDir with
// run-specific files. The kernel is copied as /bsd and if overlayDir
// exists, its contents are copied into corresponding files in the
// image.
//
// Ideally a user space tool capable of understanding FFS should
// interpret FFS inside the image file, but vnd(4) device would do in
// a pinch.
func (ctx openbsd) copyFilesToImage(overlayDir, outputDir string) error {
	script := fmt.Sprintf(`set -eux
OVERLAY="%s"
# Cleanup in case something failed before.
sync
doas umount /altroot || true
doas vnconfig -u vnd0 || true

doas /sbin/vnconfig vnd0 image
doas mount /dev/vnd0a /altroot
doas cp kernel /altroot/bsd
test -d "$OVERLAY" && doas cp -Rf "$OVERLAY"/. /altroot
sync
doas umount /altroot
doas vnconfig -u vnd0
`, overlayDir)
	_, err := osutil.RunCmd(10*time.Minute, outputDir, "/bin/sh", "-c", script)
	return err
}
