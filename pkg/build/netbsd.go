// Copyright 2018 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package build

import (
	"encoding/json"
	"fmt"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"time"

	"github.com/google/syzkaller/pkg/mgrconfig"
	"github.com/google/syzkaller/pkg/osutil"
	"github.com/google/syzkaller/pkg/report"
	"github.com/google/syzkaller/vm"
)

type netbsd struct{}

func (ctx netbsd) build(params *Params) error {
	const kernelName = "GENERIC_SYZKALLER"
	confDir := fmt.Sprintf("%v/sys/arch/%v/conf", params.KernelDir, params.TargetArch)
	compileDir := fmt.Sprintf("%v/sys/arch/%v/compile/obj/%v", params.KernelDir, params.TargetArch, kernelName)

	if err := osutil.WriteFile(filepath.Join(confDir, kernelName), params.Config); err != nil {
		return err
	}

	if strings.HasSuffix(params.Compiler, "clang++") {
		// Build tools before building kernel
		if _, err := osutil.RunCmd(10*time.Minute, params.KernelDir, "./build.sh", "-m", params.TargetArch,
			"-U", "-u", "-j"+strconv.Itoa(runtime.NumCPU()), "-V", "MKCTF=no",
			"-V", "MKLLVM=yes", "-V", "MKGCC=no", "-V", "HAVE_LLVM=yes", "tools"); err != nil {
			return err
		}

		// Build kernel
		if _, err := osutil.RunCmd(10*time.Minute, params.KernelDir, "./build.sh", "-m", params.TargetArch,
			"-U", "-u", "-j"+strconv.Itoa(runtime.NumCPU()), "-V", "MKCTF=no",
			"-V", "MKLLVM=yes", "-V", "MKGCC=no", "-V", "HAVE_LLVM=yes", "kernel="+kernelName); err != nil {
			return err
		}
	} else if strings.HasSuffix(params.Compiler, "g++") {
		if _, err := osutil.RunCmd(10*time.Minute, params.KernelDir, "./build.sh", "-m", params.TargetArch,
			"-U", "-u", "-j"+strconv.Itoa(runtime.NumCPU()), "-V", "MKCTF=no", "tools"); err != nil {
			return err
		}

		if _, err := osutil.RunCmd(10*time.Minute, params.KernelDir, "./build.sh", "-m", params.TargetArch,
			"-U", "-u", "-j"+strconv.Itoa(runtime.NumCPU()), "-V", "MKCTF=no", "kernel="+kernelName); err != nil {
			return err
		}
	}

	for _, s := range []struct{ dir, src, dst string }{
		{compileDir, "netbsd.gdb", "obj/netbsd.gdb"},
		{params.UserspaceDir, "image", "image"},
		{params.UserspaceDir, "key", "key"},
	} {
		fullSrc := filepath.Join(s.dir, s.src)
		fullDst := filepath.Join(params.OutputDir, s.dst)
		if err := osutil.CopyFile(fullSrc, fullDst); err != nil {
			return fmt.Errorf("failed to copy %v -> %v: %v", fullSrc, fullDst, err)
		}
	}
	return ctx.copyKernelToDisk(params.TargetArch, params.VMType, params.OutputDir,
		filepath.Join(compileDir, "netbsd"))
}

func (ctx netbsd) clean(kernelDir, targetArch string) error {
	_, err := osutil.RunCmd(10*time.Minute, kernelDir, "./build.sh", "-m", targetArch,
		"-U", "-j"+strconv.Itoa(runtime.NumCPU()), "cleandir")
	return err
}

// Copy the compiled kernel to the qemu disk image using ssh.
func (ctx netbsd) copyKernelToDisk(targetArch, vmType, outputDir, kernel string) error {
	vmConfig := `
{
	"snapshot": false,
	"mem": 1024
}`
	// Create config for booting the disk image.
	cfg := &mgrconfig.Config{
		Workdir:      outputDir,
		Image:        filepath.Join(outputDir, "image"),
		SSHKey:       filepath.Join(outputDir, "key"),
		SSHUser:      "root",
		TargetOS:     "netbsd",
		TargetArch:   targetArch,
		TargetVMArch: targetArch,
		Type:         "qemu",
		VM:           json.RawMessage([]byte(vmConfig)),
	}
	// Create a VM pool.
	pool, err := vm.Create(cfg, false)
	if err != nil {
		return fmt.Errorf("failed to create a VM Pool: %v", err)
	}
	// Create a new reporter instance.
	reporter, err := report.NewReporter(cfg)
	if err != nil {
		return fmt.Errorf("failed to create a Reporter: %v", err)
	}
	// Create a VM instance (we need only one).
	inst, err := pool.Create(0)
	if err != nil {
		return fmt.Errorf("failed to create the VM Instance: %v", err)
	}
	defer inst.Close()
	// Copy the kernel into the disk image and replace it
	kernel, err = inst.Copy(kernel)
	if err != nil {
		return fmt.Errorf("error copying the kernel: %v", err)
	}
	if kernel != "/netbsd" {
		return fmt.Errorf("kernel is copied into wrong location: %v", kernel)
	}
	commands := []string{"touch /fastboot"} // /fastboot file prevents disk check on start.
	if vmType == "gce" {
		commands = append(commands, []string{
			// We expect boot disk to be wd0a for the qemu (that's how qemu exposes -hda disk).
			// GCE exposes boot disk as sd0a.
			`sed -i 's#wd0#sd0#g' /etc/fstab`,
			// GCE provides vioif0 interface.
			`echo '!dhcpcd vioif0' > /etc/ifconfig.vioif0`,
			`echo 'mtu 1460' >> /etc/ifconfig.vioif0`,
		}...)
	}
	commands = append(commands, "sync") // Run sync so that the copied image is stored properly.
	outc, errc, err := inst.Run(time.Minute, nil, strings.Join(commands, ";"))
	if err != nil {
		return fmt.Errorf("error syncing the instance %v", err)
	}
	// Make sure that the command has executed properly.
	rep := inst.MonitorExecution(outc, errc, reporter, vm.ExitNormal)
	if rep != nil {
		return fmt.Errorf("error executing sync: %v", rep.Title)
	}
	return nil
}
