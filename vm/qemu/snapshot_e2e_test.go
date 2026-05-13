// Copyright 2026 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package qemu_test

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"

	flatbuffers "github.com/google/flatbuffers/go"
	"github.com/google/syzkaller/pkg/flatrpc"
	"github.com/google/syzkaller/pkg/mgrconfig"
	"github.com/google/syzkaller/pkg/report"
	"github.com/google/syzkaller/prog"
	_ "github.com/google/syzkaller/sys"
	"github.com/google/syzkaller/vm"
)

func TestSnapshotE2E(t *testing.T) {
	kernel := os.Getenv("SYZ_KERNEL")
	image := os.Getenv("SYZ_IMAGE")
	if kernel == "" || image == "" {
		t.Skip("SYZ_KERNEL or SYZ_IMAGE not set, skipping E2E test")
	}

	templateDir := setupTemplateDir(t)
	cfg := createConfig(t, kernel, image, templateDir)

	reporter, err := report.NewReporter(cfg)
	if err != nil {
		t.Fatal(err)
	}

	pool, err := vm.Create(cfg, true) // enable debug output
	if err != nil {
		t.Fatal(err)
	}
	defer pool.Close()

	inst, err := pool.Create(context.Background(), 0)
	if err != nil {
		t.Fatal(err)
	}
	defer inst.Close()

	executorBin, err := inst.Copy(cfg.ExecutorBin)
	if err != nil {
		t.Fatalf("failed to copy executor: %v", err)
	}

	startExecutor(t, inst, reporter, executorBin)
	doHandshake(t, inst)
	output := runTestProgram(t, cfg.Target, inst)

	t.Logf("Output: %s", output)
}

func setupTemplateDir(t *testing.T) string {
	templateDir := filepath.Join(t.TempDir(), "template")
	err := os.MkdirAll(filepath.Join(templateDir, "virtfs"), 0755)
	if err != nil {
		t.Fatal(err)
	}
	err = os.WriteFile(filepath.Join(templateDir, "cdrom"), []byte("dummy cdrom"), 0644)
	if err != nil {
		t.Fatal(err)
	}
	return templateDir
}

func createConfig(t *testing.T, kernel, image, templateDir string) *mgrconfig.Config {
	qemuArgs := `-enable-kvm -machine q35,nvdimm=on,accel=kvm,kernel-irqchip=split -m 1536M,slots=4,maxmem=16G -device ioh3420,id=pcie.1,chassis=1 -device intel-iommu,intremap=on,device-iotlb=on -vga virtio -usb -usbdevice tablet -object memory-backend-file,id=pmem1,share=off,mem-path=/dev/zero,size=64M -device nvdimm,id=nvdimm1,memdev=pmem1 -net nic,model=e1000e -cdrom {{TEMPLATE}}/cdrom -virtfs local,path={{TEMPLATE}}/virtfs,mount_tag=syz,security_model=mapped-xattr,id=syz,readonly=on`

	// Use a map to avoid zero-value overrides during marshaling.
	qemuCfg := map[string]any{
		"kernel":    kernel,
		"qemu_args": qemuArgs,
		"cmdline":   "root=/dev/sda1 loop.max_loop=1 dummy_hcd.num=1 netrom.nr_ndevs=1 rose.rose_ndevs=1",
		"mem":       1536,
		"count":     1,
		"cpu":       1,
		"snapshot":  true,
	}

	vmCfg, err := json.Marshal(qemuCfg)
	if err != nil {
		t.Fatal(err)
	}

	cfg := mgrconfig.DefaultValues()
	cfg.RawTarget = "linux/amd64"
	cfg.Workdir = t.TempDir()
	cfg.WorkdirTemplate = templateDir
	cfg.Type = "qemu"
	cfg.Image = image
	cfg.Snapshot = true
	cfg.VM = vmCfg
	cfg.Syzkaller = "/syzkaller/gopath/src/github.com/google/syzkaller"
	cfg.SSHKey = "../../assets/id_rsa"

	// SetTargets must be called before Complete.
	if err := mgrconfig.SetTargets(cfg); err != nil {
		t.Fatal(err)
	}

	// Complete the config to resolve binary paths.
	if err := mgrconfig.Complete(cfg); err != nil {
		t.Fatal(err)
	}
	return cfg
}

func startExecutor(t *testing.T, inst *vm.Instance, reporter *report.Reporter, executorBin string) {
	cmd := fmt.Sprintf("nohup %v exec snapshot 1>/dev/null 2>/dev/kmsg </dev/null &", executorBin)
	ctxTimeout, cancel := context.WithTimeout(context.Background(), time.Hour)
	defer cancel()
	if _, _, err := inst.Run(ctxTimeout, reporter, cmd); err != nil {
		t.Fatalf("failed to start executor: %v", err)
	}
}

func doHandshake(t *testing.T, inst *vm.Instance) {
	msg := flatrpc.SnapshotHandshakeT{
		CoverEdges:       false,
		Kernel64Bit:      true,
		Slowdown:         1,
		SyscallTimeoutMs: 100,
		ProgramTimeoutMs: 1000,
		Features:         0,
		EnvFlags:         flatrpc.ExecEnvSandboxNone,
		SandboxArg:       0,
	}
	builder := flatbuffers.NewBuilder(0)
	builder.Finish(msg.Pack(builder))

	err := inst.SetupSnapshot(builder.FinishedBytes())
	if err != nil {
		t.Fatalf("SetupSnapshot failed: %v", err)
	}
}

func runTestProgram(t *testing.T, target *prog.Target, inst *vm.Instance) []byte {
	p, err := target.Deserialize([]byte("getpid()"), prog.Strict)
	if err != nil {
		t.Fatalf("failed to deserialize program: %v", err)
	}
	progData, err := p.SerializeForExec()
	if err != nil {
		t.Fatalf("failed to serialize program for exec: %v", err)
	}

	reqMsg := flatrpc.SnapshotRequestT{
		ExecFlags: 0,
		NumCalls:  1,
		ProgData:  progData,
	}
	builder := flatbuffers.NewBuilder(0)
	builder.Finish(reqMsg.Pack(builder))

	_, output, err := inst.RunSnapshot(builder.FinishedBytes())
	if err != nil {
		t.Fatalf("RunSnapshot failed: %v", err)
	}
	return output
}
