// Copyright 2019 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

// syz-testbuild tests kernel build/boot on releases as it will be done by pkg/bisect.
// This allows to ensure that, for example, a change to kernel config won't break
// build/boot on older releases and consequently won't break bisection process.
// The binary needs to run under root because it creates images.
// The kernel checkout given to the tool will be cleaned and used for in-tree builds.
// Example invocation:
//
//	sudo syz-testbuild -kernel_src $LINUX_CHECKOUT \
//		-config dashboard/config/upstream-kasan.config \
//		-sysctl dashboard/config/upstream.sysctl \
//		-cmdline dashboard/config/upstream-apparmor.cmdline \
//		-userspace $WHEEZY_USERSPACE \
//		-bisect_bin $BISECT_BIN
//
// A suitable wheezy userspace can be downloaded from:
// https://storage.googleapis.com/syzkaller/wheezy.tar.gz
// A set of binaries required for bisection (older compilers) can be downloaded from:
// https://storage.googleapis.com/syzkaller/bisect_bin.tar.gz
package main

import (
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"log"
	"os"
	"runtime"

	"github.com/google/syzkaller/pkg/build"
	"github.com/google/syzkaller/pkg/instance"
	"github.com/google/syzkaller/pkg/mgrconfig"
	"github.com/google/syzkaller/pkg/osutil"
	"github.com/google/syzkaller/pkg/tool"
	"github.com/google/syzkaller/pkg/vcs"
)

var (
	flagOS            = flag.String("os", runtime.GOOS, "OS to test")
	flagArch          = flag.String("arch", runtime.GOARCH, "arch to test")
	flagKernelSrc     = flag.String("kernel_src", "", "path to kernel checkout")
	flagKernelConfig  = flag.String("config", "", "kernel config")
	flagKernelSysctl  = flag.String("sysctl", "", "kernel sysctl file")
	flagKernelCmdline = flag.String("cmdline", "", "kernel cmdline file")
	flagUserspace     = flag.String("userspace", "", "path to userspace for build")
	flagBisectBin     = flag.String("bisect_bin", "", "path to bisection binaries")
	flagSyzkaller     = flag.String("syzkaller", ".", "path to built syzkaller")
	flagSandbox       = flag.String("sandbox", "namespace", "sandbox to use for testing")
	flagSandboxArg    = flag.Int("sandbox_arg", 0, "an argument for sandbox runner")
)

const (
	vmType   = "qemu"
	numTests = 5
)

func main() {
	flag.Parse()
	if os.Getuid() != 0 {
		tool.Failf("image build will fail, run under root")
	}
	os.Setenv("SYZ_DISABLE_SANDBOXING", "yes")
	dir, err := os.MkdirTemp("", "syz-testbuild")
	if err != nil {
		tool.Fail(err)
	}
	defer os.RemoveAll(dir)
	cfg := &mgrconfig.Config{
		RawTarget:  *flagOS + "/" + *flagArch,
		HTTP:       ":0",
		Workdir:    dir,
		KernelSrc:  *flagKernelSrc,
		KernelObj:  *flagKernelSrc,
		Syzkaller:  *flagSyzkaller,
		Sandbox:    *flagSandbox,
		SandboxArg: int64(*flagSandboxArg),
		SSHUser:    "root",
		Procs:      1,
		Cover:      false,
		Type:       vmType,
		VM:         json.RawMessage([]byte(fmt.Sprintf(`{ "count": %v, "cpu": 2, "mem": 2048 }`, numTests))),
		Derived: mgrconfig.Derived{
			TargetOS:     *flagOS,
			TargetArch:   *flagArch,
			TargetVMArch: *flagArch,
		},
	}
	if err := mgrconfig.Complete(cfg); err != nil {
		tool.Fail(err)
	}
	repo, err := vcs.NewRepo(*flagOS, vmType, *flagKernelSrc)
	if err != nil {
		tool.Fail(err)
	}
	bisecter := repo.(vcs.Bisecter)
	head, err := repo.HeadCommit()
	if err != nil {
		tool.Fail(err)
	}
	log.Printf("HEAD is on %v %v", head.Hash, head.Title)
	tags, err := bisecter.PreviousReleaseTags(head.Hash, "gcc")
	if err != nil {
		tool.Fail(err)
	}
	log.Printf("tags: %v", tags)
	kernelConfig, err := os.ReadFile(*flagKernelConfig)
	if err != nil {
		tool.Fail(err)
	}
	env, err := instance.NewEnv(cfg, nil, nil)
	if err != nil {
		tool.Fail(err)
	}
	test(repo, bisecter, kernelConfig, env, head)
	for _, tag := range tags {
		com, err := repo.SwitchCommit(tag)
		if err != nil {
			tool.Fail(err)
		}
		test(repo, bisecter, kernelConfig, env, com)
	}
}

func test(repo vcs.Repo, bisecter vcs.Bisecter, kernelConfig []byte, env instance.Env, com *vcs.Commit) {
	compiler, compilerType, linker, ccache := "gcc", "gcc", "ld", ""
	bisectEnv, err := bisecter.EnvForCommit(compiler, compilerType, *flagBisectBin, com.Hash, kernelConfig, nil)
	if err != nil {
		tool.Fail(err)
	}
	log.Printf("testing: %v %v using %v", com.Hash, com.Title, bisectEnv.Compiler)
	if err := build.Clean(*flagOS, *flagArch, vmType, *flagKernelSrc); err != nil {
		tool.Fail(err)
	}
	_, _, err = env.BuildKernel(&instance.BuildKernelConfig{
		CompilerBin:  bisectEnv.Compiler,
		LinkerBin:    linker,
		CcacheBin:    ccache,
		UserspaceDir: *flagUserspace,
		CmdlineFile:  *flagKernelCmdline,
		SysctlFile:   *flagKernelSysctl,
		KernelConfig: bisectEnv.KernelConfig,
	})
	if err != nil {
		var verr *osutil.VerboseError
		if errors.As(err, &verr) {
			log.Printf("BUILD BROKEN: %v", verr.Title)
			saveLog(com.Hash, 0, verr.Output)
		} else {
			log.Printf("BUILD BROKEN: %v", err)
		}
		return
	}
	log.Printf("build OK")
	results, err := env.Test(numTests, nil, nil, nil)
	if err != nil {
		tool.Fail(err)
	}
	var verdicts []string
	for i, res := range results {
		if res.Error == nil {
			verdicts = append(verdicts, "OK")
			continue
		}

		var testError *instance.TestError
		var crashError *instance.CrashError
		switch {
		case errors.As(res.Error, &testError):
			if testError.Boot {
				verdicts = append(verdicts, fmt.Sprintf("boot failed: %v", testError))
			} else {
				verdicts = append(verdicts, fmt.Sprintf("basic kernel testing failed: %v", testError))
			}
			output := testError.Output
			if testError.Report != nil {
				output = testError.Report.Output
			}
			saveLog(com.Hash, i, output)
		case errors.As(res.Error, &crashError):
			verdicts = append(verdicts, fmt.Sprintf("crashed: %v", crashError))
			output := crashError.Report.Report
			if len(output) == 0 {
				output = crashError.Report.Output
			}
			saveLog(com.Hash, i, output)
		default:
			verdicts = append(verdicts, fmt.Sprintf("failed: %v", err))
		}
	}
	unique := make(map[string]bool)
	for _, verdict := range verdicts {
		unique[verdict] = true
	}
	if len(unique) == 1 {
		log.Printf("all runs: %v", verdicts[0])
	} else {
		for i, verdict := range verdicts {
			log.Printf("run #%v: %v", i, verdict)
		}
	}
}

func saveLog(hash string, idx int, data []byte) {
	if len(data) == 0 {
		return
	}
	osutil.WriteFile(fmt.Sprintf("%v.%v", hash, idx), data)
}
