// Copyright 2021 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

// syz-build is a wrapper around pkg/build for testing purposes.
package main

import (
	"flag"
	"io/ioutil"
	"os"
	"runtime"

	"github.com/google/syzkaller/pkg/build"
	"github.com/google/syzkaller/pkg/tool"
)

var (
	flagOS            = flag.String("os", runtime.GOOS, "OS to test")
	flagArch          = flag.String("arch", runtime.GOARCH, "arch to test")
	flagKernelSrc     = flag.String("kernel_src", "", "path to kernel checkout")
	flagKernelConfig  = flag.String("config", "", "kernel config file")
	flagKernelSysctl  = flag.String("sysctl", "", "kernel sysctl file")
	flagKernelCmdline = flag.String("cmdline", "", "kernel cmdline file")
	flagUserspace     = flag.String("userspace", "", "path to userspace for build")
)

func main() {
	flag.Parse()
	if os.Getuid() != 0 {
		tool.Failf("image build will fail, run under root")
	}
	os.Setenv("SYZ_DISABLE_SANDBOXING", "yes")
	kernelConfig, err := ioutil.ReadFile(*flagKernelConfig)
	if err != nil {
		tool.Fail(err)
	}
	params := build.Params{
		TargetOS:     *flagOS,
		TargetArch:   *flagArch,
		VMType:       "gce",
		KernelDir:    *flagKernelSrc,
		OutputDir:    ".",
		Compiler:     "",
		Ccache:       "",
		UserspaceDir: *flagUserspace,
		CmdlineFile:  *flagKernelCmdline,
		SysctlFile:   *flagKernelSysctl,
		Config:       kernelConfig,
	}
	if _, err := build.Image(params); err != nil {
		tool.Fail(err)
	}
}
