// Copyright 2021 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

// syz-build is a wrapper around pkg/build for testing purposes.
package main

import (
	"flag"
	"fmt"
	"os"
	"runtime"

	"github.com/google/syzkaller/pkg/build"
	"github.com/google/syzkaller/pkg/debugtracer"
	"github.com/google/syzkaller/pkg/tool"
)

var (
	flagOS            = flag.String("os", runtime.GOOS, "OS to build")
	flagArch          = flag.String("arch", runtime.GOARCH, "arch to build")
	flagVM            = flag.String("vm", "gce", "VM type to build")
	flagKernelSrc     = flag.String("kernel_src", "", "path to kernel checkout")
	flagCompiler      = flag.String("compiler", "", "non-defult compiler")
	flagLinker        = flag.String("linker", "", "non-default linker")
	flagKernelConfig  = flag.String("config", "", "kernel config file")
	flagKernelSysctl  = flag.String("sysctl", "", "kernel sysctl file")
	flagKernelCmdline = flag.String("cmdline", "", "kernel cmdline file")
	flagUserspace     = flag.String("userspace", "", "path to userspace for build")
	flagTrace         = flag.Bool("trace", false, "trace build process and save debug artefacts")
)

func main() {
	flag.Parse()
	if os.Getuid() != 0 {
		fmt.Printf("not running under root, image build may fail\n")
	}
	os.Setenv("SYZ_DISABLE_SANDBOXING", "yes")
	var kernelConfig []byte
	if *flagKernelConfig != "" {
		var err error
		kernelConfig, err = os.ReadFile(*flagKernelConfig)
		if err != nil {
			tool.Fail(err)
		}
	}
	wd, err := os.Getwd()
	if err != nil {
		tool.Fail(err)
	}
	params := build.Params{
		TargetOS:     *flagOS,
		TargetArch:   *flagArch,
		VMType:       *flagVM,
		KernelDir:    *flagKernelSrc,
		OutputDir:    wd,
		Compiler:     *flagCompiler,
		Linker:       *flagLinker,
		Ccache:       "",
		UserspaceDir: *flagUserspace,
		CmdlineFile:  *flagKernelCmdline,
		SysctlFile:   *flagKernelSysctl,
		Config:       kernelConfig,
		Tracer:       &debugtracer.NullTracer{},
	}
	if *flagTrace {
		params.Tracer = &debugtracer.GenericTracer{
			TraceWriter: os.Stdout,
			OutDir:      ".",
		}
	}
	details, err := build.Image(params)
	if err != nil {
		tool.Fail(err)
	}
	params.Tracer.Log("signature: %v", details.Signature)
	params.Tracer.Log("compiler: %v", details.CompilerID)
}
