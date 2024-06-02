// Copyright 2017 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

//go:generate go run gen.go

package csource

import (
	"bytes"
	"fmt"
	"regexp"
	"runtime"
	"sort"
	"strings"

	"github.com/google/syzkaller/executor"
	"github.com/google/syzkaller/pkg/osutil"
	"github.com/google/syzkaller/prog"
	"github.com/google/syzkaller/sys/targets"
)

const (
	sandboxNone      = "none"
	sandboxSetuid    = "setuid"
	sandboxNamespace = "namespace"
	sandboxAndroid   = "android"
)

func createCommonHeader(p, mmapProg *prog.Prog, replacements map[string]string, opts Options) ([]byte, error) {
	defines := defineList(p, mmapProg, opts)
	sysTarget := targets.Get(p.Target.OS, p.Target.Arch)
	// Note: -fdirectives-only isn't supported by clang. This code is relevant
	// for producing C++ reproducers. Hence reproducers don't work when setting
	// CPP in targets.go to clang++ at the moment.
	cmd := osutil.Command(sysTarget.CPP, "-nostdinc", "-undef", "-fdirectives-only", "-dDI", "-E", "-P", "-CC", "-")
	for _, def := range defines {
		cmd.Args = append(cmd.Args, "-D"+def)
	}
	cmd.Stdin = bytes.NewReader(executor.CommonHeader)
	stderr := new(bytes.Buffer)
	stdout := new(bytes.Buffer)
	cmd.Stderr = stderr
	cmd.Stdout = stdout
	// Note: we ignore error because we pass -nostdinc so there are lots of errors of the form:
	//	error: no include path in which to search for stdlib.h
	// This is exactly what we want: we don't want these to be included into the C reproducer.
	// But the downside is that we can miss some real errors, e.g.:
	//	error: missing binary operator before token "SYZ_SANDBOX_ANDROID"
	//	3776 | #if not SYZ_SANDBOX_ANDROID
	// Potentially we could analyze errors manually and ignore only the expected ones.
	if err := cmd.Run(); len(stdout.Bytes()) == 0 {
		return nil, fmt.Errorf("cpp failed: %v %v: %w\n%v\n%v", cmd.Path, cmd.Args, err, stdout.String(), stderr.String())
	}

	src, err := removeSystemDefines(stdout.Bytes(), defines)
	if err != nil {
		return nil, err
	}

	for from, to := range replacements {
		src = bytes.Replace(src, []byte("/*{{{"+from+"}}}*/"), []byte(to), -1)
	}

	for from, to := range map[string]string{
		"uint64": "uint64_t",
		"uint32": "uint32_t",
		"uint16": "uint16_t",
		"uint8":  "uint8_t",
	} {
		src = bytes.Replace(src, []byte(from), []byte(to), -1)
	}
	src = regexp.MustCompile("#define SYZ_HAVE_.*").ReplaceAll(src, nil)

	return src, nil
}

func defineList(p, mmapProg *prog.Prog, opts Options) (defines []string) {
	for def, ok := range commonDefines(p, opts) {
		if ok {
			defines = append(defines, def)
		}
	}
	for _, c := range p.Calls {
		defines = append(defines, "__NR_"+c.Meta.CallName)
	}
	for _, c := range mmapProg.Calls {
		defines = append(defines, "__NR_"+c.Meta.CallName)
	}
	sort.Strings(defines)
	return
}

func commonDefines(p *prog.Prog, opts Options) map[string]bool {
	sysTarget := targets.Get(p.Target.OS, p.Target.Arch)
	features := p.RequiredFeatures()
	return map[string]bool{
		"GOOS_" + p.Target.OS:           true,
		"GOARCH_" + p.Target.Arch:       true,
		"HOSTGOOS_" + runtime.GOOS:      true,
		"SYZ_USE_BITMASKS":              features.Bitmasks,
		"SYZ_USE_CHECKSUMS":             features.Csums,
		"SYZ_SANDBOX_NONE":              opts.Sandbox == sandboxNone,
		"SYZ_SANDBOX_SETUID":            opts.Sandbox == sandboxSetuid,
		"SYZ_SANDBOX_NAMESPACE":         opts.Sandbox == sandboxNamespace,
		"SYZ_SANDBOX_ANDROID":           opts.Sandbox == sandboxAndroid,
		"SYZ_THREADED":                  opts.Threaded,
		"SYZ_ASYNC":                     features.Async,
		"SYZ_REPEAT":                    opts.Repeat,
		"SYZ_REPEAT_TIMES":              opts.RepeatTimes > 1,
		"SYZ_MULTI_PROC":                opts.Procs > 1,
		"SYZ_FAULT":                     features.FaultInjection,
		"SYZ_LEAK":                      opts.Leak,
		"SYZ_NET_INJECTION":             opts.NetInjection,
		"SYZ_NET_DEVICES":               opts.NetDevices,
		"SYZ_NET_RESET":                 opts.NetReset,
		"SYZ_CGROUPS":                   opts.Cgroups,
		"SYZ_BINFMT_MISC":               opts.BinfmtMisc,
		"SYZ_CLOSE_FDS":                 opts.CloseFDs,
		"SYZ_KCSAN":                     opts.KCSAN,
		"SYZ_DEVLINK_PCI":               opts.DevlinkPCI,
		"SYZ_NIC_VF":                    opts.NicVF,
		"SYZ_USB":                       opts.USB,
		"SYZ_VHCI_INJECTION":            opts.VhciInjection,
		"SYZ_USE_TMP_DIR":               opts.UseTmpDir,
		"SYZ_HANDLE_SEGV":               opts.HandleSegv,
		"SYZ_TRACE":                     opts.Trace,
		"SYZ_WIFI":                      opts.Wifi,
		"SYZ_802154":                    opts.IEEE802154,
		"SYZ_SYSCTL":                    opts.Sysctl,
		"SYZ_SWAP":                      opts.Swap,
		"SYZ_EXECUTOR_USES_FORK_SERVER": sysTarget.ExecutorUsesForkServer,
	}
}

func removeSystemDefines(src []byte, defines []string) ([]byte, error) {
	remove := map[string]string{
		"__STDC__":        "1",
		"__STDC_HOSTED__": "1",
		"__STDC_UTF_16__": "1",
		"__STDC_UTF_32__": "1",
	}
	for _, def := range defines {
		eq := strings.IndexByte(def, '=')
		if eq == -1 {
			remove[def] = "1"
		} else {
			remove[def[:eq]] = def[eq+1:]
		}
	}
	for def, val := range remove {
		src = bytes.Replace(src, []byte("#define "+def+" "+val+"\n"), nil, -1)
	}
	// strip: #define __STDC_VERSION__ 201112L
	for _, def := range []string{"__STDC_VERSION__"} {
		pos := bytes.Index(src, []byte("#define "+def))
		if pos == -1 {
			continue
		}
		end := bytes.IndexByte(src[pos:], '\n')
		if end == -1 {
			continue
		}
		src = bytes.Replace(src, src[pos:end+1], nil, -1)
	}
	return src, nil
}
