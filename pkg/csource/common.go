// Copyright 2017 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

//go:generate go run gen.go

package csource

import (
	"bytes"
	"fmt"
	"sort"
	"strings"

	"github.com/google/syzkaller/pkg/osutil"
	"github.com/google/syzkaller/prog"
	"github.com/google/syzkaller/sys/targets"
)

const (
	linux = "linux"

	sandboxNone                = "none"
	sandboxSetuid              = "setuid"
	sandboxNamespace           = "namespace"
	sandboxAndroidUntrustedApp = "android_untrusted_app"
)

func createCommonHeader(p, mmapProg *prog.Prog, replacements map[string]string, opts Options) ([]byte, error) {
	defines := defineList(p, mmapProg, opts)
	cmd := osutil.Command("cpp", "-nostdinc", "-undef", "-fdirectives-only", "-dDI", "-E", "-P", "-")
	for _, def := range defines {
		cmd.Args = append(cmd.Args, "-D"+def)
	}
	cmd.Stdin = strings.NewReader(commonHeader)
	stderr := new(bytes.Buffer)
	stdout := new(bytes.Buffer)
	cmd.Stderr = stderr
	cmd.Stdout = stdout
	if err := cmd.Run(); len(stdout.Bytes()) == 0 {
		return nil, fmt.Errorf("cpp failed: %v\n%v\n%v", err, stdout.String(), stderr.String())
	}

	src, err := removeSystemDefines(stdout.Bytes(), defines)
	if err != nil {
		return nil, err
	}

	for from, to := range replacements {
		src = bytes.Replace(src, []byte("[["+from+"]]"), []byte(to), -1)
	}

	for from, to := range map[string]string{
		"uint64": "uint64_t",
		"uint32": "uint32_t",
		"uint16": "uint16_t",
		"uint8":  "uint8_t",
	} {
		src = bytes.Replace(src, []byte(from), []byte(to), -1)
	}

	return src, nil
}

func defineList(p, mmapProg *prog.Prog, opts Options) (defines []string) {
	sysTarget := targets.Get(p.Target.OS, p.Target.Arch)
	bitmasks, csums := prog.RequiredFeatures(p)
	enabled := map[string]bool{
		"GOOS_" + p.Target.OS:               true,
		"GOARCH_" + p.Target.Arch:           true,
		"SYZ_USE_BITMASKS":                  bitmasks,
		"SYZ_USE_CHECKSUMS":                 csums,
		"SYZ_SANDBOX_NONE":                  opts.Sandbox == sandboxNone,
		"SYZ_SANDBOX_SETUID":                opts.Sandbox == sandboxSetuid,
		"SYZ_SANDBOX_NAMESPACE":             opts.Sandbox == sandboxNamespace,
		"SYZ_SANDBOX_ANDROID_UNTRUSTED_APP": opts.Sandbox == sandboxAndroidUntrustedApp,
		"SYZ_THREADED":                      opts.Threaded,
		"SYZ_COLLIDE":                       opts.Collide,
		"SYZ_REPEAT":                        opts.Repeat,
		"SYZ_REPEAT_TIMES":                  opts.RepeatTimes > 1,
		"SYZ_PROCS":                         opts.Procs > 1,
		"SYZ_FAULT_INJECTION":               opts.Fault,
		"SYZ_TUN_ENABLE":                    opts.EnableTun,
		"SYZ_ENABLE_CGROUPS":                opts.EnableCgroups,
		"SYZ_ENABLE_NETDEV":                 opts.EnableNetdev,
		"SYZ_RESET_NET_NAMESPACE":           opts.ResetNet,
		"SYZ_USE_TMP_DIR":                   opts.UseTmpDir,
		"SYZ_HANDLE_SEGV":                   opts.HandleSegv,
		"SYZ_REPRO":                         opts.Repro,
		"SYZ_TRACE":                         opts.Trace,
		"SYZ_EXECUTOR_USES_SHMEM":           sysTarget.ExecutorUsesShmem,
		"SYZ_EXECUTOR_USES_FORK_SERVER":     sysTarget.ExecutorUsesForkServer,
	}
	for def, ok := range enabled {
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
