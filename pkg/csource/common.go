// Copyright 2017 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

//go:generate ./gen.sh

package csource

import (
	"bytes"
	"fmt"
	"strings"

	"github.com/google/syzkaller/pkg/osutil"
	"github.com/google/syzkaller/prog"
	"github.com/google/syzkaller/sys/targets"
)

const (
	linux   = "linux"
	akaros  = "akaros"
	fuchsia = "fuchsia"

	sandboxNone      = "none"
	sandboxSetuid    = "setuid"
	sandboxNamespace = "namespace"
)

func createCommonHeader(p, mmapProg *prog.Prog, replacements map[string]string, opts Options) ([]byte, error) {
	defines, err := defineList(p, mmapProg, opts)
	if err != nil {
		return nil, err
	}

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

func defineList(p, mmapProg *prog.Prog, opts Options) ([]string, error) {
	var defines []string
	bitmasks, csums := prog.RequiredFeatures(p)
	if bitmasks {
		defines = append(defines, "SYZ_USE_BITMASKS")
	}
	if csums {
		defines = append(defines, "SYZ_USE_CHECKSUMS")
	}
	switch opts.Sandbox {
	case "":
		// No sandbox, do nothing.
	case sandboxNone:
		defines = append(defines, "SYZ_SANDBOX_NONE")
	case sandboxSetuid:
		defines = append(defines, "SYZ_SANDBOX_SETUID")
	case sandboxNamespace:
		defines = append(defines, "SYZ_SANDBOX_NAMESPACE")
	default:
		return nil, fmt.Errorf("unknown sandbox mode: %v", opts.Sandbox)
	}
	if opts.Threaded {
		defines = append(defines, "SYZ_THREADED")
	}
	if opts.Collide {
		defines = append(defines, "SYZ_COLLIDE")
	}
	if opts.Repeat {
		defines = append(defines, "SYZ_REPEAT")
	}
	if opts.Procs > 1 {
		defines = append(defines, "SYZ_PROCS")
	}
	if opts.Fault {
		defines = append(defines, "SYZ_FAULT_INJECTION")
	}
	if opts.EnableTun {
		defines = append(defines, "SYZ_TUN_ENABLE")
	}
	if opts.EnableCgroups {
		defines = append(defines, "SYZ_ENABLE_CGROUPS")
	}
	if opts.EnableNetdev {
		defines = append(defines, "SYZ_ENABLE_NETDEV")
	}
	if opts.ResetNet {
		defines = append(defines, "SYZ_RESET_NET_NAMESPACE")
	}
	if opts.UseTmpDir {
		defines = append(defines, "SYZ_USE_TMP_DIR")
	}
	if opts.HandleSegv {
		defines = append(defines, "SYZ_HANDLE_SEGV")
	}
	if opts.Repro {
		defines = append(defines, "SYZ_REPRO")
	}
	for _, c := range p.Calls {
		defines = append(defines, "__NR_"+c.Meta.CallName)
	}
	for _, c := range mmapProg.Calls {
		defines = append(defines, "__NR_"+c.Meta.CallName)
	}
	defines = append(defines, "GOOS_"+p.Target.OS)
	defines = append(defines, "GOARCH_"+p.Target.Arch)
	sysTarget := targets.Get(p.Target.OS, p.Target.Arch)
	if sysTarget.ExecutorUsesShmem {
		defines = append(defines, "SYZ_EXECUTOR_USES_SHMEM")
	}
	if sysTarget.ExecutorUsesForkServer {
		defines = append(defines, "SYZ_EXECUTOR_USES_FORK_SERVER")
	}
	return defines, nil
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
