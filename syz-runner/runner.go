// Copyright 2021 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
package main

import (
	"flag"
	"fmt"
	"log"
	"runtime"

	"github.com/google/syzkaller/pkg/host"
	"github.com/google/syzkaller/pkg/ipc"
	"github.com/google/syzkaller/pkg/ipc/ipcconfig"
	"github.com/google/syzkaller/pkg/rpctype"
	"github.com/google/syzkaller/prog"
)

// Runner is responsible of running programs sent by the host via RPC and
// reporting the execution results back to the host.
type Runner struct {
	vrf      *rpctype.RPCClient
	target   *prog.Target
	opts     *ipc.ExecOpts
	config   *ipc.Config
	pool, vm int
	newEnv   bool
}

func main() {
	flagPool := flag.Int("pool", 0, "index of pool it corresponds to")
	flagVM := flag.Int("vm", 0, "index of VM that started the Runner")
	flagAddr := flag.String("addr", "", "verifier rpc address")
	flagOS := flag.String("os", runtime.GOOS, "target OS")
	flagArch := flag.String("arch", runtime.GOARCH, "target arch")
	flagEnv := flag.Bool("new-env", true, "create a new environment for each program")
	flag.Parse()

	target, err := prog.GetTarget(*flagOS, *flagArch)
	if err != nil {
		log.Fatalf("failed to configure target: %v", err)
	}

	config, opts, err := ipcconfig.Default(target)
	if err != nil {
		log.Fatalf("failed to create default ipc config: %v", err)
	}

	timeouts := config.Timeouts
	vrf, err := rpctype.NewRPCClient(*flagAddr, timeouts.Scale)
	if err != nil {
		log.Fatalf("failed to connect to verifier : %v", err)
	}

	rn := &Runner{
		vrf:    vrf,
		target: target,
		opts:   opts,
		config: config,
		pool:   *flagPool,
		vm:     *flagVM,
		newEnv: *flagEnv,
	}

	a := &rpctype.RunnerConnectArgs{
		Pool: rn.pool,
		VM:   rn.vm,
	}
	r := &rpctype.RunnerConnectRes{}
	if err := vrf.Call("Verifier.Connect", a, r); err != nil {
		log.Fatalf("failed to connect to verifier: %v", err)
	}

	if r.CheckUnsupportedCalls {
		_, unsupported, err := host.DetectSupportedSyscalls(target, ipc.FlagsToSandbox(config.Flags))
		if err != nil {
			log.Fatalf("failed to get unsupported system calls: %v", err)
		}

		calls := make([]rpctype.SyscallReason, 0)
		for c, reason := range unsupported {
			calls = append(calls, rpctype.SyscallReason{
				ID:     c.ID,
				Reason: fmt.Sprintf("%s (not supported on kernel %d)", reason, rn.pool)})
		}
		a := &rpctype.UpdateUnsupportedArgs{Pool: rn.pool, UnsupportedCalls: calls}
		if err := vrf.Call("Verifier.UpdateUnsupported", a, nil); err != nil {
			log.Fatalf("failed to send unsupported system calls: %v", err)
		}
	}

	res := &rpctype.NextExchangeRes{}
	if err := rn.vrf.Call("Verifier.NextExchange", &rpctype.NextExchangeArgs{Pool: rn.pool, VM: rn.vm}, res); err != nil {
		log.Fatalf("failed to get initial program: %v", err)
	}

	rn.Run(res.Prog, res.ProgIdx, res.RunIdx)
}

// Run is responsible for requesting new programs from the verifier, executing them and then sending back the Result.
// TODO: Implement functionality to execute several programs at once and send back a slice of results.
func (rn *Runner) Run(firstProg []byte, idx, runIdx int) {
	p, pIdx, rIdx := firstProg, idx, runIdx

	env, err := ipc.MakeEnv(rn.config, 0)
	if err != nil {
		log.Fatalf("failed to create initial execution environment: %v", err)
	}

	for {
		prog, err := rn.target.Deserialize(p, prog.NonStrict)
		if err != nil {
			log.Fatalf("failed to deserialise new program: %v", err)
		}

		_, info, hanged, err := env.Exec(rn.opts, prog)
		if err != nil {
			log.Fatalf("failed to execute the program: %v", err)
		}

		a := &rpctype.NextExchangeArgs{
			Pool:    rn.pool,
			VM:      rn.vm,
			ProgIdx: pIdx,
			Hanged:  hanged,
			Info:    *info,
			RunIdx:  rIdx,
		}

		r := &rpctype.NextExchangeRes{}
		if err := rn.vrf.Call("Verifier.NextExchange", a, r); err != nil {
			log.Fatalf("failed to make exchange with verifier: %v", err)
		}
		p, pIdx, rIdx = r.Prog, r.ProgIdx, r.RunIdx

		if !rn.newEnv {
			continue
		}

		err = env.Close()
		if err != nil {
			log.Fatalf("failed to close the execution environment: %v", err)
		}

		env, err = ipc.MakeEnv(rn.config, 0)
		if err != nil {
			log.Fatalf("failed to create new execution environmentL %v", err)
		}
	}
}
