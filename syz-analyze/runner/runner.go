package main

import (
	"flag"
	"github.com/google/syzkaller/pkg/ipc"
	"github.com/google/syzkaller/pkg/ipc/ipcconfig"
	"github.com/google/syzkaller/pkg/log"
	"github.com/google/syzkaller/pkg/rpctype"
	"github.com/google/syzkaller/prog"
	_ "github.com/google/syzkaller/sys"
	"runtime"
)

type Runner struct {
	client *rpctype.RPCClient
	target *prog.Target
	opts   *ipc.ExecOpts
	config *ipc.Config
	pool   int
	vm     int
}

func main() {
	flagVM := flag.Int("vm", 0, "vm id")
	flagPool := flag.Int("pool", 0, "pool id")
	flagAddr := flag.String("addr", "", "address for rpc")
	flagOS := flag.String("os", runtime.GOOS, "target os")
	flagArch := flag.String("arch", runtime.GOARCH, "target architecture")
	flag.Parse()

	target, err := prog.GetTarget(*flagOS, *flagArch)
	if err != nil {
		log.Fatal(err)
	}

	config, opts, err := ipcconfig.Default(target)
	if err != nil {
		log.Fatal(err)
	}

	timeouts := config.Timeouts
	client, err := rpctype.NewRPCClient(*flagAddr, timeouts.Scale)

	runner := &Runner{
		client: client,
		target: target,
		opts:   opts,
		config: config,
		pool:   *flagPool,
		vm:     *flagVM,
	}
	log.Logf(0, "%v", runner)

	res := &rpctype.NextExchangeRes{}
	if err := runner.client.Call("Analyzer.NextProgram", &rpctype.NextExchangeArgs{Pool: runner.pool, VM: runner.vm}, res); err != nil {
		log.Fatalf("Can't get initial programm: %v", err)
	}

	runner.Run(res.Prog, res.ID)
}

func (runner *Runner) Run(firstProgram []byte, taskID int64) {
	rawProgram, id := firstProgram, taskID

	env, err := ipc.MakeEnv(runner.config, 0)
	if err != nil {
		log.Fatalf("%v", err)
	}

	for {
		program, err := runner.target.Deserialize(rawProgram, prog.NonStrict)
		if err != nil {
			log.Fatalf("%v", err)
		}

		println(len(program.Calls))

		log.Logf(0, "Executing program: %s\n", rawProgram)

		output, info, hanged, err := env.Exec(runner.opts, program)

		println("-----------------")
		log.Logf(0, "%s\n", output)
		println(info)
		println(hanged)
		println(err)
		println("-----------------")

		args := &rpctype.NextExchangeArgs{
			Pool:       runner.pool,
			VM:         runner.vm,
			ExecTaskID: id,
			Hanged:     hanged,
		}

		res := &rpctype.NextExchangeRes{}

		if err := runner.client.Call("Analyzer.NextProgram", args, res); err != nil {
			log.Fatalf("Can't get next programm: %v", err)
		}

		rawProgram, id = res.Prog, res.ID
		if rawProgram == nil {
			return
		}
	}
}
