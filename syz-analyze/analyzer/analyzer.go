package main

import (
	"flag"
	"github.com/google/syzkaller/pkg/log"
	"github.com/google/syzkaller/pkg/mgrconfig"
	"github.com/google/syzkaller/pkg/tool"
	"github.com/google/syzkaller/prog"
	_ "github.com/google/syzkaller/sys"
	"github.com/google/syzkaller/vm"
	"os"
	"runtime"
)

type PoolInfo struct {
	config   *mgrconfig.Config
	pool     *vm.Pool
	programs []*prog.Prog
}

func main() {
	test()
}

func test() {
	flag.Parse()
	target, err := prog.GetTarget(runtime.GOOS, runtime.GOARCH)
	programs := loadPrograms(target, flag.Args())
	server, err := createRPCServer(":2233", PoolInfo{programs: programs})
	if err != nil {
		log.Fatal(err)
	}
	log.Logf(0, "my rpc prot: %d", server.port)
	for {
	}
}

func myFunc() {
	var configs tool.CfgsFlag
	flag.Var(&configs, "configs", "list of configuration files for kernels divided by comma")
	flag.Parse()

	pools := make(map[int]*PoolInfo)

	for idx, config := range configs {
		var err error
		pool := &PoolInfo{}
		pool.config, err = mgrconfig.LoadFile(config)
		if err != nil {
			log.Fatalf("%v", err)
		}
		pool.pool, err = vm.Create(pool.config, true)

		if err != nil {
			log.Fatalf("%v", err)
		}
		pool.programs = loadPrograms(pool.config.Target, flag.Args())
		//instance := pool.pool.Create(0)
		//instance.Run()
		pools[idx] = pool
	}
}

func loadPrograms(target *prog.Target, files []string) []*prog.Prog {
	var progs []*prog.Prog
	for _, filePath := range files {
		data, err := os.ReadFile(filePath)
		if err != nil {
			log.Fatalf("%v", err)
		}
		for _, entry := range target.ParseLog(data) {
			progs = append(progs, entry.P)
			for _, comm := range entry.P.Calls {
				println(comm.Meta.Name)
			}
			println("------")
		}
	}
	log.Logf(0, "load : %d programs", len(files))
	return progs
}

//func createConfig(target *prog.Target) (*ipc.Config, *ipc.ExecOpts) {
//	config, execOpts, err := ipcconfig.Default(target)
//	if err != nil {
//		log.Fatalf("%v", err)
//	}
//	return config, execOpts
//}

//target, err := prog.GetTarget(*flagOS, *flagArch)
//if err != nil {
//	log.Fatalf("%v", err)
//}
//print(target.OS)
//programs := loadPrograms(target, flag.Args())
//println("Programs parsed: ", len(programs))
//
//config, execOpts := createConfig(target)
//
//println("Executor: ", config.Executor)
//for _, program := range programs {
//	env, err := ipc.MakeEnv(config, 0)
//	if err != nil {
//		log.Fatalf("%v", err)
//	}
//	data := program.Serialize()
//	log.Logf(0, "executing program %v:\n%s", 0, data)
//	output, info, hanged, err := env.Exec(execOpts, program)
//	println("------")
//	println(info)
//	log.Logf(0, "result: hanged=%v err=%v\n\n%s", hanged, err, output)
//	println("------")
//
//}
//
//println(config, execOpts)
