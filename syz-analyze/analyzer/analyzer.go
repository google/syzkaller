package main

import (
	"flag"
	"fmt"
	"github.com/google/syzkaller/pkg/log"
	"github.com/google/syzkaller/pkg/mgrconfig"
	"github.com/google/syzkaller/pkg/tool"
	"github.com/google/syzkaller/prog"
	_ "github.com/google/syzkaller/sys"
	"github.com/google/syzkaller/vm"
	"os"
	"path/filepath"
	"runtime"
)

type PoolInfo struct {
	config *mgrconfig.Config
	pool   *vm.Pool
}

type Analyzer struct {
	pools       map[int]*PoolInfo
	server      *RPCServer
	programs    []*prog.Prog
	port        int
	runnerBin   string
	executorBin string
	vmStopChan  chan bool
}

func main() {
	//test()
	myFunc()
}

func test() {
	flag.Parse()
	target, err := prog.GetTarget(runtime.GOOS, runtime.GOARCH)
	programs := loadPrograms(target, flag.Args())
	pools := make(map[int]*PoolInfo)
	analyzer := &Analyzer{
		programs: programs,
		pools:    pools,
	}
	analyzer.pools[0] = &PoolInfo{}
	server, err := createRPCServer(":2233", analyzer)
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
	flagDebug := flag.Bool("debug", false, "print debug info from virtual machines")
	flag.Parse()

	pools := make(map[int]*PoolInfo)
	analyzer := &Analyzer{}
	for idx, config := range configs {
		var err error
		pool := &PoolInfo{}
		pool.config, err = mgrconfig.LoadFile(config)
		if err != nil {
			log.Fatalf("%v", err)
		}
		pool.pool, err = vm.Create(pool.config, *flagDebug)
		if err != nil {
			log.Fatalf("%v", err)
		}
		pools[idx] = pool
	}
	analyzer.pools = pools
	log.Logf(0, "pools size: %d\n", len(pools))

	config := analyzer.pools[0].config

	analyzer.programs = loadPrograms(config.Target, flag.Args())

	server, err := createRPCServer(config.RPC, analyzer)
	log.Logf(0, "my rpc port: %d\n", server.port)
	if err != nil {
		log.Fatalf("%v", err)
	}
	analyzer.server = server

	exe := config.SysTarget.ExeExtension
	runnerBin := filepath.Join(config.Syzkaller, "bin", config.Target.OS+"_"+config.Target.Arch, "syz-runner"+exe)
	// check
	analyzer.runnerBin = runnerBin

	executorBin := config.ExecutorBin
	// check
	analyzer.executorBin = executorBin

	analyzer.initializeInstances()

	for {
	}
}

func (analyzer *Analyzer) initializeInstances() {
	for poolID, pool := range analyzer.pools {
		count := pool.pool.Count()
		for vmID := 0; vmID < count; vmID++ {
			go func(pool *PoolInfo, poolID, vmID int) {
				analyzer.createInstance(pool, poolID, vmID)
			}(pool, poolID, vmID)
		}
	}
}

func (analyzer *Analyzer) createInstance(pool *PoolInfo, poolID, vmID int) {
	instance, err := pool.pool.Create(vmID)
	if err != nil {
		log.Fatalf("%v", err)
	}
	//defer instance.Close()

	port, err := instance.Forward(analyzer.port)
	log.Logf(poolID, "port for %d-%d: %d\n", poolID, vmID, port)
	if err != nil {
		log.Fatalf("%v with port %s\n", err, port)
	}

	runnerBin, err := instance.Copy(analyzer.runnerBin)
	log.Logf(poolID, "runner for %d-%d: %d\n", poolID, vmID, runnerBin)
	if err != nil {
		log.Fatalf("%v", err)
	}
	_, err = instance.Copy(analyzer.executorBin)
	if err != nil {
		log.Fatalf("%v", err)
	}

	command := fmt.Sprintf("%s -os=%s -arch=%s -addr=%s -pool=%d -vm=%d", runnerBin, pool.config.TargetOS, pool.config.TargetArch, port, poolID, vmID)
	//command := runnerBin + " -os=" + pool.config.TargetOS + " -arch=" + pool.config.TargetArch + " -addr=" + port + " -pool=" + poolID + " -vm=" + vmID
	_, _, err = instance.Run(pool.config.Timeouts.VMRunningTime, analyzer.vmStopChan, command)
	if err != nil {
		log.Fatalf("%v", err)
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
			//for _, comm := range entry.P.Calls {
			//	println(comm.Meta.Name)
			//}
			//println("------")
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
