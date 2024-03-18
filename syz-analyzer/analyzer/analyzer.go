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
	start()
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

func start() {
	var configs tool.CfgsFlag
	flag.Var(&configs, "configs", "list of configuration files for kernels divided by comma")
	flagDebug := flag.Bool("debug", false, "print debug info from virtual machines")
	flag.Parse()

	if len(configs) == 0 {
		flag.Usage()
		os.Exit(-1)
	}

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

	if err != nil {
		log.Fatalf("%v", err)
	}
	analyzer.server = server

	analyzer.initializeTasks()

	exe := config.SysTarget.ExeExtension
	runnerBin := filepath.Join(config.Syzkaller, "bin", config.Target.OS+"_"+config.Target.Arch, "syz-runner"+exe)
	// TODO: check
	analyzer.runnerBin = runnerBin

	executorBin := config.ExecutorBin
	// TODO: check
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

	port, err := instance.Forward(analyzer.server.port)
	if err != nil {
		log.Fatalf("%v with port %s\n", err, port)
	}

	runnerBin, err := instance.Copy(analyzer.runnerBin)
	if err != nil {
		log.Fatalf("%v", err)
	}
	_, err = instance.Copy(analyzer.executorBin)
	if err != nil {
		log.Fatalf("%v", err)
	}

	command := fmt.Sprintf("%s -os=%s -arch=%s -addr=%s -pool=%d -vm=%d", runnerBin, pool.config.TargetOS, pool.config.TargetArch, port, poolID, vmID)
	_, _, err = instance.Run(pool.config.Timeouts.VMRunningTime, analyzer.vmStopChan, command)
	if err != nil {
		log.Fatalf("%v", err)
	}
}

func (analyzer *Analyzer) initializeTasks() {
	for poolID, pool := range analyzer.pools {
		count := pool.pool.Count()
		for vmID := 0; vmID < count; vmID++ {
			analyzer.addTasks(vmKey(poolID, vmID), analyzer.programs)
		}
	}
}

func (analyzer *Analyzer) addTasks(vmID int, programs []*prog.Prog) {
	for programID, _ := range programs {
		for i := 0; i < 1; i++ {
			analyzer.server.tasksQueue.push(vmID, programID)
		}
	}
}

func loadPrograms(target *prog.Target, files []string) []*prog.Prog {
	var progs []*prog.Prog
	for _, filePath := range files {
		data, err := os.ReadFile(filePath)
		if err != nil {
			log.Fatalf("can't read repro file: %v", err)
		}
		for _, entry := range target.ParseLog(data) {
			progs = append(progs, entry.P)
		}
	}
	log.Logf(0, "number of loaded programs: %d", len(progs))
	return progs
}
