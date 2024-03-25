package main

import (
	"flag"
	"fmt"
	"github.com/google/syzkaller/pkg/log"
	"github.com/google/syzkaller/pkg/mgrconfig"
	"github.com/google/syzkaller/pkg/osutil"
	"github.com/google/syzkaller/pkg/tool"
	"github.com/google/syzkaller/prog"
	_ "github.com/google/syzkaller/sys"
	"github.com/google/syzkaller/vm"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"sync"
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
	statistics  *Statistics
	wgFinish    sync.WaitGroup
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
	flagStats := flag.String("stats", "", "where stats will be written after execution, default stdout")
	flagRepeats := flag.Int("repeat", 1000, "how many times will we run each reproducer")
	flag.Parse()

	if len(configs) == 0 {
		log.Errorf("There are no configs for virtual machines")
		flag.Usage()
		os.Exit(-1)
	}

	if len(flag.Args()) == 0 {
		log.Errorf("There are no reproducers for testing")
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

	analyzer.wgFinish.Add(1)

	config := analyzer.pools[0].config

	analyzer.programs = loadPrograms(config.Target, flag.Args())

	server, err := createRPCServer(config.RPC, analyzer)

	if err != nil {
		log.Fatalf("%v", err)
	}
	analyzer.server = server

	analyzer.initializeTasks(*flagRepeats)

	exe := config.SysTarget.ExeExtension
	runnerBin := filepath.Join(config.Syzkaller, "bin", config.Target.OS+"_"+config.Target.Arch, "syz-runner"+exe)
	if !osutil.IsExist(runnerBin) {
		log.Fatalf("bad syzkaller config: can't find %v", runnerBin)
	}
	analyzer.runnerBin = runnerBin

	executorBin := config.ExecutorBin
	if !osutil.IsExist(runnerBin) {
		log.Fatalf("bad syzkaller config: can't find %v", executorBin)
	}
	analyzer.executorBin = executorBin

	var sw io.Writer
	if *flagStats == "" {
		sw = os.Stdout
	} else {
		currentDir, err := filepath.Abs(filepath.Dir(os.Args[0]))
		if err != nil {
			log.Fatalf("failed to create stats file: %v", err)
		}
		file := filepath.Join(currentDir, *flagStats)
		sw, err = os.Create(file)
		if err != nil {
			log.Fatalf("failed to create stats file: %v", err)
		}
	}
	analyzer.statistics = initStatistics(len(pools), sw)

	analyzer.initializeInstances()

	analyzer.wgFinish.Wait()

	analyzer.statistics.printStatistics()
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

func (analyzer *Analyzer) initializeTasks(repeat int) {
	for poolID, pool := range analyzer.pools {
		count := pool.pool.Count()
		for vmID := 0; vmID < count; vmID++ {
			analyzer.addTasks(vmKey(poolID, vmID), analyzer.programs, repeat)
		}
	}
}

func (analyzer *Analyzer) addTasks(vmID int, programs []*prog.Prog, repeat int) {
	for programID, _ := range programs {
		for i := 0; i < repeat; i++ {
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
