package main

import (
	"flag"
	"github.com/google/syzkaller/pkg/ipc"
	"github.com/google/syzkaller/pkg/ipc/ipcconfig"
	"github.com/google/syzkaller/pkg/log"
	"github.com/google/syzkaller/prog"
	_ "github.com/google/syzkaller/sys"
	"os"
	"runtime"
)

var (
	flagOS   = flag.String("os", runtime.GOOS, "target os")
	flagArch = flag.String("arch", runtime.GOARCH, "target architecture")
	//flagExecutor = flag.String("executor", "", "Executor for syz program")
)

func main() {
	flag.Parse()

	target, err := prog.GetTarget(*flagOS, *flagArch)
	if err != nil {
		log.Fatalf("%v", err)
	}
	print(target.OS)
	programs := loadPrograms(target, flag.Args())
	println("Programs parsed: ", len(programs))

	config, execOpts := createConfig(target)

	println("Executor: ", config.Executor)
	for _, program := range programs {
		env, err := ipc.MakeEnv(config, 0)
		if err != nil {
			log.Fatalf("%v", err)
		}
		data := program.Serialize()
		log.Logf(0, "executing program %v:\n%s", 0, data)
		output, info, hanged, err := env.Exec(execOpts, program)
		println("------")
		println(info)
		log.Logf(0, "result: hanged=%v err=%v\n\n%s", hanged, err, output)
		println("------")

	}

	println(config, execOpts)
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
	return progs
}

func createConfig(target *prog.Target) (*ipc.Config, *ipc.ExecOpts) {
	config, execOpts, err := ipcconfig.Default(target)
	if err != nil {
		log.Fatalf("%v", err)
	}
	return config, execOpts
}
