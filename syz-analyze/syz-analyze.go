package main

import (
  "flag"
  "github.com/google/syzkaller/pkg/log"
  "github.com/google/syzkaller/prog"
  "os"
  "runtime"
	_ "github.com/google/syzkaller/sys"
)

var (
  flagOS       = flag.String("os", runtime.GOOS, "target os")
  flagArch     = flag.String("arch", runtime.GOARCH, "target architecture")
  flagExecutor = flag.String("executor", "", "Executor for syz program")
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
}

func loadPrograms(target *prog.Target, files []string) []*prog.Prog {
	var progs []*prog.Prog
  for _, filePath := range files {
    data, err := os.ReadFile(filePath)
    if err != nil {
      log.Fatal(err)
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
