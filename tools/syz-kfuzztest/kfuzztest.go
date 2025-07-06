package main

import (
	"flag"
	"fmt"
	"github.com/google/syzkaller/pkg/kfuzztest"
)

var (
	vmlinuxPath = flag.String("vmlinux", "", "Path to vmlinux binary.")
)

func main() {
	flag.Parse()

	prog, err := kfuzztest.ExtractProg(*vmlinuxPath)
	if err != nil {
		panic(err)
	}

	fmt.Printf("%d syscalls and %d types\n", len(prog.Syscalls), len(prog.Types))

	fmt.Printf("dumping program syscalls\n")
	for _, syscall := range prog.Syscalls {
		fmt.Printf("\t%s, with ID = %d & NR = %d\n", syscall.Name, syscall.ID, syscall.NR)
	}

	fmt.Printf("dumping program types\n")
	for _, typ := range prog.Types {
		fmt.Printf("\t%s\n", typ.TemplateName())
	}
}
