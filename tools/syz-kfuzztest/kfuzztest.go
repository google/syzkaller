package main

import (
	"flag"
	"github.com/google/syzkaller/pkg/kfuzztest"
)

var (
	vmlinuxPath = flag.String("vmlinux", "", "Path to vmlinux binary.")
)

func main() {
	flag.Parse()

	_, err := kfuzztest.ExtractProg(*vmlinuxPath)
	if err != nil {
		panic(err)
	}
}
