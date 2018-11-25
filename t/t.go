package main

import "fmt"
import "github.com/google/syzkaller/pkg/build"

func main() {
	fmt.Printf("Error %v\n", build.CopyKernelToImage("."))
}
