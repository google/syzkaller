package main

import (
	"bufio"
	"fmt"
	"github.com/google/syzkaller/pkg/log"
	"github.com/google/syzkaller/prog"
	"os"
	"strconv"
	"strings"
)

func BuildTable(target *prog.Target) {
	file, err := os.Open(AddrPath)
	if err != nil {
		log.Fatal(err)
	}
	defer file.Close()

	addrGenerator := *prog.GetAddrGeneratorInstance()
	addrCnt := 0

	maxAddr := uint64(0)

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := scanner.Text()

		// Split the line into key and value based on space
		parts := strings.Split(line, " ")
		if len(parts) != 2 {
			fmt.Println("Invalid line:", line)
			continue
		}

		// Parse the string value to uint64
		value, err := strconv.ParseUint(parts[1], 10, 64)
		if err != nil {
			fmt.Println("Error parsing value for key", parts[0], ":", err)
			continue
		}

		if maxAddr < value {
			maxAddr = value
		}

		addrGenerator.AddrBase[parts[0]] = value
		addrGenerator.AddrCounter[parts[0]] = 0
		addrCnt += 1
	}
	addrGenerator.AddrBase["[UNK]"] = maxAddr + 0x80
	addrGenerator.AddrCounter["[UNK]"] = 0

	BuildCallMeta(target)

	log.Logf(0, "Build arg table done: %v", addrCnt)
}

const AddrPath = "/root/data/addr.txt"

func BuildCallMeta(target *prog.Target) {
	callMetaInstance := prog.GetCallMetaInstance()
	for _, s := range target.Syscalls {
		callMetaInstance.Set(s.Name, s)
	}
}
