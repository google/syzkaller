package main

import (
	"github.com/google/syzkaller/pkg/log"
	"github.com/google/syzkaller/prog"
	"io"
	"os"
	"strings"
)

func BuildTable(target *prog.Target) {
	file, err := os.Open(VocabPath)
	if err != nil {
		log.Fatal(err)
	}
	defer file.Close()

	// Read the file content
	content, err := io.ReadAll(file)
	if err != nil {
		log.Fatal(err)
	}

	addrGenerator := *prog.GetAddrGeneratorInstance()
	addrCnt := 0

	textCalls := strings.Split(string(content), "[SEP]\n")
	for _, textC := range textCalls {
		program, err := target.Deserialize([]byte(textC), prog.NonStrict)
		if err != nil {
			log.Fatalf("Deserialize failed: %v", textC)
		}

		addrGenerator.ResetCounter()
		for _, call := range program.Calls {
			_, ok := addrGenerator.AddrBase[call.Meta.Name]
			if !ok {
				fields := call.Meta.Args
				for j, _arg := range call.Args {
					switch arg := _arg.(type) {
					case *prog.ResultArg:
						continue
					default:
						argReplacer := *prog.NewArgReplacer(call.Meta.Name, true)
						argReplacer.DFSArgs(arg, fields[j])
						addrCnt += argReplacer.InitAddrCnt
					}
				}
			}
		}
	}

	BuildCallMeta(target)

	log.Logf(0, "Build arg table done: %v", addrCnt)
}

const VocabPath = "/root/data/"

func BuildCallMeta(target *prog.Target) {
	callMetaInstance := prog.GetCallMetaInstance()
	for _, s := range target.Syscalls {
		callMetaInstance.Set(s.Name, s)
	}
}
