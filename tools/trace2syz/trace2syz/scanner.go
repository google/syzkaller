package trace2syz

import (
	"bufio"
	"fmt"
	"github.com/google/syzkaller/pkg/log"
	"io/ioutil"
	"strconv"
	"strings"
)

const (
	maxBufferSize = 64 * 1024 * 1024 //maxBufferSize is maximum size for buffer
	coverDelim    = ","              //Delimiter to split instructions in trace e.g. Cover:0x734,0x735
	coverID       = "Cover:"         //CoverID is the indicator that the line in the trace is the coverage
	sysrestart    = "ERESTART"       //SYSRESTART corresponds to the error code of ERESTART.
	signalPlus    = "+++"            //SignalPlus marks +++
	signalMinus   = "---"            //SignalPlus marks ---
	Strace        = "strace"         //Strace
)

func parseIps(line string) []uint64 {
	line = line[1 : len(line)-1] //Remove quotes
	ips := strings.Split(strings.Split(line, coverID)[1], coverDelim)
	coverSet := make(map[uint64]bool)
	cover := make([]uint64, 0)
	for _, ins := range ips {
		if strings.TrimSpace(ins) == "" {
			continue
		} else {
			ip, err := strconv.ParseUint(strings.TrimSpace(ins), 0, 64)
			if err != nil {
				panic(fmt.Sprintf("failed parsing ip: %s", ins))
			}
			if _, ok := coverSet[ip]; !ok {
				coverSet[ip] = true
				cover = append(cover, ip)
			}
		}
	}
	return cover
}

func parseSyscall(scanner *bufio.Scanner, traceType string) (int, *Syscall) {
	if strings.ToLower(traceType) == Strace {
		lex := newStraceLexer(scanner.Bytes())
		ret := StraceParse(lex)
		return ret, lex.result
	}
	return -1, nil
}

func parseLoop(scanner *bufio.Scanner, traceType string) (tree *TraceTree) {
	tree = NewTraceTree()
	//Creating the process tree
	var lastCall *Syscall
	for scanner.Scan() {
		line := scanner.Text()
		restart := strings.Contains(line, sysrestart)
		signalPlus := strings.Contains(line, signalPlus)
		signalMinus := strings.Contains(line, signalMinus)
		shouldSkip := restart || signalPlus || signalMinus
		if shouldSkip {
			continue
		} else if strings.Contains(line, coverID) {
			cover := parseIps(line)
			log.Logf(4, "Cover: %d", len(cover))
			//fmt.Printf("Cover: %d\n", len(cover))
			lastCall.Cover = cover
			continue

		} else {
			log.Logf(4, "Scanning call: %s\n", line)
			ret, call := parseSyscall(scanner, traceType)
			if ret != 0 {
				log.Logf(0, "Error parsing line: %s\n", line)
			}
			if call == nil {
				log.Fatalf("Failed to parse line: %s\n", line)
			}
			lastCall = tree.Add(call)
			//trace.Calls = append(trace.Calls, call)
			//fmt.Printf("result: %v\n", lex.result.CallName)
		}
	}
	if len(tree.Ptree) == 0 {
		return nil
	}
	return
}

//Parse parses a trace of system calls and returns an intermediate representation
func Parse(filename string, traceType string) *TraceTree {
	var data []byte
	var err error

	if data, err = ioutil.ReadFile(filename); err != nil {
		log.Fatalf("error reading file: %s\n", err.Error())
	}
	buf := make([]byte, maxBufferSize)
	scanner := bufio.NewScanner(strings.NewReader(string(data)))
	scanner.Buffer(buf, maxBufferSize)

	tree := parseLoop(scanner, traceType)
	if tree != nil {
		tree.Filename = filename
	}
	return tree
}
