package main

import (
	"flag"
	"fmt"
	"github.com/google/syzkaller/pkg/db"
	"github.com/google/syzkaller/pkg/hash"
	"github.com/google/syzkaller/pkg/log"
	"github.com/google/syzkaller/prog"
	"github.com/google/syzkaller/sys"
	"github.com/shankarapailoor/moonshine/trace2syz/trace2syz"
	"io/ioutil"
	"os"
	"path"
	"path/filepath"
	"strconv"
	"strings"
)

var (
	flagFile      = flag.String("file", "", "file to parse")
	flagDir       = flag.String("dir", "", "director to parse")
	flagTraceType = flag.String("traceType", trace2syz.Strace, "Type of trace e.g., strace, perf")
)

const (
	OS               = "linux" //Target OS
	Arch             = "amd64" //Target architecture
	currentDBVersion = 3       //Marked as minimized
)

func main() {
	rev := sys.GitRevision
	flag.Parse()
	target, err := prog.GetTarget(OS, Arch)
	if err != nil {
		log.Fatalf("error getting target: %v, git revision: %v", err.Error(), rev)
	} else {
		parseTraces(target)
		log.Logf(0, "Successfully converted traces. Generating corpus.db\n")
		pack("deserialized", "corpus.db")
	}
}

func parseTraces(target *prog.Target) []*trace2syz.Context {
	ret := make([]*trace2syz.Context, 0)
	names := make([]string, 0)
	traceType := trace2syz.Strace
	if *flagFile != "" {
		names = append(names, *flagFile)
	} else if *flagDir != "" {
		names = getTraceFiles(*flagDir)
	} else {
		panic("Flag or FlagDir required")
	}

	if *flagTraceType != "" {
		traceType = *flagTraceType
	}

	totalFiles := len(names)
	log.Logf(0, "Parsing %d traces\n", totalFiles)
	for i, file := range names {
		log.Logf(1, "Parsing File %d/%d: %s\n", i+1, totalFiles, path.Base(names[i]))
		tree := trace2syz.Parse(file, traceType)
		if tree == nil {
			log.Logf(1, "File: %s is empty\n", path.Base(file))
			continue
		}
		ctxs := parseTree(tree, tree.RootPid, target)
		ret = append(ret, ctxs...)
		for i, ctx := range ctxs {
			ctx.Prog.Target = ctx.Target
			if err := ctx.FillOutMemory(); err != nil {
				log.Logf(1, "Failed to fill out memory\n")
				continue
			}
			if err := ctx.Prog.Validate(); err != nil {
				panic(fmt.Sprintf("Error validating program: %s\n", err.Error()))
			}
			if progIsTooLarge(ctx.Prog) {
				log.Logf(1, "Prog is too large\n")
				continue
			}
			progName := "deserialized/" + filepath.Base(file) + strconv.Itoa(i)
			if err := ioutil.WriteFile(progName, ctx.Prog.Serialize(), 0640); err != nil {
				log.Fatalf("failed to output file: %v", err)
			}
		}

	}
	return ret
}

func progIsTooLarge(p *prog.Prog) bool {
	buff := make([]byte, prog.ExecBufferSize)
	if _, err := p.SerializeForExec(buff); err != nil {
		return true
	}
	return false
}

func getTraceFiles(dir string) []string {
	names := make([]string, 0)
	if infos, err := ioutil.ReadDir(dir); err == nil {
		for _, info := range infos {
			name := path.Join(dir, info.Name())
			names = append(names, name)
		}
	} else {
		log.Fatalf("Failed to read dir: %s\n", err.Error())
	}
	return names
}

//parseTree groups system calls in the trace by process id.
//The tree preserves process hierarchy i.e. parent->[]child
func parseTree(tree *trace2syz.TraceTree, pid int64, target *prog.Target) []*trace2syz.Context {
	log.Logf(2, "Parsing trace: %s\n", tree.Filename)
	ctxs := make([]*trace2syz.Context, 0)
	ctx, err := trace2syz.ParseTrace(tree.TraceMap[pid], target)
	parsedProg := ctx.Prog
	if err != nil {
		panic("Failed to parse program")
	}

	if len(parsedProg.Calls) == 0 {
		parsedProg = nil
	}

	if parsedProg != nil {
		ctx.Prog = parsedProg
		ctxs = append(ctxs, ctx)
	}
	for _, childPid := range tree.Ptree[pid] {
		if tree.TraceMap[childPid] != nil {
			ctxs = append(ctxs, parseTree(tree, childPid, target)...)
		}
	}
	return ctxs
}

func pack(dir, file string) {
	log.Logf(0, "Converted traces...Generating corpus.db")
	files, err := ioutil.ReadDir(dir)
	if err != nil {
		log.Fatalf("failed to read dir: %v", err)
	}
	os.Remove(file)
	syzDb, err := db.Open(file)
	syzDb.BumpVersion(currentDBVersion)
	if err != nil {
		log.Fatalf("failed to open database file: %v", err)
	}
	log.Logf(1, "Deserializing programs => deserialized/")
	for _, file := range files {
		data, err := ioutil.ReadFile(filepath.Join(dir, file.Name()))
		if err != nil {
			log.Fatalf("failed to read file %v: %v", file.Name(), err)
		}
		var seq uint64
		key := file.Name()
		if parts := strings.Split(file.Name(), "-"); len(parts) == 2 {
			var err error

			if seq, err = strconv.ParseUint(parts[1], 10, 64); err == nil {
				key = parts[0]
			}
		}
		if sig := hash.String(data); key != sig {
			key = sig
		}
		syzDb.Save(key, data, seq)
	}
	if err := syzDb.Flush(); err != nil {
		log.Fatalf("failed to save database file: %v", err)
	}
	log.Logf(0, "Finished!")
}
