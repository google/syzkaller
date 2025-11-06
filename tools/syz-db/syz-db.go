// Copyright 2017 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package main

import (
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/google/syzkaller/pkg/db"
	"github.com/google/syzkaller/pkg/hash"
	"github.com/google/syzkaller/pkg/osutil"
	"github.com/google/syzkaller/pkg/tool"
	"github.com/google/syzkaller/prog"
	_ "github.com/google/syzkaller/sys"
	"golang.org/x/exp/maps"
)

func main() {
	var (
		flagVersion = flag.Uint64("version", 0, "database version")
		flagOS      = flag.String("os", runtime.GOOS, "target OS")
		flagArch    = flag.String("arch", runtime.GOARCH, "target arch")
	)
	flag.Parse()
	args := flag.Args()
	if len(args) == 0 {
		usage()
	}
	if args[0] == "bench" {
		if len(args) != 2 {
			usage()
		}
		target, err := prog.GetTarget(*flagOS, *flagArch)
		if err != nil {
			tool.Failf("failed to find target: %v", err)
		}
		bench(target, args[1])
		return
	}
	var target *prog.Target
	if *flagOS != "" || *flagArch != "" {
		var err error
		target, err = prog.GetTarget(*flagOS, *flagArch)
		if err != nil {
			tool.Failf("failed to find target: %v", err)
		}
	}
	switch args[0] {
	case "pack":
		if len(args) != 3 {
			usage()
		}
		pack(args[1], args[2], target, *flagVersion)
	case "unpack":
		if len(args) != 3 {
			usage()
		}
		unpack(args[1], args[2])
	case "merge":
		if len(args) < 3 {
			usage()
		}
		merge(args[1], args[2:], target)
	case "print":
		if len(args) != 2 {
			usage()
		}
		print(args[1])
	case "rm":
		if len(args) != 3 {
			usage()
		}
		rm(args[1], args[2], target)
	default:
		usage()
	}
}

func usage() {
	fmt.Fprintf(os.Stderr, `usage: syz-db can be used to manipulate corpus
databases that are used by syz-managers. The following generic arguments are
offered:
  -arch string
  -os string
  -version uint
  -vv int

  they can be used for:
  packing a database:
    syz-db pack dir corpus.db
  unpacking a database. A file containing performed syscalls will be returned:
    syz-db unpack corpus.db dir
  merging databases. No additional file will be created: The first file will be replaced by the merged result:
    syz-db merge dst-corpus.db add-corpus.db* add-prog*
  running a deserialization benchmark and printing corpus stats:
    syz-db bench corpus.db
  print corpus db:
    syz-db print corpus.db
  remove a syscall from db
    syz-db rm corpus.db syscall_name
`)
	os.Exit(1)
}

func pack(dir, file string, target *prog.Target, version uint64) {
	files, err := os.ReadDir(dir)
	if err != nil {
		tool.Failf("failed to read dir: %v", err)
	}
	var records []db.Record
	for _, file := range files {
		data, err := os.ReadFile(filepath.Join(dir, file.Name()))
		if err != nil {
			tool.Failf("failed to read file %v: %v", file.Name(), err)
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
			if target != nil {
				p, err := target.Deserialize(data, prog.NonStrict)
				if err != nil {
					tool.Failf("failed to deserialize %v: %v", file.Name(), err)
				}
				data = p.Serialize()
				sig = hash.String(data)
			}
			fmt.Fprintf(os.Stderr, "fixing hash %v -> %v\n", key, sig)
			key = sig
		}
		records = append(records, db.Record{
			Val: data,
			Seq: seq,
		})
	}
	if err := db.Create(file, version, records); err != nil {
		tool.Fail(err)
	}
}

func unpack(file, dir string) {
	db, err := db.Open(file, false)
	if err != nil {
		tool.Failf("failed to open database: %v", err)
	}
	osutil.MkdirAll(dir)
	for key, rec := range db.Records {
		fname := filepath.Join(dir, key)
		if rec.Seq != 0 {
			fname += fmt.Sprintf("-%v", rec.Seq)
		}
		if err := osutil.WriteFile(fname, rec.Val); err != nil {
			tool.Failf("failed to output file: %v", err)
		}
	}
}

func merge(file string, adds []string, target *prog.Target) {
	failures, err := db.Merge(file, adds, target)
	if err != nil {
		tool.Failf("%s", err)
	}
	if len(failures) > 0 {
		for _, fail := range failures {
			fmt.Printf("failed to deserialize a record from %s: %s\n", fail.File, fail.Err)
		}
		tool.Failf("there have been deserialization errors")
	}
}

func bench(target *prog.Target, file string) {
	start := time.Now()
	db, err := db.Open(file, false)
	if err != nil {
		tool.Failf("failed to open database: %v", err)
	}
	var corpus []*prog.Prog
	for _, rec := range db.Records {
		p, err := target.Deserialize(rec.Val, prog.NonStrict)
		if err != nil {
			tool.Failf("failed to deserialize: %v\n%s", err, rec.Val)
		}
		corpus = append(corpus, p)
	}
	runtime.GC()
	var stats runtime.MemStats
	runtime.ReadMemStats(&stats)
	fmt.Printf("allocs %v MB (%v M), next GC %v MB, sys heap %v MB, live allocs %v MB (%v M), time %v\n",
		stats.TotalAlloc>>20,
		stats.Mallocs>>20,
		stats.NextGC>>20,
		stats.HeapSys>>20,
		stats.Alloc>>20,
		(stats.Mallocs-stats.Frees)>>20,
		time.Since(start))
	n := len(corpus)
	fmt.Printf("corpus size: %v\n", n)
	if n == 0 {
		return
	}
	sum := 0
	lens := make([]int, n)
	for i, p := range corpus {
		sum += len(p.Calls)
		lens[i] = len(p.Calls)
	}
	sort.Ints(lens)
	fmt.Printf("program size: min=%v avg=%v max=%v 10%%=%v 50%%=%v 90%%=%v\n",
		lens[0], sum/n, lens[n-1], lens[n/10], lens[n/2], lens[n*9/10])
}

func print(file string) {
	db, err := db.Open(file, false)
	if err != nil {
		tool.Failf("failed to open database: %v", err)
	}
	keys := maps.Keys(db.Records)
	sort.Strings(keys)
	for _, key := range keys {
		rec := db.Records[key]
		fmt.Printf("%v\n%v\n", key, string(rec.Val))
	}
}

func rm(file, syscall string, target *prog.Target) {
	db, err := db.Open(file, false)
	if err != nil {
		tool.Failf("failed to open database: %w", err)
	}
	for key, rec := range db.Records {
		p, err := target.Deserialize(rec.Val, prog.NonStrict)
		if err != nil {
			tool.Failf("failed to deserialize: %w\n%s", err, rec.Val)
		}
		for i := len(p.Calls) - 1; i >= 0; i-- {
			if strings.Contains(p.Calls[i].Meta.Name, syscall) {
				p.RemoveCall(i)
			}
		}
		data := p.Serialize()
		if len(data) > 0 {
			db.Save(key, data, rec.Seq)
		} else {
			delete(db.Records, key)
		}
	}
	if err := db.Flush(); err != nil {
		tool.Fail(err)
	}
}
