// Copyright 2020 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

// Package tool contains various helper utilitites useful for implementation of command line tools.
package tool

import (
	"flag"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
)

// Init handles common tasks for command line tools:
//   - invokes flag.Parse
//   - adds support for optional flags (see OptionalFlags)
//   - adds support for cpu/mem profiling (-cpuprofile/memprofile flags)
//
// Use as defer tool.Init()().
func Init() func() {
	flagCPUProfile := flag.String("cpuprofile", "", "write CPU profile to this file")
	flagMEMProfile := flag.String("memprofile", "", "write memory profile to this file")
	if err := ParseFlags(flag.CommandLine, os.Args[1:]); err != nil {
		Fail(err)
	}
	return installProfiling(*flagCPUProfile, *flagMEMProfile)
}

// ServeHTPP serves default http mux on the specified address in a separate goroutine.
// Terminates the process on any errors.
func ServeHTTP(addr string) {
	ln, err := net.Listen("tcp4", addr)
	if err != nil {
		log.Fatalf("failed to listen on %v: %v", addr, err)
	}
	log.Printf("serving http on http://%v", ln.Addr())
	go func() {
		err := http.Serve(ln, nil)
		log.Fatalf("failed to serve http: %v", err)
	}()
}

func Failf(msg string, args ...any) {
	fmt.Fprintf(os.Stderr, msg+"\n", args...)
	os.Exit(1)
}

func Fail(err error) {
	Failf("%v", err)
}
