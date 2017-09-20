// Copyright 2017 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package main

import (
	"os"
	"os/signal"
	"sync/atomic"
	"syscall"

	"github.com/google/syzkaller/pkg/log"
)

func handleInterrupt(shutdown *uint32) {
	c := make(chan os.Signal, 2)
	signal.Notify(c, syscall.SIGINT)
	<-c
	log.Logf(0, "shutting down...")
	atomic.StoreUint32(shutdown, 1)
	<-c
	log.Fatalf("terminating")
}
