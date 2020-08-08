// Copyright 2015 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package main

import (
	"bufio"
	"bytes"
	"fmt"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/google/syzkaller/pkg/cover"
	"github.com/google/syzkaller/pkg/osutil"
	"github.com/google/syzkaller/sys/targets"
)

var (
	initCoverOnce     sync.Once
	initCoverError    error
	initCoverVMOffset uint32
	reportGenerator   *cover.ReportGenerator
)

func initCover(target *targets.Target, kernelObj, kernelSrc, kernelBuildSrc string) error {
	initCoverOnce.Do(func() {
		if kernelObj == "" {
			initCoverError = fmt.Errorf("kernel_obj is not specified")
			return
		}
		vmlinux := filepath.Join(kernelObj, target.KernelObject)
		reportGenerator, initCoverError = cover.MakeReportGenerator(target, vmlinux, kernelSrc, kernelBuildSrc)
		if initCoverError != nil {
			return
		}
		initCoverVMOffset, initCoverError = getVMOffset(target, vmlinux)
	})
	return initCoverError
}

func coverToPCs(target *targets.Target, cov []uint32) []uint64 {
	pcs := make([]uint64, 0, len(cov))
	for _, pc := range cov {
		fullPC := cover.RestorePC(pc, initCoverVMOffset)
		prevPC := cover.PreviousInstructionPC(target, fullPC)
		pcs = append(pcs, prevPC)
	}
	return pcs
}

func getVMOffset(target *targets.Target, vmlinux string) (uint32, error) {
	if target.OS == "freebsd" {
		return 0xffffffff, nil
	}
	readelf := "readelf"
	if target.Triple != "" {
		readelf = target.Triple + "-" + readelf
	}
	out, err := osutil.RunCmd(time.Hour, "", readelf, "-SW", vmlinux)
	if err != nil {
		return 0, err
	}
	s := bufio.NewScanner(bytes.NewReader(out))
	var addr uint32
	for s.Scan() {
		ln := s.Text()
		pieces := strings.Fields(ln)
		for i := 0; i < len(pieces); i++ {
			if pieces[i] != "PROGBITS" {
				continue
			}
			v, err := strconv.ParseUint("0x"+pieces[i+1], 0, 64)
			if err != nil {
				return 0, fmt.Errorf("failed to parse addr in readelf output: %v", err)
			}
			if v == 0 {
				continue
			}
			v32 := (uint32)(v >> 32)
			if addr == 0 {
				addr = v32
			}
			if addr != v32 {
				return 0, fmt.Errorf("different section offsets in a single binary")
			}
		}
	}
	return addr, nil
}
