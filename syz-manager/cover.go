// Copyright 2015 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package main

import (
	"bufio"
	"bytes"
	"fmt"
	"io"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/google/syzkaller/pkg/cover"
	"github.com/google/syzkaller/pkg/osutil"
)

var (
	initCoverOnce     sync.Once
	initCoverError    error
	initCoverVMOffset uint32
	reportGenerator   *cover.ReportGenerator
)

func initCover(kernelObj, kernelObjName, kernelSrc, arch, OS string) error {
	if kernelObj == "" {
		return fmt.Errorf("kernel_obj is not specified")
	}
	vmlinux := filepath.Join(kernelObj, kernelObjName)
	var err error
	reportGenerator, err = cover.MakeReportGenerator(vmlinux, kernelSrc, arch)
	if err != nil {
		return err
	}
	initCoverVMOffset, err = getVMOffset(vmlinux, OS)
	return err
}

func generateCoverHTML(w io.Writer, kernelObj, kernelObjName, kernelSrc, arch, OS string, cov cover.Cover) error {
	if len(cov) == 0 {
		return fmt.Errorf("no coverage data available")
	}
	initCoverOnce.Do(func() { initCoverError = initCover(kernelObj, kernelObjName, kernelSrc, arch, OS) })
	if initCoverError != nil {
		return initCoverError
	}
	pcs := make([]uint64, 0, len(cov))
	for pc := range cov {
		pcs = append(pcs, cover.RestorePC(pc, initCoverVMOffset))
	}
	return reportGenerator.Do(w, pcs)
}

func getVMOffset(vmlinux, OS string) (uint32, error) {
	if OS == "freebsd" {
		return 0xffffffff, nil
	}
	out, err := osutil.RunCmd(time.Hour, "", "readelf", "-SW", vmlinux)
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
