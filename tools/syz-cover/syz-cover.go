// Copyright 2018 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

// syz-cover generates coverage HTML report from raw coverage files.
// Raw coverage files are text files with one PC in hex form per line, e.g.:
//
//	0xffffffff8398658d
//	0xffffffff839862fc
//	0xffffffff8398633f
//
// Raw coverage files can be obtained either from /rawcover manager HTTP handler,
// or from syz-execprog with -coverfile flag.
//
// Usage:
//
//	syz-cover -config config_file rawcover.file*
//
// or use all pcs in rg.Symbols
//
//	syz-cover -config config_file
package main

import (
	"bufio"
	"bytes"
	"encoding/json"
	"flag"
	"os"
	"os/exec"
	"strconv"
	"strings"

	"github.com/google/syzkaller/pkg/cover"
	"github.com/google/syzkaller/pkg/host"
	"github.com/google/syzkaller/pkg/mgrconfig"
	"github.com/google/syzkaller/pkg/osutil"
	"github.com/google/syzkaller/pkg/tool"
)

func main() {
	var (
		flagConfig  = flag.String("config", "", "configuration file")
		flagModules = flag.String("modules", "",
			"modules info obtained from /modules or file from /proc/modules (optional)")
		flagExportCSV      = flag.String("csv", "", "export coverage data in csv format (optional)")
		flagExportLineJSON = flag.String("json", "", "export coverage data with source line info in json format (optional)")
		flagExportHTML     = flag.String("html", "", "save coverage HTML report to file (optional)")
	)
	defer tool.Init()()

	cfg, err := mgrconfig.LoadFile(*flagConfig)
	if err != nil {
		tool.Fail(err)
	}
	var modules []host.KernelModule
	if *flagModules != "" {
		m, err := loadModules(*flagModules)
		if err != nil {
			tool.Fail(err)
		}
		modules = m
	}
	rg, err := cover.MakeReportGenerator(cfg, cfg.KernelSubsystem, modules, false)
	if err != nil {
		tool.Fail(err)
	}
	var pcs []uint64
	if len(flag.Args()) == 0 {
		for _, s := range rg.Symbols {
			pcs = append(pcs, s.PCs...)
		}
	} else {
		pcs, err = readPCs(flag.Args())
		if err != nil {
			tool.Fail(err)
		}
	}
	progs := []cover.Prog{{PCs: pcs}}
	buf := new(bytes.Buffer)
	if *flagExportCSV != "" {
		if err := rg.DoCSV(buf, progs, nil); err != nil {
			tool.Fail(err)
		}
		if err := osutil.WriteFile(*flagExportCSV, buf.Bytes()); err != nil {
			tool.Fail(err)
		}
		return
	}
	if *flagExportLineJSON != "" {
		if err := rg.DoLineJSON(buf, progs, nil); err != nil {
			tool.Fail(err)
		}
		if err := osutil.WriteFile(*flagExportLineJSON, buf.Bytes()); err != nil {
			tool.Fail(err)
		}
		return
	}
	if err := rg.DoHTML(buf, progs, nil); err != nil {
		tool.Fail(err)
	}
	if *flagExportHTML != "" {
		if err := osutil.WriteFile(*flagExportHTML, buf.Bytes()); err != nil {
			tool.Fail(err)
		}
		return
	}
	fn, err := osutil.TempFile("syz-cover")
	if err != nil {
		tool.Fail(err)
	}
	fn += ".html"
	if err := osutil.WriteFile(fn, buf.Bytes()); err != nil {
		tool.Fail(err)
	}
	if err := exec.Command("xdg-open", fn).Start(); err != nil {
		tool.Failf("failed to start browser: %v", err)
	}
}

func readPCs(files []string) ([]uint64, error) {
	var pcs []uint64
	for _, file := range files {
		data, err := os.ReadFile(file)
		if err != nil {
			return nil, err
		}
		for s := bufio.NewScanner(bytes.NewReader(data)); s.Scan(); {
			line := strings.TrimSpace(s.Text())
			if line == "" {
				continue
			}
			pc, err := strconv.ParseUint(line, 0, 64)
			if err != nil {
				return nil, err
			}
			pcs = append(pcs, pc)
		}
	}
	return pcs, nil
}

func loadModules(fname string) ([]host.KernelModule, error) {
	data, err := os.ReadFile(fname)
	if err != nil {
		return nil, err
	}
	var modules []host.KernelModule
	if err := json.Unmarshal(data, &modules); err != nil {
		return host.ParseModulesText(data)
	}
	return modules, nil
}
