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
	"time"

	"cloud.google.com/go/civil"
	"github.com/google/syzkaller/pkg/cover"
	"github.com/google/syzkaller/pkg/mgrconfig"
	"github.com/google/syzkaller/pkg/osutil"
	"github.com/google/syzkaller/pkg/tool"
	"github.com/google/syzkaller/pkg/vminfo"
)

var (
	flagConfig  = flag.String("config", "", "configuration file")
	flagModules = flag.String("modules", "",
		"modules JSON info obtained from /modules (optional)")
	flagExportCSV        = flag.String("csv", "", "export coverage data in csv format (optional)")
	flagExportLineJSON   = flag.String("json", "", "export coverage data with source line info in json format (optional)")
	flagExportJSONL      = flag.String("jsonl", "", "export jsonl coverage data (optional)")
	flagExportHTML       = flag.String("html", "", "save coverage HTML report to file (optional)")
	flagNsHeatmap        = flag.String("heatmap", "", "generate namespace heatmap")
	flagNsHeatmapGroupBy = flag.String("group-by", "dir", "dir or subsystem")
	flagDateFrom         = flag.String("from",
		civil.DateOf(time.Now().Add(-14*24*time.Hour)).String(), "heatmap date from(optional)")
	flagDateTo = flag.String("to",
		civil.DateOf(time.Now()).String(), "heatmap date to(optional)")
	flagProjectID = flag.String("project", "syzkaller", "spanner db project name")
)

func toolBuildNsHeatmap() {
	buf := new(bytes.Buffer)
	var dateFrom, dateTo civil.Date
	var err error
	if dateFrom, err = civil.ParseDate(*flagDateFrom); err != nil {
		tool.Failf("failed to parse date from: %v", err.Error())
	}
	if dateTo, err = civil.ParseDate(*flagDateTo); err != nil {
		tool.Failf("failed to parse date to: %v", err.Error())
	}
	switch *flagNsHeatmapGroupBy {
	case "dir":
		if err = cover.DoDirHeatMap(buf, *flagProjectID, *flagNsHeatmap, dateFrom, dateTo); err != nil {
			tool.Fail(err)
		}
	case "subsystem":
		if err = cover.DoSubsystemsHeatMap(buf, *flagProjectID, *flagNsHeatmap, dateFrom, dateTo); err != nil {
			tool.Fail(err)
		}
	default:
		tool.Failf("group by %s not supported", *flagNsHeatmapGroupBy)
	}
	if err = osutil.WriteFile(*flagNsHeatmap+".html", buf.Bytes()); err != nil {
		tool.Fail(err)
	}
}

func main() {
	defer tool.Init()()
	if *flagNsHeatmap != "" {
		toolBuildNsHeatmap()
		return
	}
	cfg, err := mgrconfig.LoadFile(*flagConfig)
	if err != nil {
		tool.Fail(err)
	}
	var modules []*vminfo.KernelModule
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
	params := cover.HandlerParams{
		Progs: progs,
	}
	if *flagExportCSV != "" {
		if err := rg.DoCSV(buf, params); err != nil {
			tool.Fail(err)
		}
		if err := osutil.WriteFile(*flagExportCSV, buf.Bytes()); err != nil {
			tool.Fail(err)
		}
		return
	}
	if *flagExportLineJSON != "" {
		if err := rg.DoLineJSON(buf, params); err != nil {
			tool.Fail(err)
		}
		if err := osutil.WriteFile(*flagExportLineJSON, buf.Bytes()); err != nil {
			tool.Fail(err)
		}
		return
	}
	if *flagExportJSONL != "" {
		if err := rg.DoCoverJSONL(buf, params); err != nil {
			tool.Fail(err)
		}
		if err := osutil.WriteFile(*flagExportJSONL, buf.Bytes()); err != nil {
			tool.Fail(err)
		}
		return
	}
	if err := rg.DoHTML(buf, params); err != nil {
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

func loadModules(fname string) ([]*vminfo.KernelModule, error) {
	data, err := os.ReadFile(fname)
	if err != nil {
		return nil, err
	}
	var modules []*vminfo.KernelModule
	err = json.Unmarshal(data, &modules)
	if err != nil {
		return nil, err
	}
	return modules, nil
}
