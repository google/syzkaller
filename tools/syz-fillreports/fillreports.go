// Copyright 2023 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

// syz-fillreports queries all open bugs from a namespace, extracts the missing reporting elements
// (currently only missing guilty files are supported) and uploads them back to the dashboard.

package main

import (
	"flag"
	"log"
	"sync"

	"github.com/google/syzkaller/dashboard/dashapi"
	"github.com/google/syzkaller/pkg/mgrconfig"
	"github.com/google/syzkaller/pkg/report"
	_ "github.com/google/syzkaller/sys"
	"github.com/google/syzkaller/sys/targets"
)

var (
	flagDashboard = flag.String("dashboard", "https://syzkaller.appspot.com", "dashboard address")
	flagAPIClient = flag.String("client", "", "the name of the API client")
	flagAPIKey    = flag.String("key", "", "api key")
)

func main() {
	flag.Parse()

	dash, err := dashapi.New(*flagAPIClient, *flagDashboard, *flagAPIKey)
	if err != nil {
		log.Fatalf("dashapi failed: %v", err)
	}
	resp, err := dash.BugList()
	if err != nil {
		log.Fatalf("bug list query failed: %v", err)
	}
	workItems := loadBugReports(dash, resp.List)
	for item := range workItems {
		processReport(dash, item.report, item.bugID)
	}
}

func processReport(dash *dashapi.Dashboard, bugReport *dashapi.BugReport, bugID string) {
	if bugReport.ReportElements != nil && len(bugReport.ReportElements.GuiltyFiles) > 0 {
		log.Printf("%v: already has guilty files", bugReport.ID)
		return
	}
	if bugReport.BugStatus != dashapi.BugStatusOpen &&
		bugReport.BugStatus != dashapi.BugStatusFixed {
		log.Printf("%v: status is not BugStatusOpen or BugStatusFixed", bugReport.ID)
		return
	}
	if bugReport.OS == "" || bugReport.Arch == "" {
		log.Printf("%v: OS or Arch is empty", bugReport.ID)
		return
	}
	cfg := &mgrconfig.Config{
		Derived: mgrconfig.Derived{
			TargetOS:   bugReport.OS,
			TargetArch: bugReport.Arch,
			SysTarget:  targets.Get(bugReport.OS, bugReport.Arch),
		},
	}
	reporter, err := report.NewReporter(cfg)
	if err != nil {
		log.Fatalf("%v: failed to create a reporter for %s/%s",
			bugReport.ID, bugReport.OS, bugReport.Arch)
	}
	guiltyFile := reporter.ReportToGuiltyFile(bugReport.Title, bugReport.Report)
	if guiltyFile == "" {
		log.Printf("%v: no guilty files extracted", bugReport.ID)
		return
	}
	err = dash.UpdateReport(&dashapi.UpdateReportReq{
		BugID:       bugID,
		CrashID:     bugReport.CrashID,
		GuiltyFiles: &[]string{guiltyFile},
	})
	if err != nil {
		log.Printf("%v: failed to save: %v", bugReport.ID, err)
	}
	log.Printf("%v: updated", bugReport.ID)
}

type workItem struct {
	report *dashapi.BugReport
	bugID  string
}

func loadBugReports(dash *dashapi.Dashboard, IDs []string) <-chan *workItem {
	const (
		threads = 8
		logStep = 100
	)
	ids := make(chan string)
	ret := make(chan *workItem)
	var wg sync.WaitGroup
	for i := 0; i < threads; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for id := range ids {
				resp, err := dash.LoadBug(id)
				if err != nil {
					log.Printf("%v: failed to load bug: %v", id, err)
					continue
				}
				if resp.ID == "" {
					continue
				}
				ret <- &workItem{
					report: resp,
					bugID:  id,
				}
			}
		}()
	}
	go func() {
		for i, id := range IDs {
			if i%logStep == 0 {
				log.Printf("loaded %d/%d", i, len(IDs))
			}
			ids <- id
		}
		close(ids)
		wg.Wait()
		close(ret)
	}()
	return ret
}
