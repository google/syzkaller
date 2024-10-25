// Copyright 2019 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"os"
	"path"
	"strings"

	"github.com/google/syzkaller/dashboard/api"
	"golang.org/x/sync/errgroup"
)

var (
	flagDashboard = flag.String("dashboard", "https://syzkaller.appspot.com", "dashboard address")
	flagOutputDir = flag.String("output", "repros", "output dir")
	flagNamespace = flag.String("namespace", "upstream", "target namespace")
	flagToken     = flag.String("token", "", "gcp bearer token to disable throttling (contact syzbot first)\n"+
		"usage example: ./tools/syz-reprolist -namespace upstream -token $(gcloud auth print-access-token)")
	flagParallel = flag.Int("j", 2, "number of parallel threads")
)

func main() {
	flag.Parse()
	if err := os.MkdirAll(*flagOutputDir, 0755); err != nil {
		log.Fatalf("alert: failed to create output dir: %v", err)
	}
	if *flagNamespace == "" {
		log.Fatal("alert: namespace can't be empty")
	}
	if err := exportNamespace(); err != nil {
		log.Fatalf("alert: error: %s", err.Error())
	}
}

func exportNamespace() error {
	cli := api.NewClient(*flagDashboard, *flagToken)
	bugs, err := cli.BugGroups(*flagNamespace, api.BugGroupOpen|api.BugGroupFixed)
	if err != nil {
		return err
	}
	fmt.Printf("total %d bugs available\n", len(bugs))

	iBugChan := make(chan int)
	g, _ := errgroup.WithContext(context.Background())
	for i := 0; i < *flagParallel; i++ {
		i := i
		g.Go(func() error {
			for iBug := range iBugChan {
				bug, err := cli.Bug(bugs[iBug].Link)
				if err != nil {
					return err
				}
				cReproURL := bug.Crashes[0].CReproducerLink // export max 1 CRepro per bug
				if cReproURL == "" {
					continue
				}
				reproID := reproIDFromURL(cReproURL)
				fmt.Printf("[%v](%v/%v)saving c-repro %v for bug %v\n",
					i, iBug, len(bugs), reproID, bug.ID)
				cReproBody, err := cli.Text(cReproURL)
				if err != nil {
					return err
				}
				if err := saveCRepro(reproID, cReproBody); err != nil {
					return fmt.Errorf("saveRepro(bugID=%s, reproID=%s): %w", bug.ID, reproID, err)
				}
			}
			return nil
		})
	}
	errChan := make(chan error)
	go func() {
		errChan <- g.Wait()
	}()
	for iBug := range bugs {
		select {
		case iBugChan <- iBug:
		case err := <-errChan:
			return err
		}
	}
	close(iBugChan)
	return g.Wait()
}

func saveCRepro(reproID string, reproData []byte) error {
	reproPath := path.Join(*flagOutputDir, reproID+".c")
	if err := os.WriteFile(reproPath, reproData, 0666); err != nil {
		return fmt.Errorf("os.WriteFile: %w", err)
	}
	return nil
}

func reproIDFromURL(url string) string {
	parts := strings.Split(url, "&")
	if len(parts) != 2 {
		log.Panicf("can't split %s in two parts by ?", url)
	}
	parts = strings.Split(parts[1], "=")
	if len(parts) != 2 {
		log.Panicf("can't split %s in two parts by =", url)
	}
	return parts[1]
}
