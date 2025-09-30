// Copyright 2020 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package main

import (
	"context"
	"encoding/json"
	"flag"
	"os"

	"github.com/google/syzkaller/dashboard/dashapi"
	"github.com/google/syzkaller/pkg/kcidb"
	"github.com/google/syzkaller/pkg/tool"
)

func main() {
	const (
		origin    = "syzbot"
		projectID = "kernelci-production"
		topicName = "playground_kernelci_new"
	)
	var (
		flagRestURI    = flag.String("rest", "", "REST API endpoint for KCIDB")
		flagToken      = flag.String("token", "", "KCIDB API token")
		flagDashClient = flag.String("client", "", "dashboard client")
		flagDashAddr   = flag.String("addr", "", "dashboard address")
		flagDashKey    = flag.String("key", "", "dashboard API key")
		flagBug        = flag.String("bug", "", "bug ID to upload to KCIDB")
		flagInput      = flag.String("input", "", "input JSON file with bug report")
		flagOutput     = flag.String("output", "", "output JSON file for KCIDB data")
	)
	flag.Parse()

	var bug *dashapi.BugReport

	// If input file is specified, read from file instead of calling API
	if *flagInput != "" {
		data, err := os.ReadFile(*flagInput)
		if err != nil {
			tool.Fail(err)
		}
		bug = &dashapi.BugReport{}
		if err := json.Unmarshal(data, bug); err != nil {
			tool.Fail(err)
		}
	} else {
		// Original behavior: fetch from dashboard API
		dash, err := dashapi.New(*flagDashClient, *flagDashAddr, *flagDashKey)
		if err != nil {
			tool.Fail(err)
		}
		bug, err = dash.LoadBug(*flagBug)
		if err != nil {
			tool.Fail(err)
		}
	}

	kcidb.Validate = true
	client, err := kcidb.NewClient(context.Background(), origin, *flagRestURI, *flagToken)
	if err != nil {
		tool.Fail(err)
	}
	defer client.Close()

	// If output file is specified, write to file instead of submitting.
	if *flagOutput != "" {
		if err := client.PublishToFile(bug, *flagOutput); err != nil {
			tool.Fail(err)
		}
	} else {
		// Original behavior: submit to REST API
		if err := client.Publish(bug); err != nil {
			tool.Fail(err)
		}
	}
}
