// Copyright 2020 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package main

import (
	"context"
	"flag"
	"io/ioutil"

	"github.com/google/syzkaller/dashboard/dashapi"
	"github.com/google/syzkaller/pkg/kcidb"
	"github.com/google/syzkaller/pkg/tool"
)

func main() {
	const (
		origin    = "syzkcidb"
		projectID = "kernelci-production"
		topicName = "playground_kernelci_new"
	)
	var (
		flagCred       = flag.String("cred", "", "application credentials file for KCIDB")
		flagDashClient = flag.String("client", "", "dashboard client")
		flagDashAddr   = flag.String("addr", "", "dashboard address")
		flagDashKey    = flag.String("key", "", "dashboard API key")
		flagBug        = flag.String("bug", "", "bug ID to upload to KCIDB")
	)
	flag.Parse()

	dashboard := dashapi.New(*flagDashClient, *flagDashAddr, *flagDashKey)
	bug, err := dashboard.LoadBug(*flagBug)
	if err != nil {
		tool.Fail(err)
	}

	cred, err := ioutil.ReadFile(*flagCred)
	if err != nil {
		tool.Fail(err)
	}
	kcidb.Validate = true
	client, err := kcidb.NewClient(context.Background(), origin, projectID, topicName, cred)
	if err != nil {
		tool.Fail(err)
	}
	defer client.Close()

	if err := client.Publish(bug); err != nil {
		tool.Fail(err)
	}
}
