// Copyright 2020 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package kcidb

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"os/exec"
	"strings"
	"time"

	"github.com/google/syzkaller/dashboard/dashapi"
	"github.com/google/syzkaller/sys/targets"
)

type Client struct {
	ctx     context.Context
	origin  string
	resturi string
	token   string
}

// NewClient creates a new client to send pubsub messages to Kcidb.
// Origin is how this system identified in Kcidb, e.g. "syzbot_foobar".
// Project is Kcidb GCE project name, e.g. "kernelci-production".
// Topic is pubsub topic to publish messages to, e.g. "playground_kernelci_new".
// Credentials is Google application credentials file contents to use for authorization.
func NewClient(ctx context.Context, origin, resturi, token string) (*Client, error) {
	c := &Client{
		ctx:     ctx,
		origin:  origin,
		resturi: resturi,
		token:   token,
	}
	return c, nil
}

func (c *Client) Close() error {
	return nil
}

func (c *Client) RESTSubmit(data []byte) error {
	if c.resturi == "" {
		return fmt.Errorf("resturi is not set")
	}
	req, err := http.NewRequest("POST", c.resturi, bytes.NewReader(data))
	if err != nil {
		return fmt.Errorf("failed to create request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+c.token)
	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("failed to send request: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("unexpected response status: %s", resp.Status)
	}
	return nil
}

func (c *Client) Publish(bug *dashapi.BugReport) error {
	target := targets.List[bug.OS][bug.VMArch]
	if target == nil {
		return fmt.Errorf("unsupported OS/arch %v/%v", bug.OS, bug.VMArch)
	}
	data, err := json.MarshalIndent(c.convert(target, bug), "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal kcidb json: %w", err)
	}
	if err := kcidbValidate(data); err != nil {
		return err
	}
	if err := c.RESTSubmit(data); err != nil {
		return fmt.Errorf("failed to submit kcidb json: %w", err)
	}
	return err
}

func (c *Client) PublishToFile(bug *dashapi.BugReport, filename string) error {
	target := targets.List[bug.OS][bug.VMArch]
	if target == nil {
		return fmt.Errorf("unsupported OS/arch %v/%v", bug.OS, bug.VMArch)
	}
	data, err := json.MarshalIndent(c.convert(target, bug), "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal kcidb json: %w", err)
	}
	if err := kcidbValidate(data); err != nil {
		return err
	}
	if err := os.WriteFile(filename, data, 0644); err != nil {
		return fmt.Errorf("failed to write kcidb json to file: %w", err)
	}
	return nil
}

var Validate bool

func kcidbValidate(data []byte) error {
	if !Validate {
		return nil
	}
	const bin = "kcidb-validate"
	if _, err := exec.LookPath(bin); err != nil {
		fmt.Fprintf(os.Stderr, "%v is not found\n", bin)
		return nil
	}
	cmd := exec.Command(bin)
	cmd.Stdin = bytes.NewReader(data)
	output, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("%v failed (%w) on:\n%s\n\nerror: %s",
			bin, err, data, output)
	}
	return nil
}

func (c *Client) convert(target *targets.Target, bug *dashapi.BugReport) *Kcidb {
	res := &Kcidb{
		Version: &Version{
			Major: 5,
			Minor: 3,
		},
		Checkouts: []*Checkout{
			{
				Origin:              c.origin,
				ID:                  c.extID(bug.KernelCommit),
				GitRepositoryURL:    normalizeRepo(bug.KernelRepo),
				GitCommitHash:       bug.KernelCommit,
				GitRepositoryBranch: bug.KernelBranch,
				Comment:             bug.KernelCommitTitle,
				StartTime:           bug.BuildTime.Format(time.RFC3339),
				Valid:               true,
			},
		},
		Builds: []*Build{
			{
				Origin:       c.origin,
				ID:           c.extID(bug.BuildID),
				CheckoutID:   c.extID(bug.KernelCommit),
				Architecture: target.KernelArch,
				Compiler:     bug.CompilerID,
				StartTime:    bug.BuildTime.Format(time.RFC3339),
				ConfigURL:    bug.KernelConfigLink,
				Status:       "PASS",
			},
		},
	}
	if strings.Contains(bug.Title, "build error") {
		build := res.Builds[0]
		build.Status = "FAIL"
		build.LogURL = bug.LogLink
		build.Misc = &BuildMisc{
			OriginURL:  bug.Link,
			ReportedBy: bug.CreditEmail,
		}
	} else {
		var outputFiles []*Resource
		if bug.ReportLink != "" {
			outputFiles = append(outputFiles, &Resource{Name: "report.txt", URL: bug.ReportLink})
		}
		if bug.LogLink != "" {
			outputFiles = append(outputFiles, &Resource{Name: "log.txt", URL: bug.LogLink})
		}
		if bug.ReproCLink != "" {
			outputFiles = append(outputFiles, &Resource{Name: "repro.c", URL: bug.ReproCLink})
		}
		if bug.ReproSyzLink != "" {
			outputFiles = append(outputFiles, &Resource{Name: "repro.syz.txt", URL: bug.ReproSyzLink})
		}
		if bug.MachineInfoLink != "" {
			outputFiles = append(outputFiles, &Resource{Name: "machine_info.txt", URL: bug.MachineInfoLink})
		}
		causeRevisionID := ""
		if bug.BisectCause != nil && bug.BisectCause.Commit != nil {
			causeRevisionID = bug.BisectCause.Commit.Hash
		}
		res.Tests = []*Test{
			{
				Origin:      c.origin,
				ID:          c.extID(bug.ID),
				BuildID:     c.extID(bug.BuildID),
				Path:        "syzkaller",
				StartTime:   bug.CrashTime.Format(time.RFC3339),
				OutputFiles: outputFiles,
				Comment:     bug.Title,
				Status:      "FAIL",
				Misc: &TestMisc{
					OriginURL:       bug.Link,
					ReportedBy:      bug.CreditEmail,
					UserSpaceArch:   bug.UserSpaceArch,
					CauseRevisionID: causeRevisionID,
				},
			},
		}
	}
	return res
}

func normalizeRepo(repo string) string {
	// Kcidb needs normalized repo addresses to match reports from different
	// origins and with subscriptions. "https:" is always preferred over "git:"
	// where available. Unfortunately we don't know where it's available
	// and where it isn't. We know that "https:" is supported on kernel.org,
	// and that's the main case we need to fix up. "https:" is always used
	// for github.com and googlesource.com.
	return strings.ReplaceAll(repo, "git://git.kernel.org", "https://git.kernel.org")
}

func (c *Client) extID(id string) string {
	return c.origin + ":" + id
}
