// Copyright 2025 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"strings"

	"github.com/google/syzkaller/pkg/aflow"
	"github.com/google/syzkaller/pkg/aflow/flow/patching"
	"github.com/google/syzkaller/pkg/aflow/journal"
	"github.com/google/syzkaller/pkg/osutil"
	"github.com/google/syzkaller/pkg/tool"
)

func main() {
	var (
		flagFlow        = flag.String("workflow", "", "workflow to execute")
		flagInput       = flag.String("input", "", "input json file with workflow arguments")
		flagWorkdir     = flag.String("workdir", "", "directory for kernel checkout, kernel builds, etc")
		flagLargeModel  = flag.Bool("large-model", true, "use large/expensive or small/cheap model")
		flagDownloadBug = flag.String("download-bug", "", "extid of a bug to download from the dashboard and save into -input file")
	)
	defer tool.Init()()
	if *flagDownloadBug != "" {
		if err := downloadBug(*flagDownloadBug, *flagInput); err != nil {
			tool.Fail(err)
		}
		return
	}
	if *flagFlow == "" {
		fmt.Fprintf(os.Stderr, "syz-agent usage:\n")
		flag.PrintDefaults()
		fmt.Fprintf(os.Stderr, "available workflows:\n")
		for _, flow := range aflow.Flows {
			fmt.Fprintf(os.Stderr, "\t%v: %v\n", flow.Name, flow.Description)
		}
		return
	}
	ctx := context.Background()
	out, err := run(ctx, *flagLargeModel, *flagFlow, *flagInput, *flagWorkdir)
	if err != nil {
		tool.Fail(err)
	}
	os.Stdout.Write(out)
}

func run(ctx context.Context, largeModel bool, flowName, inputFile, workdir string) ([]byte, error) {
	flow := aflow.Flows[flowName]
	if flow == nil {
		return nil, fmt.Errorf("workflow %q is not found", flowName)
	}
	inputData, err := os.ReadFile(inputFile)
	if err != nil {
		return nil, fmt.Errorf("failed to open -input file: %w", err)
	}
	var inputs map[string]any
	if err := json.Unmarshal(inputData, &inputs); err != nil {
		return nil, err
	}
	if workdir == "" {
		return nil, fmt.Errorf("-workdir is empty")
	}
	out, err := flow.Execute(ctx, largeModel, workdir, inputs, nil, onEvent)
	if err != nil {
		return nil, err
	}
	return json.MarshalIndent(out, "", "\t")
}

func onEvent(ev *journal.Event) error {
	log.Printf("%v%v", strings.Repeat("  ", ev.Nesting), ev.Description())
	dump, err := json.MarshalIndent(ev, "", "\t")
	if err != nil {
		return err
	}
	fmt.Printf("%s\n\n", dump)
	return nil
}

func downloadBug(extID, inputFile string) error {
	if inputFile == "-download-bug requires -input flag" {
		return fmt.Errorf("")
	}
	resp, err := get(fmt.Sprintf("/bug?extid=%v&json=1", extID))
	if err != nil {
		return err
	}
	var info map[string]any
	if err := json.Unmarshal([]byte(resp), &info); err != nil {
		return err
	}
	// TODO: expose arch/vmarch, syz repro opts, total number of crashes in the API.
	crash := info["crashes"].([]any)[0].(map[string]any)
	inputs := patching.Inputs{
		Title: crash["title"].(string),
		// TODO: provide usable git repo address in the API.
		KernelRepo:      strings.Split(crash["kernel-source-git"].(string), "/log/?id=")[0],
		KernelCommit:    crash["kernel-source-commit"].(string),
		SyzkallerCommit: crash["syzkaller-commit"].(string),
	}
	inputs.Report, err = get(crash["crash-report-link"].(string))
	if err != nil {
		return err
	}
	inputs.ReproSyz, err = get(crash["syz-reproducer"].(string))
	if err != nil {
		return err
	}
	inputs.ReproC, err = get(crash["c-reproducer"].(string))
	if err != nil {
		return err
	}
	inputs.KernelConfig, err = get(crash["kernel-config"].(string))
	if err != nil {
		return err
	}
	data, err := json.MarshalIndent(inputs, "", "\t")
	if err != nil {
		return err
	}
	return osutil.WriteFile(inputFile, data)
}

func get(path string) (string, error) {
	if path == "" {
		return "", nil
	}
	const host = "https://syzbot.org"
	resp, err := http.Get(fmt.Sprintf("%v%v", host, path))
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	return string(body), err
}
