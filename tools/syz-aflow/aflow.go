// Copyright 2025 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

// syz-aflow tool can be used to invoke any agentic workflow registered with pkg/aflow.
// For example, to run the patching workflow use:
//
//	go run ./tools/syz-aflow -input=input.json -download-bug=d8fd35fa6177afa8c92b
//	go run ./tools/syz-aflow -input=input.json -workflow=patching -workdir=workdir
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
	"path/filepath"

	"github.com/google/syzkaller/pkg/aflow"
	_ "github.com/google/syzkaller/pkg/aflow/flow"
	"github.com/google/syzkaller/pkg/aflow/trajectory"
	"github.com/google/syzkaller/pkg/osutil"
	"github.com/google/syzkaller/pkg/tool"
)

func main() {
	var (
		flagFlow        = flag.String("workflow", "", "workflow to execute")
		flagInput       = flag.String("input", "", "input json file with workflow arguments")
		flagWorkdir     = flag.String("workdir", "", "directory for kernel checkout, kernel builds, etc")
		flagModel       = flag.String("model", aflow.DefaultModel, "use this LLM model")
		flagDownloadBug = flag.String("download-bug", "", "extid of a bug to download from the dashboard"+
			" and save into -input file")
	)
	defer tool.Init()()
	if *flagDownloadBug != "" {
		if err := downloadBug(*flagDownloadBug, *flagInput); err != nil {
			tool.Fail(err)
		}
		return
	}
	if *flagFlow == "" {
		fmt.Fprintf(os.Stderr, "syz-aflow usage:\n")
		flag.PrintDefaults()
		fmt.Fprintf(os.Stderr, "available workflows:\n")
		for _, flow := range aflow.Flows {
			fmt.Fprintf(os.Stderr, "\t%v: %v\n", flow.Name, flow.Description)
		}
		return
	}
	if err := run(context.Background(), *flagModel, *flagFlow, *flagInput, *flagWorkdir); err != nil {
		tool.Fail(err)
	}
}

func run(ctx context.Context, model, flowName, inputFile, workdir string) error {
	flow := aflow.Flows[flowName]
	if flow == nil {
		return fmt.Errorf("workflow %q is not found", flowName)
	}
	inputData, err := os.ReadFile(inputFile)
	if err != nil {
		return fmt.Errorf("failed to open -input file: %w", err)
	}
	var inputs map[string]any
	if err := json.Unmarshal(inputData, &inputs); err != nil {
		return err
	}
	cache, err := aflow.NewCache(filepath.Join(workdir, "cache"), 0)
	if err != nil {
		return err
	}
	_, err = flow.Execute(ctx, model, workdir, inputs, cache, onEvent)
	return err
}

func onEvent(span *trajectory.Span) error {
	log.Printf("%v", span)
	return nil
}

func downloadBug(extID, inputFile string) error {
	if inputFile == "" {
		return fmt.Errorf("-download-bug requires -input flag")
	}
	resp, err := get(fmt.Sprintf("/bug?extid=%v&json=1", extID))
	if err != nil {
		return err
	}
	var info map[string]any
	if err := json.Unmarshal([]byte(resp), &info); err != nil {
		return err
	}
	crash := info["crashes"].([]any)[0].(map[string]any)
	inputs := map[string]any{
		"SyzkallerCommit": crash["syzkaller-commit"],
	}
	inputs["ReproSyz"], err = get(crash["syz-reproducer"].(string))
	if err != nil {
		return err
	}
	inputs["ReproC"], err = get(crash["c-reproducer"].(string))
	if err != nil {
		return err
	}
	inputs["KernelConfig"], err = get(crash["kernel-config"].(string))
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
