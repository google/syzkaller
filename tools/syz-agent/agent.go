// Copyright 2025 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"os"

	"github.com/google/syzkaller/pkg/agent"
	_ "github.com/google/syzkaller/pkg/agent/flow/patching"
	"github.com/google/syzkaller/pkg/tool"
	"google.golang.org/adk/session"
)

func main() {
	var (
		flagFlow       = flag.String("workflow", "", "workflow to execute")
		flagInput      = flag.String("input", "", "input json file with workflow arguments")
		flagLargeModel = flag.Bool("large-model", false, "use large/expensive model")
	)
	defer tool.Init()()
	ctx := context.Background()
	out, err := run(ctx, *flagLargeModel, *flagFlow, *flagInput)
	if err != nil {
		tool.Fail(err)
	}
	os.Stdout.Write(out)
}

func run(ctx context.Context, largeModel bool, flowName, inputFile string) ([]byte, error) {
	flow := agent.Flows[flowName]
	if flow == nil {
		return nil, fmt.Errorf("workflow %q is not found", flowName)
	}
	inputData, err := os.ReadFile(inputFile)
	if err != nil {
		return nil, fmt.Errorf("failed to open -input file: %w", err)
	}
	inputs, err := flow.ParseInputs(inputData)
	if err != nil {
		return nil, err
	}

	if dump, err := json.MarshalIndent(flow, "", "\t"); err != nil {
		return nil, err
	} else {
		fmt.Printf("running workflow:\n%s\n", dump)
	}

	if dump, err := json.MarshalIndent(inputs, "", "\t"); err != nil {
		return nil, err
	} else {
		fmt.Printf("inputs:\n%s\n", dump)
	}

	out, err := flow.Execute(ctx, largeModel, inputs, nil, eventLogger)
	if err != nil {
		return nil, err
	}
	return json.MarshalIndent(out, "", "\t")
}

func eventLogger(ev *session.Event) error {
	if dump, err := json.MarshalIndent(ev, "", "\t"); err != nil {
		return err
	} else {
		fmt.Printf("event:\n%s\n", dump)
	}
	return nil
}
