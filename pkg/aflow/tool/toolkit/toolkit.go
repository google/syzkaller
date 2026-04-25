// Copyright 2026 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package toolkit

import (
	_ "embed"
	"github.com/google/syzkaller/pkg/aflow"
)

var (
	ToolGetToolkit = aflow.NewFuncTool("get-toolkit", getToolkit, `
Tool provides a specialized toolkit of C macros and snippets for a given name.
Available toolkits:
 - "race": Use it when you need specific primitives (like spin-wait barriers or CPU pinning) to reproduce complex bugs.
`)
)

type getToolkitArgs struct {
	Name string `jsonschema:"Name of the toolkit to retrieve (e.g., 'race')."`
}

type getToolkitResult struct {
	Toolkit string `jsonschema:"The C macros and snippets for the requested toolkit."`
}

//go:embed race_toolkit.h
var raceConditionToolkit string

func getToolkit(ctx *aflow.Context, _ struct{}, args getToolkitArgs) (getToolkitResult, error) {
	if args.Name == "race" {
		return getToolkitResult{Toolkit: raceConditionToolkit}, nil
	}
	return getToolkitResult{}, aflow.BadCallError("unknown toolkit: %s. Available toolkits: race", args.Name)
}

func GetRaceToolkit() string {
	return raceConditionToolkit
}
