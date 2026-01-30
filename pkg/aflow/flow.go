// Copyright 2025 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package aflow

import (
	"fmt"
	"maps"
	"slices"

	"github.com/google/syzkaller/pkg/aflow/ai"
)

// Flow describes a single agentic workflow.
// A workflow takes some inputs, and produces some outputs in the end
// (specified as fields of the Inputs/Outputs struct types, correspondingly).
// A workflow consists of one or more actions that do the actual computation
// and produce the outputs. Actions can be based on an arbitrary Go function
// (FuncAction), or an LLM agent invocation (LLMAgent). Actions can produce
// final output fields, and/or intermediate inputs for subsequent actions.
// LLMAgent can also use tools that can accept workflow inputs, or outputs
// or preceding actions.
// A workflow is executed sequentially, but it can be thought of as a dataflow graph.
// Actions are nodes of the graph, and they consume/produce some named values
// (input/output fields, and intermediate values consumed by other actions).
type Flow struct {
	Name string // Empty for the main workflow for the workflow type.
	Root Action

	Models []string // LLM models used in this workflow.
	*FlowType
}

type FlowType struct {
	Type           ai.WorkflowType
	Description    string
	checkInputs    func(map[string]any) error
	extractOutputs func(map[string]any) map[string]any
}

var Flows = make(map[string]*Flow)

// Register a workflow type (characterized by Inputs and Outputs),
// and one or more implementations of the workflow type (actual workflows).
// All workflows for the same type consume the same inputs and produce the same outputs.
// There should be the "main" implementation for the workflow type with an empty name,
// and zero or more secondary implementations with non-empty names.
func Register[Inputs, Outputs any](typ ai.WorkflowType, description string, flows ...*Flow) {
	if err := register[Inputs, Outputs](typ, description, Flows, flows); err != nil {
		panic(err)
	}
}

func register[Inputs, Outputs any](typ ai.WorkflowType, description string,
	all map[string]*Flow, flows []*Flow) error {
	if typ == "" {
		return fmt.Errorf("empty flow type")
	}
	t := &FlowType{
		Type:        typ,
		Description: description,
		checkInputs: func(inputs map[string]any) error {
			_, err := convertFromMap[Inputs](inputs, false, false)
			return err
		},
		extractOutputs: extractOutputs[Outputs],
	}
	for _, flow := range flows {
		if flow.Name == "" {
			flow.Name = string(typ)
		} else {
			flow.Name = string(typ) + "-" + flow.Name
		}
		flow.FlowType = t
		if err := registerOne[Inputs, Outputs](all, flow); err != nil {
			return err
		}
	}
	return nil
}

func registerOne[Inputs, Outputs any](all map[string]*Flow, flow *Flow) error {
	if all[flow.Name] != nil {
		return fmt.Errorf("flow %v is already registered", flow.Name)
	}
	ctx := newVerifyContext()
	provideOutputs[Inputs](ctx, "flow inputs")
	flow.Root.verify(ctx)
	requireInputs[Outputs](ctx, "flow outputs")
	if err := ctx.finalize(); err != nil {
		return fmt.Errorf("flow %v: %w", flow.Name, err)
	}
	flow.Models = slices.Collect(maps.Keys(ctx.models))
	slices.Sort(flow.Models)
	all[flow.Name] = flow
	return nil
}
