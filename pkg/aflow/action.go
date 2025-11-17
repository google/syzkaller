// Copyright 2025 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package aflow

import (
	"fmt"
	"maps"
	"reflect"
	"slices"

	"google.golang.org/adk/agent"
	"google.golang.org/adk/agent/workflowagents/sequentialagent"
	"google.golang.org/adk/model"
	"google.golang.org/genai"
)

type Action interface {
	create(*createContext) (agent.Agent, error)
	verify(*verifyContext)
}

type Pipeline struct {
	// For logging/debugging.
	Name string
	// These actions are invoked sequentially,
	// but dataflow across actions is specified by their use
	// of variables in args/instructions/prompts.
	Actions []Action
}

type createContext struct {
	actions       map[string]int
	llm           model.LLM
	contentConfig *genai.GenerateContentConfig
}

type verifyContext struct {
	state map[string]*varState
	err   error
}

type varState struct {
	action string
	typ    reflect.Type
	used   bool
}

func (cctx *createContext) actionName(name, def string) string {
	if name == "" {
		name = def
	}
	cctx.actions[name]++
	if n := cctx.actions[name]; n != 1 {
		name = fmt.Sprintf("%v-%v", name, n)
	}
	return name
}

func (vctx *verifyContext) errorf(who, msg string, args ...any) {
	if vctx.err == nil {
		vctx.err = fmt.Errorf(fmt.Sprintf("action %v: %v", who, msg), args...)
	}
}

func (vctx *verifyContext) requireNotEmpty(who, name, value string) {
	if value == "" {
		vctx.errorf(who, "%v must not be empty", name)
	}
}

func (vctx *verifyContext) requireInput(who, name string, typ reflect.Type) {
	state := vctx.state[name]
	if state == nil {
		vctx.errorf(who, "no input %v, available inputs: %v",
			name, slices.Collect(maps.Keys(vctx.state)))
		return
	}
	if typ != state.typ {
		vctx.errorf(who, "input %v has wrong type: want %v, has %v",
			name, typ, state.typ)
	}
	state.used = true
}

func (vctx *verifyContext) provideOutput(who, name string, typ reflect.Type, unique bool) {
	state := vctx.state[name]
	if state != nil {
		if unique {
			vctx.errorf(who, "output %v is already set", name)
		} else if typ != state.typ {
			vctx.errorf(who, "output %v changes type: %v -> %v",
				name, state.typ, typ)
		} else if !state.used {
			vctx.errorf(state.action, "output %v is unused", name)
		}
	}
	vctx.state[name] = &varState{
		action: who,
		typ:    typ,
	}
}

func (vctx *verifyContext) finalize() error {
	for name, state := range vctx.state {
		if !state.used {
			vctx.errorf(state.action, "output %v is unused", name)
		}
	}
	return vctx.err
}

func requireInputs[T any](vctx *verifyContext, who string) {
	for name, typ := range foreachFieldOf[T]() {
		vctx.requireInput(who, name, typ)
	}
}

func provideOutputs[T any](vctx *verifyContext, who string) {
	for name, typ := range foreachFieldOf[T]() {
		vctx.provideOutput(who, name, typ, true)
	}
}

func NewPipeline(actions ...Action) *Pipeline {
	return &Pipeline{
		Actions: actions,
	}
}

func (p *Pipeline) create(cctx *createContext) (agent.Agent, error) {
	var agents []agent.Agent
	for _, sub := range p.Actions {
		subAgent, err := sub.create(cctx)
		if err != nil {
			return nil, err
		}
		agents = append(agents, subAgent)
	}
	return sequentialagent.New(sequentialagent.Config{
		AgentConfig: agent.Config{
			Name:      cctx.actionName(p.Name, "pipeline"),
			SubAgents: agents,
		},
	})
}

func (p *Pipeline) verify(vctx *verifyContext) {
	for _, a := range p.Actions {
		a.verify(vctx)
	}
}
