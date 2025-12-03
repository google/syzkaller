// Copyright 2025 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package aflow

import (
	"context"
	"testing"

	"google.golang.org/adk/model"
	"google.golang.org/adk/session"
)

func TestFuncAction(t *testing.T) {
	type flowInputs struct {
		InFoo int    `json:"in-foo"`
		InBar string `json:"in-bar"`
	}
	type flowOutputs struct {
		OutFoo int    `json:"out-foo"`
		OutBar string `json:"out-bar"`
	}
	type funcInputs struct {
		InFoo int    `json:"in-foo"`
		InBar string `json:"in-bar"`
	}
	type funcOutputs struct {
		OutFoo int    `json:"out-foo"`
		OutBar string `json:"out-bar"`
	}
	flows := make(map[string]*Flow)
	const flowName = "test-flow"
	ctx := context.Background()
	register[flowInputs, flowOutputs](flows, []*Flow{
		&Flow{
			Name: flowName,
			Root: NewFuncAction[funcInputs, funcOutputs]("func-action",
				func(Context, funcInputs) (funcOutputs, error) {
					return funcOutputs{}, nil
				}),
		},
	})
	inputs := flowInputs{
		InFoo: 10,
		InBar: "bar",
	}
	workdir := t.TempDir()
	cb := &testCallback{}
	flows[flowName].Execute(ctx, true, workdir, inputs, nil, cb)
}

type testCallback struct {
}

func (cb *testCallback) OnRequest(agentName string, req *model.LLMRequest) error {
	return nil
}

func (cb *testCallback) OnEvent(*session.Event) error {
	return nil
}
