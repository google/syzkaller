// Copyright 2025 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package agent

import (
	"context"

	"google.golang.org/adk/agent"
	"google.golang.org/adk/model/gemini"
	"google.golang.org/adk/runner"
	"google.golang.org/adk/session"
	"google.golang.org/genai"
)

const (
	largeModelName = "gemini-2.5-pro"
	smallModelName = "gemini-2.0-flash-lite" // cheaper/faster (for smoke testing)
	maxLLMCalls    = 100
)

func (flow *Flow) Execute(ctx context.Context, largeModel bool, inputs any,
	events []*session.Event, eventSink func(*session.Event) error) (any, error) {
	modelName := smallModelName
	var thinkingConfig *genai.ThinkingConfig
	if largeModel {
		modelName = largeModelName
		thinkingConfig = &genai.ThinkingConfig{
			IncludeThoughts: true,
			ThinkingBudget:  genai.Ptr[int32](-1),
		}
	}
	llm, err := gemini.NewModel(ctx, modelName, &genai.ClientConfig{})
	if err != nil {
		return nil, err
	}
	cctx := &createContext{
		llm: llm,
		contentConfig: &genai.GenerateContentConfig{
			Temperature:    genai.Ptr[float32](0),
			ThinkingConfig: thinkingConfig,
		},
	}
	root, err := flow.Root.create(cctx)
	if err != nil {
		return nil, err
	}
	state, err := flow.convertInputs(inputs)
	if err != nil {
		return nil, err
	}
	sessions := session.InMemoryService()
	const (
		userID    = "user"
		sessionID = "session"
	)
	createReq := &session.CreateRequest{
		AppName:   flow.Name,
		UserID:    userID,
		SessionID: sessionID,
		State:     state,
	}
	createResp, err := sessions.Create(ctx, createReq)
	if err != nil {
		return nil, err
	}
	session := createResp.Session
	for _, ev := range events {
		if err := sessions.AppendEvent(ctx, session, ev); err != nil {
			return nil, err
		}
	}
	r, err := runner.New(runner.Config{
		AppName:        flow.Name,
		Agent:          root,
		SessionService: sessions,
	})
	if err != nil {
		return nil, err
	}
	cfg := agent.RunConfig{
		MaxLLMCalls: maxLLMCalls,
	}
	for ev, err := range r.Run(ctx, userID, sessionID, nil, cfg) {
		if err != nil {
			return nil, err
		}
		if err := eventSink(ev); err != nil {
			return nil, err
		}
	}
	return flow.extractOutputs(session.State())
}
