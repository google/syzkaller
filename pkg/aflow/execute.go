// Copyright 2025 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package aflow

import (
	"context"
	"iter"
	"os"
	"path/filepath"
	"sync"

	"github.com/google/syzkaller/pkg/aflow/journal"
	"github.com/google/syzkaller/pkg/hash"
	"github.com/google/syzkaller/pkg/osutil"
	"github.com/google/syzkaller/prog"
	"google.golang.org/adk/agent"
	"google.golang.org/adk/model"
	"google.golang.org/adk/model/gemini"
	"google.golang.org/adk/runner"
	"google.golang.org/adk/session"
	"google.golang.org/genai"
)

const (
	// https://ai.google.dev/gemini-api/docs/models
	largeModelName = "gemini-3.0-pro"
	smallModelName = "gemini-2.0-flash-lite" // cheaper/faster (for smoke testing)
)

func (flow *Flow) Execute(ctx context.Context, largeModel bool, workdir string,
	inputs any, events []*journal.Event, onEvent journal.OnEvent) (any, error) {
	var stub stubContext
	if s := ctx.Value(stubContextKey); s != nil {
		stub = *s.(*stubContext)
	}
	workdir = osutil.Abs(workdir)
	modelName := smallModelName
	var thinkingConfig *genai.ThinkingConfig
	if largeModel {
		modelName = largeModelName
		thinkingConfig = &genai.ThinkingConfig{
			IncludeThoughts: true,
			ThinkingBudget:  genai.Ptr[int32](-1),
		}
	}
	j, err := journal.New(events, onEvent, stub.now)
	if err != nil {
		return nil, err
	}
	span, err := j.Append(&journal.EventFlowStart{
		SpanStart: journal.SpanStart{
			Name: flow.Name,
		},
		Name:     flow.Name,
		Revision: prog.GitRevision,
		Args:     flow.compactInputs(inputs),
	})
	if err != nil {
		return nil, err
	}
	if span.End != nil {
		return flow.outputsFromMap(span.End.FlowEnd.Results)
	}
	ectx := &Context{
		Workdir: workdir,
		journal: j,
		inputs:  inputs,
	}
	ctx = context.WithValue(ctx, contextKey, ectx)
	var llm model.LLM
	if stub.generateContent != nil {
		llm = &stubModel{stub.generateContent}
	} else {
		llm, err = gemini.NewModel(ctx, modelName, &genai.ClientConfig{})
		if err != nil {
			return nil, err
		}
	}
	cctx := &createContext{
		actions: make(map[string]int),
		llm:     llm,
		contentConfig: &genai.GenerateContentConfig{
			ResponseModalities: []string{"TEXT"},
			ThinkingConfig:     thinkingConfig,
		},
	}
	root, err := flow.Root.create(cctx)
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
	}
	if _, err := sessions.Create(ctx, createReq); err != nil {
		return nil, err
	}
	r, err := runner.New(runner.Config{
		AppName:        flow.Name,
		Agent:          root,
		SessionService: sessions,
	})
	if err != nil {
		return nil, err
	}
	cfg := agent.RunConfig{}
	for _, err := range r.Run(ctx, userID, sessionID, nil, cfg) {
		if err != nil {
			// TODO: figure out how to handle errors that happened somewhere
			// not in our actions. In these cases the journal won't record the error.
			return nil, err
		}
	}
	_, err = j.Append(&journal.EventFlowEnd{
		Results: flow.outputsToMap(ectx.outputs),
	})
	if err != nil {
		return nil, err
	}

	return ectx.outputs, nil
}

type contextKeyType int

var (
	contextKey     = contextKeyType(0)
	stubContextKey = contextKeyType(1)
)

type Context struct {
	Workdir string
	journal *journal.Journal
	inputs  any
	outputs any
}

type stubContext struct {
	now             journal.Now
	generateContent func(req *model.LLMRequest) (*model.LLMResponse, error)
}

type stubModel struct {
	generateContent func(req *model.LLMRequest) (*model.LLMResponse, error)
}

func (m *stubModel) Name() string {
	return "stub-model"
}

func (m *stubModel) GenerateContent(ctx context.Context, req *model.LLMRequest,
	stream bool) iter.Seq2[*model.LLMResponse, error] {
	return func(yield func(*model.LLMResponse, error) bool) {
		resp, err := m.generateContent(req)
		yield(resp, err)
	}
}

var cacheMu sync.Mutex

func (ctx *Context) Cache(typ, desc string, populate func(string) error) (string, error) {
	id := hash.String(desc)
	dir := filepath.Join(ctx.Workdir, typ, id)
	metaFile := filepath.Join(dir, "aflow-meta")
	if osutil.IsExist(metaFile) {
		return dir, nil
	}

	cacheMu.Lock()
	defer cacheMu.Unlock()

	os.RemoveAll(dir)
	if err := osutil.MkdirAll(dir); err != nil {
		return "", err
	}
	if err := populate(dir); err != nil {
		return "", err
	}
	// TODO: also write info when the entry was created, and clean up them later.
	if err := osutil.WriteFile(metaFile, []byte(desc)); err != nil {
		return "", err
	}
	return dir, nil
}

func errorToString(err error) string {
	if err != nil {
		return err.Error()
	}
	return ""
}
