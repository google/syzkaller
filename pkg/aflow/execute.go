// Copyright 2025 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package aflow

import (
	"context"
	"fmt"
	"iter"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/google/syzkaller/pkg/aflow/trajectory"
	"github.com/google/syzkaller/pkg/hash"
	"github.com/google/syzkaller/pkg/osutil"
	"google.golang.org/adk/agent"
	"google.golang.org/adk/model"
	"google.golang.org/adk/model/gemini"
	"google.golang.org/adk/runner"
	"google.golang.org/adk/session"
	"google.golang.org/genai"
)

const (
	// https://ai.google.dev/gemini-api/docs/models
	largeModelName = "gemini-3-pro-preview"
	smallModelName = "gemini-2.0-flash-lite" // cheaper/faster (for smoke testing)
)

func ModelName(largeModel bool) string {
	if largeModel {
		return largeModelName
	}
	return smallModelName
}

func (flow *Flow) Execute(ctx context.Context, largeModel bool, workdir string,
	inputs map[string]any, onEvent onEvent) (map[string]any, error) {
	if workdir == "" {
		return nil, fmt.Errorf("workdir is empty")
	}
	var stub stubContext
	if s := ctx.Value(stubContextKey); s != nil {
		stub = *s.(*stubContext)
	}
	timeNow := time.Now
	if stub.timeNow != nil {
		timeNow = stub.timeNow
	}
	workdir = osutil.Abs(workdir)
	modelName := ModelName(largeModel)
	var thinkingConfig *genai.ThinkingConfig
	if largeModel {
		thinkingConfig = &genai.ThinkingConfig{
			IncludeThoughts: true,
			ThinkingBudget:  genai.Ptr[int32](-1),
		}
	}
	ectx := &Context{
		Workdir: workdir,
		state:   make(map[string]any),
		timeNow: timeNow,
		onEvent: onEvent,
		inputs:  inputs,
	}
	span := &trajectory.Span{
		Type: trajectory.SpanFlow,
		Name: flow.Name,
	}
	if err := ectx.startSpan(span); err != nil {
		return nil, err
	}
	ctx = context.WithValue(ctx, contextKey, ectx)
	var llm model.LLM
	if stub.generateContent != nil {
		llm = &stubModel{stub.generateContent}
	} else {
		var err error
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
			//!!! figure out how to handle errors that happened somewhere
			// not in our actions. In these cases the journal won't record the error.
			return nil, err
		}
	}
	span.Results = ectx.outputs
	if err := ectx.finishSpan(span, nil); err != nil {
		return nil, err
	}
	return ectx.outputs, nil
}

type onEvent func(*trajectory.Span) error

type contextKeyType int

var (
	contextKey     = contextKeyType(0)
	stubContextKey = contextKeyType(1)
)

type Context struct {
	Workdir string
	state   map[string]any
	timeNow func() time.Time
	onEvent onEvent
	spanSeq int
	inputs  map[string]any
	outputs map[string]any
}

var cacheMu sync.Mutex

func (ctx *Context) Cache(typ, desc string, populate func(string) error) (string, error) {
	id := hash.String(desc)
	dir := filepath.Join(ctx.Workdir, typ, id)
	metaFile := filepath.Join(dir, "aflow-meta")
	if osutil.IsExist(metaFile) {
		// Note the entry was used now.
		now := ctx.timeNow()
		if err := os.Chtimes(metaFile, now, now); err != nil {
			return "", err
		}
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
	// TODO(dvyukov): also write info when the entry was created, and clean up them later.
	if err := osutil.WriteFile(metaFile, []byte(desc)); err != nil {
		return "", err
	}
	return dir, nil
}

func (ctx *Context) startSpan(span *trajectory.Span) error {
	span.Seq = ctx.spanSeq
	ctx.spanSeq++
	//span.Nesting = ...
	span.Timestamp = ctx.timeNow()
	return ctx.onEvent(span)
}

func (ctx *Context) finishSpan(span *trajectory.Span, spanErr error) error {
	span.Finished = true
	span.Duration = ctx.timeNow().Sub(span.Timestamp)
	if spanErr != nil {
		span.Error = spanErr.Error()
	}
	err := ctx.onEvent(span)
	if spanErr != nil {
		err = spanErr
	}
	return err
}

type stubContext struct {
	timeNow         func() time.Time
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
