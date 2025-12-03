// Copyright 2025 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package aflow

import (
	"context"
	"maps"
	"os"
	"path/filepath"
	"sync"

	"github.com/google/syzkaller/pkg/aflow/journal"
	"github.com/google/syzkaller/pkg/hash"
	"github.com/google/syzkaller/pkg/osutil"
	"google.golang.org/adk/agent"
	"google.golang.org/adk/model/gemini"
	"google.golang.org/adk/runner"
	"google.golang.org/adk/session"
	"google.golang.org/genai"
)

const (
	largeModelName = "gemini-2.5-pro"
	smallModelName = "gemini-2.0-flash-lite" // cheaper/faster (for smoke testing)
)

func (flow *Flow) Execute(ctx context.Context, largeModel bool, workdir string,
	inputs any, events []*journal.Event, onEvent journal.OnEvent) (any, error) {
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
	inputsMap, inputsMapOk := inputs.(map[string]any)
	if !inputsMapOk {
		inputsMap = flow.inputsToMap(inputs)
	}
	j, err := journal.New(events, onEvent, nil)
	if err != nil {
		return nil, err
	}
	span, err := j.Append(&journal.EventFlowStart{
		SpanStart: journal.SpanStart{
			Name: flow.Name,
		},
		Args: flow.compactInputs(inputsMap),
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
	}
	ctx = context.WithValue(ctx, contextKey, ectx)
	llm, err := gemini.NewModel(ctx, modelName, &genai.ClientConfig{})
	if err != nil {
		return nil, err
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
		State:     inputsMap,
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

	getReq := &session.GetRequest{
		AppName:   flow.Name,
		UserID:    userID,
		SessionID: sessionID,
	}
	getResp, err := sessions.Get(ctx, getReq)
	if err != nil {
		return nil, err
	}
	results, err := flow.outputsFromMap(maps.Collect(getResp.Session.State().All()))
	if err != nil {
		return nil, err
	}
	_, err = j.Append(&journal.EventFlowEnd{
		Results: flow.outputsToMap(results),
	})
	if err != nil {
		return nil, err
	}

	return results, nil
}

type contextKeyType int

var contextKey contextKeyType = 0

type Context struct {
	Workdir string
	journal *journal.Journal
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
