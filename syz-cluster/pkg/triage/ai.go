// Copyright 2026 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

// Package triage analyzes incoming patch series, repositories, and kernel trees
// to evaluate patch relevance and generate test target configurations.
package triage

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/google/syzkaller/pkg/aflow"
	"github.com/google/syzkaller/pkg/aflow/ai"
	"github.com/google/syzkaller/pkg/aflow/backend"
	"github.com/google/syzkaller/pkg/aflow/backend/gemini"
	_ "github.com/google/syzkaller/pkg/aflow/flow"
	"github.com/google/syzkaller/pkg/aflow/trajectory"
	aflowhtml "github.com/google/syzkaller/pkg/aflow/trajectory/html"
	"github.com/google/syzkaller/pkg/debugtracer"
	"github.com/google/syzkaller/pkg/gcpsecret"
	"github.com/google/syzkaller/pkg/osutil"
	"github.com/google/syzkaller/syz-cluster/pkg/api"
	"github.com/google/syzkaller/syz-cluster/pkg/app"
	"google.golang.org/genai"
)

type AITriageResult struct {
	WorthFuzzing   bool
	NeedsKMSAN     bool
	KMSANReasoning string
	FocusSymbols   []string
	EnableConfigs  []string
	Reasoning      string
	Trajectory     []byte
}

type AIFindingTriageResult struct {
	Introduced bool
	Reasoning  string
	Trajectory []byte
}

const (
	aiEvaluationTimeout     = time.Hour
	aiFindingTriageTimeout  = 15 * time.Minute
	seriesTriageTokenLimit  = 5 * 1000 * 1000  // 5M tokens
	findingTriageTokenLimit = 10 * 1000 * 1000 // 10M tokens
)

func CommitPatchForAflow(ops *GitTreeOps) error {
	if _, err := ops.Run("add", "-A"); err != nil {
		return fmt.Errorf("git add failed: %v", osutil.VerboseMessage(err))
	}
	if _, err := ops.Run("-c", "user.name=syz-cluster", "-c", "user.email=triage@syzkaller.com",
		"commit", "-m", "syz-cluster: applied patch under review"); err != nil {
		return fmt.Errorf("git commit failed: %v", osutil.VerboseMessage(err))
	}
	return nil
}

type AIClient struct {
	provider backend.Provider
	cache    *aflow.Cache
	tracer   debugtracer.DebugTracer
}

func NewAIClient(ctx context.Context, config *app.AppConfig, tracer debugtracer.DebugTracer) (*AIClient, error) {
	apiKey, err := gcpsecret.Resolve(ctx, config.AI.GeminiAPIKey)
	if err != nil {
		return nil, fmt.Errorf("failed to resolve Gemini API key: %w", err)
	}

	cache, err := aflow.NewCache("/tmp/aflow-cache", 1024*1024*1024)
	if err != nil {
		return nil, fmt.Errorf("failed to create aflow cache: %w", err)
	}

	provider, err := gemini.NewProvider(ctx, gemini.Config{
		ClientConfig: &genai.ClientConfig{
			APIKey: apiKey,
		},
	})
	if err != nil {
		return nil, fmt.Errorf("failed to initialize LLM provider: %w", err)
	}

	return &AIClient{
		provider: provider,
		cache:    cache,
		tracer:   tracer,
	}, nil
}

func (c *AIClient) Close() error {
	if c.provider != nil {
		c.provider.Close()
	}
	return nil
}

func (c *AIClient) execute(ctx context.Context, flowType ai.WorkflowType, args any,
	tokenLimit int) (map[string]any, []byte, error) {
	var spans []*trajectory.Span
	seenID := make(map[int]struct{})
	onEvent := func(span *trajectory.Span) error {
		// Aflow sends us the same span pointer twice: on start and on finish.
		if _, ok := seenID[span.Seq]; ok {
			return nil
		}
		seenID[span.Seq] = struct{}{}
		spans = append(spans, span)
		return nil
	}

	argsBytes, err := json.Marshal(args)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to marshal initial args: %w", err)
	}
	var initialState map[string]any
	if err := json.Unmarshal(argsBytes, &initialState); err != nil {
		return nil, nil, fmt.Errorf("failed to unmarshal initial state: %w", err)
	}

	workflowDesc := aflow.Flows[string(flowType)]
	if workflowDesc == nil {
		return nil, nil, fmt.Errorf("failed to find workflow %s", flowType)
	}

	outputs, execErr := workflowDesc.Execute(ctx, initialState, aflow.ExecuteOptions{
		Provider:   c.provider,
		Workdir:    "/tmp/aflow-cache",
		Cache:      c.cache,
		OnEvent:    onEvent,
		TokenLimit: tokenLimit,
	})

	var htmlReport []byte
	buf := new(bytes.Buffer)
	if renderErr := aflowhtml.RenderReport(buf, spans); renderErr == nil {
		htmlReport = buf.Bytes()
	} else if c.tracer != nil {
		c.tracer.Logf("failed to render trajectory: %v", renderErr)
	}

	return outputs, htmlReport, execErr
}

func (c *AIClient) EvaluatePatch(ctx context.Context, series *api.Series,
	kernelSrcDir string) (*AITriageResult, error) {
	aiCtx, cancel := context.WithTimeout(ctx, aiEvaluationTimeout)
	defer cancel()

	if c.tracer != nil {
		c.tracer.Logf("starting AI patch evaluation...")
	}
	args := ai.PatchTriageArgs{
		// TODO: Set TargetArch dynamically based on the fuzzing targets for the patch.
		// For now it's irrelevant as we only fuzz amd64 anyway.
		TargetArch: "amd64",
		KernelSrc:  kernelSrcDir,
	}
	outputs, htmlReport, err := c.execute(aiCtx, ai.WorkflowPatchTriage, args, seriesTriageTokenLimit)
	if err != nil {
		return &AITriageResult{Trajectory: htmlReport}, err
	}

	outBytes, err := json.Marshal(outputs)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal outputs: %w", err)
	}
	var result ai.PatchTriageResult
	if err := json.Unmarshal(outBytes, &result); err != nil {
		return nil, fmt.Errorf("AI evaluation returned invalid data: %w", err)
	}

	if c.tracer != nil {
		c.tracer.Logf("AI verdict: WorthFuzzing=%v (Reason: %s)", result.WorthFuzzing, result.Reasoning)
	}

	return &AITriageResult{
		WorthFuzzing:   result.WorthFuzzing,
		NeedsKMSAN:     result.NeedsKMSAN,
		KMSANReasoning: result.KMSANReasoning,
		FocusSymbols:   result.FocusSymbols,
		EnableConfigs:  result.EnableConfigs,
		Reasoning:      result.Reasoning,
		Trajectory:     htmlReport,
	}, nil
}

func (c *AIClient) EvaluateFinding(ctx context.Context, series *api.Series,
	baseCommit, crashReport, kernelSrcDir string) (*AIFindingTriageResult, error) {
	aiCtx, cancel := context.WithTimeout(ctx, aiFindingTriageTimeout)
	defer cancel()

	if c.tracer != nil {
		c.tracer.Logf("starting AI finding triage evaluation...")
	}
	var seriesPatches []ai.SeriesPatch
	if series != nil {
		for _, p := range series.Patches {
			seriesPatches = append(seriesPatches, ai.SeriesPatch{
				Seq:   p.Seq,
				Title: p.Title,
				Body:  p.Body,
			})
		}
	}

	args := ai.FindingTriageArgs{
		TargetArch:  "amd64",
		KernelSrc:   kernelSrcDir,
		BaseCommit:  baseCommit,
		Patches:     seriesPatches,
		CrashReport: crashReport,
	}
	outputs, htmlReport, err := c.execute(aiCtx, ai.WorkflowFindingTriage, args, findingTriageTokenLimit)
	if err != nil {
		return &AIFindingTriageResult{Trajectory: htmlReport}, err
	}

	outBytes, err := json.Marshal(outputs)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal outputs: %w", err)
	}
	var result ai.FindingTriageResult
	if err := json.Unmarshal(outBytes, &result); err != nil {
		return nil, fmt.Errorf("AI evaluation returned invalid data: %w", err)
	}

	if c.tracer != nil {
		c.tracer.Logf("AI verdict: Introduced=%v (Reason: %s)", result.Introduced, result.Reasoning)
	}

	return &AIFindingTriageResult{
		Introduced: result.Introduced,
		Reasoning:  result.Reasoning,
		Trajectory: htmlReport,
	}, nil
}

func EvaluatePatch(ctx context.Context, config *app.AppConfig, series *api.Series,
	tracer debugtracer.DebugTracer, kernelSrcDir string) (*AITriageResult, error) {
	client, err := NewAIClient(ctx, config, tracer)
	if err != nil {
		return nil, err
	}
	defer client.Close()
	return client.EvaluatePatch(ctx, series, kernelSrcDir)
}
