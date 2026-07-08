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
	WorthFuzzing  bool
	FocusSymbols  []string
	EnableConfigs []string
	Reasoning     string
	Trajectory    []byte
}

const aiEvaluationTimeout = time.Hour

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

func EvaluatePatch(ctx context.Context, config *app.AppConfig, series *api.Series,
	tracer debugtracer.DebugTracer, kernelSrcDir string) (*AITriageResult, error) {
	apiKey, err := gcpsecret.Resolve(ctx, config.AI.GeminiAPIKey)
	if err != nil {
		return nil, fmt.Errorf("failed to resolve Gemini API key: %w", err)
	}

	aiCtx, cancel := context.WithTimeout(ctx, aiEvaluationTimeout)
	defer cancel()

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

	args := ai.PatchTriageArgs{
		// TODO: Set TargetArch dynamically based on the fuzzing targets for the patch.
		// For now it's irrelevant as we only fuzz amd64 anyway.
		TargetArch: "amd64",
		KernelSrc:  kernelSrcDir,
	}
	argsBytes, err := json.Marshal(args)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal initial args: %w", err)
	}
	var initialState map[string]any
	if err := json.Unmarshal(argsBytes, &initialState); err != nil {
		return nil, fmt.Errorf("failed to unmarshal initial state: %w", err)
	}

	tracer.Logf("starting AI patch evaluation...")
	workflowDesc := aflow.Flows[string(ai.WorkflowPatchTriage)]
	if workflowDesc == nil {
		return nil, fmt.Errorf("failed to find workflow %s", ai.WorkflowPatchTriage)
	}

	cache, err := aflow.NewCache("/tmp/aflow-cache", 1024*1024*1024)
	if err != nil {
		return nil, fmt.Errorf("failed to create aflow cache: %w", err)
	}

	provider, err := gemini.NewProvider(aiCtx, gemini.Config{
		ClientConfig: &genai.ClientConfig{
			APIKey: apiKey,
		},
	})
	if err != nil {
		return nil, fmt.Errorf("failed to initialize LLM provider: %w", err)
	}
	defer provider.Close()

	outputs, err := workflowDesc.Execute(aiCtx, provider, "/tmp/aflow-cache", false, initialState, cache, onEvent)

	var htmlReport []byte
	buf := new(bytes.Buffer)
	if renderErr := aflowhtml.RenderReport(buf, spans); renderErr == nil {
		htmlReport = buf.Bytes()
	} else {
		tracer.Logf("failed to render trajectory: %v", renderErr)
	}

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

	tracer.Logf("AI verdict: WorthFuzzing=%v (Reason: %s)", result.WorthFuzzing, result.Reasoning)

	return &AITriageResult{
		WorthFuzzing:  result.WorthFuzzing,
		FocusSymbols:  result.FocusSymbols,
		EnableConfigs: result.EnableConfigs,
		Reasoning:     result.Reasoning,
		Trajectory:    htmlReport,
	}, nil
}
