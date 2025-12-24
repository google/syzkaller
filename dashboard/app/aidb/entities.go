// Copyright 2025 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package aidb

import (
	"time"
)

type WorkflowType string

const (
	WorkflowPatching = WorkflowType("patching")
)

type Workflow struct {
	Name   string
	Type   WorkflowType
	Active bool
}

type Job struct {
	ID           string
	Type         WorkflowType
	Workflow     string
	Error        string
	Created      time.Time
	Started      time.Time
	Finished     time.Time
	CodeRevision string

	Patching *PatchingJob `spanner:"->"`
	//LastEvent	TIMESTAMP,
	//NumEvents	INT64 NOT NULL,
}

type PatchingJob struct {
	ID              string
	ReproOpts       []byte
	ReproSyz        int64
	ReproC          int64
	KernelConfig    int64
	SyzkallerCommit string
}

type SpanType string

const (
	SpanFlow   = SpanType("flow")
	SpanAction = SpanType("action")
	SpanAgent  = SpanType("agent")
	SpanLLM    = SpanType("llm")
	SpanTool   = SpanType("tool")
)

type TrajectorySpan struct {
	JobID   string
	Type    SpanType
	Nesting int64
	Seq     int64

	Name        string // action/tool name
	Timestamp   time.Time
	Finished    bool
	Duration    time.Duration // relevant if Finished
	Error       string        // relevant if Finished
	NestedError bool          // relevant if Finished

	// Args/results for actions/tools.
	Args    map[string]any
	Results map[string]any

	// Agent invocation.
	Instruction string
	Prompt      string
	Reply       string

	// LLM invocation.
	Thoughts string
}
