// Copyright 2026 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

// ai package contains common definitions that are used across pkg/aflow/... and dashboard/{app,dashapi}.
package ai

type WorkflowType string

const (
	WorkflowPatching        = WorkflowType("patching")
	WorkflowAssessmentKCSAN = WorkflowType("assessment-kcsan")
)
