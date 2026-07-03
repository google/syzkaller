// Copyright 2025 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

// Package flow registers and exports predefined workflows for crash analysis, patch triage, and reproduction.
package flow

import (
	_ "github.com/google/syzkaller/pkg/aflow/flow/assessment"
	_ "github.com/google/syzkaller/pkg/aflow/flow/fuzzing"
	_ "github.com/google/syzkaller/pkg/aflow/flow/patching"
	_ "github.com/google/syzkaller/pkg/aflow/flow/repro"
	_ "github.com/google/syzkaller/pkg/aflow/flow/reproc"
)
