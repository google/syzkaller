// Copyright 2026 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package syzlang

import "github.com/google/syzkaller/pkg/aflow"

var Tools = []aflow.Tool{ToolListDescriptions, ToolGetDescriptions, ToolSyzCompilerCheck}
