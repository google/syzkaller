// Copyright 2024 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package queue

import "github.com/google/syzkaller/pkg/stat"

// Common stats related to fuzzing that are updated/read by different parts of the system.
var (
	StatNoExecRequests = stat.New("no exec requests",
		"Number of times fuzzer was stalled with no exec requests", stat.Rate{})
	StatNoExecDuration = stat.New("no exec duration",
		"Total duration fuzzer was stalled with no exec requests (ns/sec)", stat.Rate{})
	StatExecBufferTooSmall = stat.New("buffer too small",
		"Program serialization overflowed exec buffer", stat.NoGraph)
)
