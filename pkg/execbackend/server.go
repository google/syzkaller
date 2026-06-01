// Copyright 2026 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package execbackend

import (
	"context"

	"github.com/google/syzkaller/pkg/flatrpc"
	"github.com/google/syzkaller/pkg/fuzzer/queue"
	"github.com/google/syzkaller/pkg/report"
	"github.com/google/syzkaller/pkg/signal"
	"github.com/google/syzkaller/vm"
	"github.com/google/syzkaller/vm/dispatcher"
)

type Server interface {
	// Setup performs initial one-time configuration for the backend (e.g. starting a TCP listener).
	// It is called synchronously before any VM instances are started.
	Setup() error

	// Serve runs the global background loops for the backend (e.g. accepting connections).
	// It is called asynchronously and runs until the provided context is canceled.
	Serve(ctx context.Context) error

	// Close forcefully cleans up any global resources held by the backend.
	Close() error

	// TriagedCorpus notifies the backend that the initial seed corpus has been fully evaluated.
	TriagedCorpus()

	// DistributeSignalDelta sends newly discovered max signal down to all connected executors
	// so they can use it for subsequent coverage feedback filtering.
	DistributeSignalDelta(plus signal.Signal)

	// SetSource updates the source of execution requests for the backend.
	// This is typically called after the initial machine check is complete.
	SetSource(source queue.Source)

	// Features returns the enabled features. It is only valid after the machine check is complete.
	Features() flatrpc.Feature

	// RunRequests handles the lifecycle of a single VM instance. It copies the executor
	// binary, establishes communication, continuously polls Source() for execution requests,
	// and returns when the VM crashes, hangs, or the context is canceled.
	RunRequests(ctx context.Context, inst *vm.Instance, reporter *report.Reporter,
		updInfo dispatcher.UpdateInfo) ([]*report.Report, error)
}
