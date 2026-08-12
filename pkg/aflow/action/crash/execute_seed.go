// Copyright 2026 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package crash

import (
	"errors"
	"fmt"
	"syscall"

	"github.com/google/syzkaller/pkg/aflow"
	"github.com/google/syzkaller/pkg/flatrpc"
	"github.com/google/syzkaller/pkg/fuzzer/queue"
	"github.com/google/syzkaller/pkg/hash"
	"github.com/google/syzkaller/pkg/log"
	"github.com/google/syzkaller/pkg/symbolizer"
	"github.com/google/syzkaller/prog"
	"github.com/google/syzkaller/sys/targets"
)

type ExecuteSeedArgs struct {
	TargetConfig
	ReproSyz string
}

const deserializationErrorHelp = `

Syzlang Syntax Reminders:
- Multi-line statements are not supported. Each syscall must be on a single line.
- Inline comments (inside syscalls) are not supported. Put comments on their own lines.
- Double quotes ("...") are only for hex sequences. Use single quotes ('...') for strings and paths.`

// ExecuteSeedFunc boots the kernel and runs a single test program to collect coverage.
// It differs from ReproduceFuncWithCoverage in that it forces threaded mode and
// returns coverage data even if the execution fails with an error (e.g., timeout).
func ExecuteSeedFunc(ctx *aflow.Context, args ExecuteSeedArgs) (string, error) {
	if args.TargetArch == "" {
		args.TargetArch = targets.AMD64
	}

	target, err := prog.GetTarget(targets.Linux, args.TargetArch)
	if err != nil {
		return "", err
	}

	fullSyz := ctx.RestoreBlobs(args.ReproSyz)
	// We perform normalization so that the cache key is calculated correctly.
	p, err := target.Deserialize([]byte(fullSyz), prog.Strict)
	if err != nil {
		return "", aflow.BadCallError("%v%s", ctx.ReplaceBlobs(err.Error()), deserializationErrorHelp)
	}
	if len(p.Calls) > prog.MaxCalls {
		return "", aflow.BadCallError("program has %d calls, exceeding the limit of %d", len(p.Calls), prog.MaxCalls)
	}
	fullSyz = string(p.Serialize())

	if args.Image == "" || len(args.VM) == 0 {
		return "", fmt.Errorf("VM configuration is missing")
	}
	imageHash, err := hash.File(args.Image)
	if err != nil {
		return "", err
	}

	desc := fmt.Sprintf("seed-exec: kernel commit %v, kernel config hash %v, image hash %v,"+
		" vm %v, vm config hash %v, syz repro hash %v",
		args.KernelCommit, hash.String(args.KernelConfig), imageHash.String(),
		args.Type, hash.String(args.VM), hash.String(fullSyz))
	cached, cachedID, err := aflow.CacheObject(ctx, "seed-exec", desc, func() (cachedExecution, error) {
		var res cachedExecution
		res.GeneratedSyz = args.ReproSyz

		rm, err := ctx.GetRunnerManager()
		if err != nil {
			return res, fmt.Errorf("failed to get runner manager: %w", err)
		}

		runRes, err := rm.Submit(ctx.Context, p)
		if err != nil {
			return res, aflow.FlowError(fmt.Errorf("RunnerManager Submit failed: %w", err))
		}

		log.Logf(1, "VM Console Output:\n%s", runRes.Output)

		crashes := rm.RecentCrashes()
		if len(crashes) > 0 {
			res.BugTitle = crashes[0].Title
			res.Report = fmt.Sprintf("The kernel crashed after one of the previous executions:\n%s", string(crashes[0].Report))
			for _, rep := range crashes[1:] {
				res.OtherReports = append(res.OtherReports, string(rep.Report))
			}
		}

		if runRes.Status == queue.ExecFailure && runRes.Err != nil {
			res.Error = runRes.Err.Error()
		}

		if runRes.Info != nil {
			res.CallErrors = extractCallErrors(runRes.Info, p.Calls)
			var err error
			res.Coverage, err = extractCoverage(runRes.Info, args.TargetConfig)
			if err != nil {
				return res, err
			}
		}

		return res, nil
	})

	if err != nil {
		return "", err
	}
	if cached.Error != "" {
		return "", errors.New(cached.Error)
	}
	if cached.BugTitle != "" {
		return "", fmt.Errorf("kernel crashed: %s", cached.BugTitle)
	}

	return cachedID, nil
}

func extractCallErrors(info *flatrpc.ProgInfo, calls []*prog.Call) []CallError {
	var callErrors []CallError
	for i, call := range info.Calls {
		if call == nil {
			continue
		}
		if call.Error != 0 || call.Flags&flatrpc.CallFlagFinished == 0 {
			callName := "unknown"
			if i < len(calls) {
				callName = calls[i].Meta.Name
			}
			var errStr string
			if call.Flags&flatrpc.CallFlagExecuted == 0 {
				errStr = "call unexecuted (executor halted on an earlier call)"
			} else if call.Flags&flatrpc.CallFlagFinished == 0 {
				errStr = "call execution timed out or hung"
			} else {
				errStr = syscall.Errno(call.Error).Error()
			}
			callErrors = append(callErrors, CallError{
				Index:    i,
				CallName: callName,
				Errno:    call.Error,
				Error:    errStr,
			})
		}
	}
	return callErrors
}

// extractCoverage converts raw coverage PCs from ProgInfo into symbolized source code frames.
// It skips symbolization and returns nil if no coverage data was collected.
func extractCoverage(info *flatrpc.ProgInfo, args TargetConfig) ([][]symbolizer.Frame, error) {
	var cov [][]uint64
	hasCov := false
	for _, call := range info.Calls {
		if call == nil {
			cov = append(cov, nil)
			continue
		}
		cov = append(cov, call.Cover)
		if len(call.Cover) > 0 {
			hasCov = true
		}
	}
	if info.Extra != nil && len(info.Extra.Cover) > 0 {
		cov = append(cov, info.Extra.Cover)
		hasCov = true
	} else {
		cov = append(cov, nil)
	}
	if !hasCov {
		return nil, nil
	}
	symbolized, err := symbolize(args, cov)
	if err != nil {
		return nil, fmt.Errorf("failed to symbolize coverage: %w", err)
	}
	return symbolized, nil
}
