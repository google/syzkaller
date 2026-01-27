// Copyright 2026 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package instance

import (
	"context"
	"fmt"
	"os"
	"time"

	"github.com/google/syzkaller/pkg/log"
	"github.com/google/syzkaller/sys/targets"
	"github.com/google/syzkaller/vm"
	"github.com/google/syzkaller/vm/vmimpl"
)

func ExtractMemoryDump(inst *vm.Instance, target *targets.Target, path string) error {
	// TODO: if the instance has not yet panicked, we could change it
	// by writing to /proc/sys/kernel/sysrq. But the problem is that we don't
	// want to enable CONFIG_MAGIC_SYSRQ during fuzzing.
	const (
		maxRetries = 10
		retrySleep = 30 * time.Second
		// Using more restrictive masks causes the crash utility to fail.
		cmd = "/usr/sbin/makedumpfile -F -c -d 0 /proc/vmcore"
	)
	if target.OS != targets.Linux {
		return fmt.Errorf("memory dump is only supported on linux")
	}

	var lastErr error
	for i := 0; i < maxRetries; i++ {
		err := extractKdumpInner(inst, path, cmd)
		if err == nil {
			return nil
		}
		lastErr = err
		log.Logf(0, "[instance #%d] failed to extract memory dump: %v",
			inst.Index(), err)
		time.Sleep(retrySleep)
	}
	return fmt.Errorf("failed to extract memory dump after %v attempts: %w", maxRetries, lastErr)
}

func extractKdumpInner(inst *vm.Instance, path, cmd string) error {
	// We need a long timeout for dump extraction, it can be gigabytes.
	// 1 hour should be enough for typical scenarios.
	ctx, cancel := context.WithTimeout(context.Background(), time.Hour)
	defer cancel()

	outc, errc, err := inst.RunStream(ctx, cmd)
	if err != nil {
		return fmt.Errorf("failed to start command: %w", err)
	}

	f, err := os.Create(path)
	if err != nil {
		return fmt.Errorf("failed to create dump file: %w", err)
	}
	defer f.Close()

	for {
		select {
		case chunk, ok := <-outc:
			if !ok {
				outc = nil
				continue
			}
			if chunk.Type != vmimpl.OutputStdout {
				// Filter out console and stderr.
				continue
			}
			if _, err := f.Write(chunk.Data); err != nil {
				return fmt.Errorf("failed to write to dump file: %w", err)
			}
		case err := <-errc:
			return err
		case <-ctx.Done():
			return ctx.Err()
		}
	}
	return nil
}
