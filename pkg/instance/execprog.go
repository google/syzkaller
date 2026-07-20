// Copyright 2022 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package instance

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"regexp"
	"strconv"
	"time"

	"github.com/google/syzkaller/pkg/csource"
	"github.com/google/syzkaller/pkg/log"
	"github.com/google/syzkaller/pkg/mgrconfig"
	"github.com/google/syzkaller/pkg/osutil"
	"github.com/google/syzkaller/pkg/report"
	"github.com/google/syzkaller/prog"
	"github.com/google/syzkaller/sys/targets"
	"github.com/google/syzkaller/vm"
	"github.com/google/syzkaller/vm/vmimpl"
)

type ExecutorLogger func(int, string, ...any)

type OptionalConfig struct {
	Logf               ExecutorLogger
	OldFlagsCompatMode bool
	BeforeContextLen   int
	StraceBin          string
}

type ExecProgInstance struct {
	execprogBin string
	executorBin string
	reporter    *report.Reporter
	mgrCfg      *mgrconfig.Config
	VMInstance  *vm.Instance
	OptionalConfig
}

type RunResult struct {
	Output   []byte
	Report   *report.Report
	Duration time.Duration
	Coverage [][]uint64
	// Path to a local file with the memory dump extracted from the VM.
	// It's populated after a crash if MemoryDump was enabled in RunOptions.
	// Empty if no dump was extracted.
	MemoryDump string
}

var crashKernelCmdlineRe = regexp.MustCompile(`(?i)command line:.*elfcorehdr=`)

// CanExtractMemoryDump returns true if /proc/vmcore may be available in the VM.
func CanExtractMemoryDump(rep *report.Report) bool {
	return rep != nil && (rep.Panicked || crashKernelCmdlineAfterReport(rep))
}

func crashKernelCmdlineAfterReport(rep *report.Report) bool {
	if rep.EndPos < 0 || rep.EndPos > len(rep.Output) {
		return false
	}
	for _, line := range bytes.Split(rep.Output[rep.EndPos:], []byte{'\n'}) {
		if crashKernelCmdlineRe.Match(line) {
			return true
		}
	}
	return false
}

const (
	// It's reasonable to expect that tools/syz-execprog should not normally
	// return a non-zero exit code.
	SyzExitConditions = vm.ExitTimeout | vm.ExitNormal
	binExitConditions = vm.ExitTimeout | vm.ExitNormal | vm.ExitError
)

func SetupExecProg(vmInst *vm.Instance, mgrCfg *mgrconfig.Config, reporter *report.Reporter,
	opt *OptionalConfig) (*ExecProgInstance, error) {
	var err error
	execprogBin := mgrCfg.SysTarget.ExecprogBin
	if execprogBin == "" {
		execprogBin, err = vmInst.Copy(mgrCfg.ExecprogBin)
		if err != nil {
			return nil, &TestError{Title: fmt.Sprintf("failed to copy syz-execprog to VM: %v", err)}
		}
	}
	executorBin := mgrCfg.SysTarget.ExecutorBin
	if executorBin == "" {
		executorBin, err = vmInst.Copy(mgrCfg.ExecutorBin)
		if err != nil {
			return nil, &TestError{Title: fmt.Sprintf("failed to copy syz-executor to VM: %v", err)}
		}
	}
	ret := &ExecProgInstance{
		execprogBin: execprogBin,
		executorBin: executorBin,
		reporter:    reporter,
		mgrCfg:      mgrCfg,
		VMInstance:  vmInst,
	}
	if opt != nil {
		ret.OptionalConfig = *opt
		if !mgrCfg.StraceBinOnTarget && ret.StraceBin != "" {
			var err error
			ret.StraceBin, err = vmInst.Copy(ret.StraceBin)
			if err != nil {
				return nil, &TestError{Title: fmt.Sprintf("failed to copy strace bin: %v", err)}
			}
		}
	}
	if ret.Logf == nil {
		ret.Logf = func(int, string, ...any) {}
	}
	return ret, nil
}

func CreateExecProgInstance(vmPool *vm.Pool, vmIndex int, mgrCfg *mgrconfig.Config,
	reporter *report.Reporter, opt *OptionalConfig) (*ExecProgInstance, error) {
	vmInst, err := vmPool.Create(context.Background(), vmIndex)
	if err != nil {
		return nil, fmt.Errorf("failed to create VM: %w", err)
	}
	ret, err := SetupExecProg(vmInst, mgrCfg, reporter, opt)
	if err != nil {
		vmInst.Close()
		return nil, err
	}
	return ret, nil
}

func (inst *ExecProgInstance) runCommand(command string, opts RunOptions) (*RunResult, error) {
	start := time.Now()

	var prefixOutput []byte
	if inst.StraceBin != "" {
		filterCalls := ""
		switch inst.mgrCfg.SysTarget.OS {
		case targets.Linux:
			// wait4 and nanosleep generate a lot of noise, especially when running syz-executor.
			// We cut them on the VM side in order to decrease load on the network and to use
			// the limited buffer size wisely.
			filterCalls = ` -e \!wait4,clock_nanosleep,nanosleep`
		}
		command = inst.StraceBin + filterCalls + ` -s 100 -x -f ` + command
		prefixOutput = []byte(fmt.Sprintf("%s\n\n<...>\n", command))
	}
	optionalBeforeContext := func(*vm.RunOptions) {}
	if inst.BeforeContextLen != 0 {
		optionalBeforeContext = vm.WithBeforeContext(inst.BeforeContextLen)
	}
	ctxTimeout, cancel := context.WithTimeout(context.Background(), opts.Duration)
	defer cancel()
	output, reps, err := inst.VMInstance.Run(ctxTimeout, inst.reporter, command,
		vm.WithExitCondition(opts.ExitConditions),
		optionalBeforeContext,
	)
	var rep *report.Report
	if len(reps) > 0 {
		rep = reps[0]
	}
	if ctxTimeout.Err() == context.DeadlineExceeded || errors.Is(err, context.DeadlineExceeded) {
		output = append(output, []byte(fmt.Sprintf("\n[host] Command execution timed out after %v\n", opts.Duration))...)
		err = nil
	}
	if err != nil {
		return nil, fmt.Errorf("failed to run command in VM: %w", err)
	}
	if rep == nil {
		inst.Logf(2, "program did not crash")
	} else {
		if err := inst.reporter.Symbolize(rep); err != nil {
			inst.Logf(0, "failed to symbolize report: %v", err)
		}
		inst.Logf(2, "program crashed: %v", rep.Title)
	}
	res := &RunResult{
		Output:   append(prefixOutput, output...),
		Report:   rep,
		Duration: time.Since(start),
	}
	if opts.MemoryDump {
		res.MemoryDump, err = inst.extractDump(rep, opts)
		if err != nil {
			return nil, err
		}
	}
	return res, nil
}

func (inst *ExecProgInstance) extractDump(rep *report.Report,
	opts RunOptions) (string, error) {
	if !CanExtractMemoryDump(rep) {
		return "", nil
	}
	dumpPath, err := osutil.TempFileIn(opts.MemoryDumpDir, "syz-dump-*")
	if err != nil {
		return "", err
	}
	if err := ExtractMemoryDump(inst.VMInstance, inst.mgrCfg.SysTarget, dumpPath); err != nil {
		log.Errorf("failed to extract memory dump: %v", err)
		os.Remove(dumpPath)
		return "", nil
	}

	return dumpPath, nil
}

func (inst *ExecProgInstance) runBinary(bin string, opts RunOptions) (*RunResult, error) {
	bin, err := inst.VMInstance.Copy(bin)
	if err != nil {
		return nil, &TestError{Title: fmt.Sprintf("failed to copy binary to VM: %v", err)}
	}
	opts.ExitConditions = binExitConditions
	return inst.runCommand(bin, opts)
}

type RunOptions struct {
	Opts            csource.Options
	Duration        time.Duration
	CollectCoverage bool
	// If ExitConditions is empty, RunSyzProg() will assume instance.SyzExitConditions.
	// RunCProg() always runs with binExitConditions.
	ExitConditions vm.ExitCondition
	// If MemoryDump is set, the package will attempt to extract a memory dump from the VM.
	MemoryDump bool
	// If not empty, the memory dump file will be created in the given location.
	// If empty, the system default temporary directory will be used.
	MemoryDumpDir string
}

func (inst *ExecProgInstance) RunCProg(p *prog.Prog, opts RunOptions) (*RunResult, error) {
	src, err := csource.Write(p, opts.Opts)
	if err != nil {
		return nil, err
	}
	inst.Logf(2, "testing compiled C program (duration=%v, %+v): %s",
		opts.Duration, opts.Opts, p)
	return inst.RunCProgRaw(src, p.Target, opts)
}

func (inst *ExecProgInstance) RunCProgRaw(src []byte, target *prog.Target, opts RunOptions) (*RunResult, error) {
	bin, err := csource.BuildNoWarn(target, src)
	if err != nil {
		return nil, err
	}
	defer os.Remove(bin)
	return inst.runBinary(bin, opts)
}

func (inst *ExecProgInstance) RunSyzProgFile(progFile string, opts RunOptions) (*RunResult, error) {
	coverFile := ""
	ncalls := 0
	if opts.CollectCoverage && inst.mgrCfg.TargetOS != "linux" {
		return nil, fmt.Errorf("coverage collection via ssh cat is only supported on Linux")
	}

	if opts.CollectCoverage {
		if opts.Opts.Repeat {
			return nil, fmt.Errorf("coverage retrieval is not supported when repeat is enabled")
		}
		progData, err := os.ReadFile(progFile)
		if err != nil {
			return nil, fmt.Errorf("failed to read prog file: %w", err)
		}
		_, ncalls, err = prog.CallSet(progData)
		if err != nil {
			return nil, fmt.Errorf("failed to parse prog: %w", err)
		}
		coverFile = fmt.Sprintf("/tmp/syz-cover-%d", time.Now().UnixNano())
	}
	vmProgFile, err := inst.VMInstance.Copy(progFile)
	if err != nil {
		return nil, &TestError{Title: fmt.Sprintf("failed to copy prog to VM: %v", err)}
	}
	command := ExecprogCmd(inst.execprogBin, inst.executorBin, inst.mgrCfg.TargetOS, inst.mgrCfg.TargetArch,
		inst.mgrCfg.Type, opts.Opts, !inst.OldFlagsCompatMode, inst.mgrCfg.Timeouts.Slowdown, coverFile, vmProgFile)
	res, err := inst.runCommand(command, opts)
	if err != nil {
		return nil, err
	}
	if coverFile != "" {
		coverage, err := inst.retrieveCoverageFiles(coverFile, ncalls)
		if err != nil {
			return nil, err
		}
		res.Coverage = coverage
	}
	return res, nil
}

func (inst *ExecProgInstance) RunSyzProg(syzProg []byte, opts RunOptions) (*RunResult, error) {
	progFile, err := osutil.WriteTempFile(syzProg)
	if err != nil {
		return nil, err
	}
	defer os.Remove(progFile)

	if opts.ExitConditions == 0 {
		opts.ExitConditions = SyzExitConditions
	}
	return inst.RunSyzProgFile(progFile, opts)
}

func parseCoverageData(data []byte) ([]uint64, error) {
	var res []uint64
	for s := bufio.NewScanner(bytes.NewReader(data)); s.Scan(); {
		v, err := strconv.ParseUint(s.Text(), 0, 64)
		if err != nil {
			return nil, err
		}
		res = append(res, v)
	}
	return res, nil
}

// runStreamAndCollectStdout runs a command on the VM and streams its
// stdout to the provided writer. Use a file for large outputs (like memory
// dumps) to avoid OOMs, and a buffer for small outputs.
// This function is also used by dump.go.
// If this function returns an error, you MUST NOT reuse the same vm for
// any further command execution since the outc channel might be constantly
// drained, making the output incomplete.
func runStreamAndCollectStdout(ctx context.Context, inst *vm.Instance, command string, w io.Writer) error {
	// In case of write error to w, we want to cancel the command
	// execution, so that we don't keep getting chunks written to the channel.
	cancellableCtx, cancel := context.WithCancel(ctx)

	outc, errc, err := inst.RunStream(cancellableCtx, command)
	if err != nil {
		cancel()
		return err
	}

	// A deadlock can happen if this function returns early while outc is still active.
	// If the channel buffer fills up, decoders in merger.go will block trying to send to outc.
	// Consequently, merger.Wait() in Multiplex will block forever waiting for decoders to finish.
	// Draining the channel in a background goroutine unblocks the decoders and breaks the deadlock.
	defer func() {
		if outc != nil {
			go func() {
				for range outc {
				}
			}()
		}
	}()
	// First cancel the execution before draining.
	defer cancel()

	writeChunk := func(chunk vmimpl.Chunk) error {
		// Filter out console and stderr by only taking from stdout.
		if chunk.Type != vmimpl.OutputStdout {
			return nil
		}
		if _, err := w.Write(chunk.Data); err != nil {
			return fmt.Errorf("failed to write output: %w", err)
		}
		return nil
	}

	for {
		select {
		case chunk, ok := <-outc:
			if !ok {
				outc = nil
				continue
			}
			if err := writeChunk(chunk); err != nil {
				return err
			}
		case err := <-errc:
			errc = nil
			// Command finished. Drain outc to get any remaining command
			// output. The deferred drain is not run here, because we still
			// need the output.
			n := len(outc)
			for range n {
				if err := writeChunk(<-outc); err != nil {
					return err
				}
			}
			// In case of race between context cancellation and receiving
			// command error, prioritize context error.
			if ctx.Err() != nil {
				return ctx.Err()
			}
			outc = nil
			return err
		case <-ctx.Done():
			return ctx.Err()
		}
	}
}

func (inst *ExecProgInstance) runStreamAndCollectStdoutToBuf(ctx context.Context, command string) ([]byte, error) {
	var buf bytes.Buffer
	err := runStreamAndCollectStdout(ctx, inst.VMInstance, command, &buf)
	return buf.Bytes(), err
}

func (inst *ExecProgInstance) retrieveCoverageFiles(vmCoverFilePrefix string, ncalls int) ([][]uint64, error) {
	// syz-execprog generates these coverage files during execution (see tools/syz-execprog/execprog.go).
	// Because we run a single program exactly once (opts.Repeat is false), it generates:
	// - Per-call coverage: <prefix>_prog1.<call_index>
	// - Extra coverage (background threads): <prefix>_prog1.extra
	var files []string
	for i := range ncalls {
		files = append(files, fmt.Sprintf("%s_prog1.%d", vmCoverFilePrefix, i))
	}
	files = append(files, fmt.Sprintf("%s_prog1.extra", vmCoverFilePrefix))

	coverage := make([][]uint64, 0, ncalls)
	for _, file := range files {
		catCmd := "cat " + file + " 2>/dev/null || true"
		catCtx, cancel := context.WithTimeout(context.Background(), time.Minute)
		catOutput, err := inst.runStreamAndCollectStdoutToBuf(catCtx, catCmd)
		cancel()
		if err != nil {
			return nil, fmt.Errorf("failed to read coverage file %s in VM: %w", file, err)
		}

		cover, err := parseCoverageData(catOutput)
		if err != nil {
			return nil, fmt.Errorf("failed to parse cover data from %s: %w", file, err)
		}
		coverage = append(coverage, cover)
	}

	return coverage, nil
}
