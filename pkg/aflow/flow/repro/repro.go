// Copyright 2026 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

// Package repro provides workflows for reproducing kernel crashes from bug descriptions.
package repro

import (
	"encoding/json"

	"github.com/google/syzkaller/docs"
	"github.com/google/syzkaller/pkg/aflow"
	"github.com/google/syzkaller/pkg/aflow/action/crash"
	"github.com/google/syzkaller/pkg/aflow/action/kernel"
	"github.com/google/syzkaller/pkg/aflow/ai"
	"github.com/google/syzkaller/pkg/aflow/flow/common"
	"github.com/google/syzkaller/pkg/aflow/tool/codesearcher"
	"github.com/google/syzkaller/pkg/aflow/tool/syzlang"
	"github.com/google/syzkaller/pkg/csource"
	"github.com/google/syzkaller/pkg/mgrconfig"
	"github.com/google/syzkaller/prog"
	"github.com/google/syzkaller/sys/targets"
)

type ReproInputs struct {
	AgentName    string
	TargetOS     string
	TargetArch   string
	BugTitle     string
	CrashReport  string
	KernelRepo   string
	KernelCommit string
	KernelConfig string
	Image        string
	Type         string
	VM           json.RawMessage
	Syzkaller    string
	StraceBin    string
}

func init() {
	aflow.Register[ReproInputs, ai.ReproOutputs](
		ai.WorkflowRepro,
		"reproduce a kernel crash and generate a syzlang program",
		&aflow.Flow{
			Consts: map[string]any{
				"SyzkallerCommit":              prog.GitRevisionBase,
				"DescriptionFiles":             syzlang.DescriptionFiles(),
				"DocProgramSyntax":             docs.ProgramSyntax,
				"DocSyscallDescriptionsSyntax": docs.SyscallDescriptionsSyntax,
				"ReproC":                       "", // is needed by crash.Reproduce
				"NeedStrace":                   false,
			},
			Root: aflow.Pipeline(
				kernel.Checkout,
				kernel.Build,
				codesearcher.PrepareIndex,
				&aflow.LLMAgent{
					Name:    "crash-repro-finder",
					Model:   aflow.BestExpensiveModel,
					Outputs: aflow.ValidatedLLMOutputs[ReproFinderResult, ReproFinderState](formatReproFinderOutputs),
					Tools: aflow.Tools(
						common.CodeAccessTools,
						syzlang.ReadDescription,
						syzlang.Reproduce,
						syzlang.Coverage,
					),
					TaskType:    aflow.FormalReasoningTask,
					Instruction: reproInstruction,
					Prompt:      reproPrompt,
				},
				generateReproOpts,
				crash.Reproduce,
				aflow.NewFuncAction("compare", func(ctx *aflow.Context,
					args struct {
						BugTitle           string
						ReproducedBugTitle string
						// This is an unused output of crash.Reproduce.
						// TODO: figure out how to handle such outputs better.
						ReproducedFaultInjection string
					}) (struct{ Reproduced bool }, error) {
					return struct{ Reproduced bool }{args.BugTitle == args.ReproducedBugTitle}, nil
				}),
			),
		},
	)
}

type ReproFinderResult struct {
	Sandbox  string `jsonschema:"Sandbox to use for execution (none/setuid/namespace/android)."`
	ReproSyz string `jsonschema:"Valid syzkaller reproducer program without triple backticks."`
}

type ReproFinderState struct {
	TargetOS   string
	TargetArch string
}

func formatReproFinderOutputs(ctx *aflow.Context, state ReproFinderState,
	res ReproFinderResult) (ReproFinderResult, error) {
	switch res.Sandbox {
	case "", "none", "setuid", "namespace", "android":
	default:
		return res, aflow.BadCallError("unsupported sandbox type %q", res.Sandbox)
	}
	pt, err := prog.GetTarget(state.TargetOS, state.TargetArch)
	if err != nil {
		return res, err
	}
	p, err := pt.Deserialize([]byte(res.ReproSyz), prog.NonStrict)
	if err != nil {
		return res, aflow.BadCallError("failed to deserialize syzkaller program: %v", err)
	}
	if len(p.Calls) == 0 {
		return res, aflow.BadCallError("the generated syzkaller program is empty (contains 0 system calls)")
	}
	res.ReproSyz = string(p.Serialize())
	return res, nil
}

var generateReproOpts = aflow.NewFuncAction("generate-repro-opts", func(_ *aflow.Context, args struct {
	TargetArch string
	Sandbox    string
}) (struct{ ReproOpts string }, error) {
	cfg := mgrconfig.DefaultValues()
	cfg.RawTarget = targets.Linux + "/" + args.TargetArch
	if args.Sandbox != "" {
		cfg.Sandbox = args.Sandbox
	}
	if err := mgrconfig.SetTargets(cfg); err != nil {
		return struct{ ReproOpts string }{}, err
	}
	cfg.Timeouts = cfg.SysTarget.Timeouts(1)
	opts := csource.DefaultOpts(cfg)
	return struct{ ReproOpts string }{string(opts.Serialize())}, nil
})

const reproInstruction = `
You are an expert in Linux kernel fuzzing. Your goal is to write a syzkaller program to trigger a specific bug.

Execution sandboxes ('Sandbox' output field):
- "none": Runs test processes as root without Linux namespace isolation (PID, Net, IPC, User).
- "setuid": Runs test processes under unprivileged user accounts (drops root privileges and capabilities).
- "namespace": Runs test processes inside isolated Linux namespaces
  (CLONE_NEWNS, CLONE_NEWUTS, CLONE_NEWIPC, CLONE_NEWPID, CLONE_NEWNET,
  CLONE_NEWUSER) with isolated network devices (loopback, tun, etc.).
  Use this for network, IPC, or namespace bugs.
- "android": Simulates Android application privilege and SELinux restrictions (drops privileges to Android UIDs/GIDs).

Document about syzkaller program syntax:
===
{{.DocProgramSyntax}}
===

Document about syzlang system call descriptions syntax:
===
{{.DocSyscallDescriptionsSyntax}}
===
` + common.InstructionDontMakeAssumptionsAboutSourceCode

const reproPrompt = `
Bug title: {{.BugTitle}}

The bug report to reproduce:
{{.CrashReport}}

The list of existing description files:
{{range $file := .DescriptionFiles}}{{$file}}
{{end}}
`
