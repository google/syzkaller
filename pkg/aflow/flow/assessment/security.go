// Copyright 2026 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package assessment

import (
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"

	"github.com/google/syzkaller/pkg/aflow"
	"github.com/google/syzkaller/pkg/aflow/action/actionsyzlang"
	"github.com/google/syzkaller/pkg/aflow/action/kernel"
	"github.com/google/syzkaller/pkg/aflow/ai"
	"github.com/google/syzkaller/pkg/aflow/flow/common"
	"github.com/google/syzkaller/pkg/aflow/tool/codesearcher"
	"github.com/google/syzkaller/pkg/aflow/tool/gitlog"
	"github.com/google/syzkaller/pkg/aflow/tool/grepper"
	"github.com/google/syzkaller/pkg/email"
)

type assessmentSecurityInputs struct {
	TargetOS     string
	TargetArch   string
	TargetVMArch string `json:",omitempty"`
	CrashReport  string
	ReproSyz     string
	ReproC       string
	KernelRepo   string
	KernelCommit string
	KernelConfig string
}

type rootCauseOutputs struct {
	RootCauseSummary   string   `jsonschema:"Short (up to 4-5 sentences) summary of the root cause and its direct impact."`
	RootCauseFiles     []string `jsonschema:"Kernel source file paths containing the bug."`
	MemoryCorruption   bool     `jsonschema:"Analysis result: Memory Corruption."`
	InfoLeak           string   `jsonschema:"Analysis result: Information Leak (none, pointers, or arbitrary)."`
	RawDenialOfService bool     `jsonschema:"Analysis result: Denial Of Service."`
	IsNetCandidate     bool     `jsonschema:"Analysis result: Networking Candidate."`
	IsKVMCandidate     bool     `jsonschema:"Analysis result: Virtualization / KVM Candidate."`
}

type rootCauseValidationState struct {
	KernelSrc string
}

func validateRootCauseOutputs(ctx *aflow.Context, state rootCauseValidationState, args rootCauseOutputs) (
	rootCauseOutputs, error) {
	args.RootCauseSummary = strings.TrimSpace(args.RootCauseSummary)
	if args.RootCauseSummary == "" {
		return args, aflow.BadCallError("RootCauseSummary must not be empty")
	}
	if len(args.RootCauseFiles) == 0 {
		return args, aflow.BadCallError("RootCauseFiles must not be empty")
	}
	root, err := os.OpenRoot(state.KernelSrc)
	if err != nil {
		return args, err
	}
	defer root.Close()

	var cleaned, errs []string
	for _, f := range args.RootCauseFiles {
		clean := filepath.Clean(strings.TrimLeft(strings.TrimSpace(f), "/"))
		if clean == "." || clean == "" {
			errs = append(errs, fmt.Sprintf("invalid file path %q in RootCauseFiles", f))
			continue
		}
		info, err := root.Stat(clean)
		if err != nil {
			errs = append(errs, fmt.Sprintf("file %q does not exist in the kernel source tree", clean))
			continue
		}
		if info.IsDir() {
			errs = append(errs, fmt.Sprintf("%q is a directory, expected a file in RootCauseFiles", clean))
			continue
		}
		if !slices.Contains(cleaned, clean) {
			cleaned = append(cleaned, clean)
		}
	}
	if len(cleaned) == 0 {
		return args, aflow.BadCallError("%s", strings.Join(errs, "; "))
	}
	args.RootCauseFiles = cleaned
	switch args.InfoLeak {
	case ai.InfoLeakNone, ai.InfoLeakPointers, ai.InfoLeakArbitrary:
	default:
		return args, aflow.BadCallError("InfoLeak must be one of %q, %q, %q (got %q)",
			ai.InfoLeakNone, ai.InfoLeakPointers, ai.InfoLeakArbitrary, args.InfoLeak)
	}
	return args, nil
}

var validLinuxCaps = map[string]bool{
	// keep-sorted start
	"CAP_AUDIT_CONTROL":      true,
	"CAP_AUDIT_READ":         true,
	"CAP_AUDIT_WRITE":        true,
	"CAP_BLOCK_SUSPEND":      true,
	"CAP_BPF":                true,
	"CAP_CHECKPOINT_RESTORE": true,
	"CAP_CHOWN":              true,
	"CAP_DAC_OVERRIDE":       true,
	"CAP_DAC_READ_SEARCH":    true,
	"CAP_FOWNER":             true,
	"CAP_FSETID":             true,
	"CAP_IPC_LOCK":           true,
	"CAP_IPC_OWNER":          true,
	"CAP_KILL":               true,
	"CAP_LEASE":              true,
	"CAP_LINUX_IMMUTABLE":    true,
	"CAP_MAC_ADMIN":          true,
	"CAP_MAC_OVERRIDE":       true,
	"CAP_MKNOD":              true,
	"CAP_NET_ADMIN":          true,
	"CAP_NET_BIND_SERVICE":   true,
	"CAP_NET_BROADCAST":      true,
	"CAP_NET_RAW":            true,
	"CAP_PERFMON":            true,
	"CAP_SETFCAP":            true,
	"CAP_SETGID":             true,
	"CAP_SETPCAP":            true,
	"CAP_SETUID":             true,
	"CAP_SYSLOG":             true,
	"CAP_SYS_ADMIN":          true,
	"CAP_SYS_BOOT":           true,
	"CAP_SYS_CHROOT":         true,
	"CAP_SYS_MODULE":         true,
	"CAP_SYS_NICE":           true,
	"CAP_SYS_PACCT":          true,
	"CAP_SYS_PTRACE":         true,
	"CAP_SYS_RAWIO":          true,
	"CAP_SYS_RESOURCE":       true,
	"CAP_SYS_TIME":           true,
	"CAP_SYS_TTY_CONFIG":     true,
	"CAP_WAKE_ALARM":         true,
	// keep-sorted end
}

type localReachabilityOutputs struct {
	Unprivileged       bool     `jsonschema:"Analysis result: Unprivileged."`
	UserNamespace      bool     `jsonschema:"Analysis result: User Namespace."`
	RequiredCaps       []string `jsonschema:"Analysis result: Required Capabilities."`
	PeripheralTrigger  bool     `jsonschema:"Analysis result: Peripheral Trigger."`
	FilesystemTrigger  bool     `jsonschema:"Analysis result: Malicious Filesystem Trigger."`
	RawFuzzingArtifact bool     `jsonschema:"Analysis result: Fuzzing Or Testing Artifact."`
}

func validateLocalReachabilityOutputs(ctx *aflow.Context, state struct{},
	args localReachabilityOutputs) (localReachabilityOutputs, error) {
	if args.Unprivileged && !args.UserNamespace {
		return args, aflow.BadCallError("UserNamespace must be true when Unprivileged is true")
	}
	if args.Unprivileged && len(args.RequiredCaps) != 0 {
		return args, aflow.BadCallError("RequiredCaps must be empty when Unprivileged is true")
	}
	var caps []string
	for _, c := range args.RequiredCaps {
		c = strings.ToUpper(strings.TrimSpace(c))
		if !validLinuxCaps[c] {
			return args, aflow.BadCallError("unknown Linux capability %q in RequiredCaps", c)
		}
		if !slices.Contains(caps, c) {
			caps = append(caps, c)
		}
	}
	slices.Sort(caps)
	args.RequiredCaps = caps
	if args.RawFuzzingArtifact && (args.Unprivileged || args.PeripheralTrigger || args.FilesystemTrigger) {
		return args, aflow.BadCallError(
			"RawFuzzingArtifact cannot be true when Unprivileged, PeripheralTrigger, or FilesystemTrigger is true")
	}
	return args, nil
}

type netReachabilityOutputs struct {
	NetworkTrigger    bool `jsonschema:"Analysis result: Ethernet Network Trigger."`
	NetworkNeedsSetup bool `jsonschema:"Analysis result: Ethernet Network Trigger Needs Setup."`
	RemoteTrigger     bool `jsonschema:"Analysis result: Other Remote Trigger."`
}

func validateNetReachabilityOutputs(ctx *aflow.Context, state struct{}, args netReachabilityOutputs) (
	netReachabilityOutputs, error) {
	if args.NetworkNeedsSetup && !args.NetworkTrigger {
		return args, aflow.BadCallError("NetworkNeedsSetup can only be true when NetworkTrigger is true")
	}
	return args, nil
}

type kvmReachabilityOutputs struct {
	VMGuestTrigger bool `jsonschema:"Analysis result: VM Guest Trigger."`
	VMHostTrigger  bool `jsonschema:"Analysis result: VM Host Trigger."`
}

var combineAssessment = aflow.NewFuncAction("combine-assessment", combineAssessmentFunc)

type combineAssessmentArgs struct {
	RootCauseAnalysis         string
	LocalReachabilityAnalysis string
	NetReachabilityAnalysis   string
	KVMReachabilityAnalysis   string
	MemoryCorruption          bool
	InfoLeak                  string
	RawDenialOfService        bool
	RawFuzzingArtifact        bool
	NetworkTrigger            bool
	RemoteTrigger             bool
	VMGuestTrigger            bool
	VMHostTrigger             bool
}

type combineAssessmentResult struct {
	Explanation     string
	Exploitable     bool
	DenialOfService bool
	FuzzingArtifact bool
}

func combineAssessmentFunc(ctx *aflow.Context, args combineAssessmentArgs) (combineAssessmentResult, error) {
	var sb strings.Builder
	fmt.Fprintf(&sb, "Root Cause Analysis:\n\n%s\n\nLocal Reachability Analysis:\n\n%s",
		strings.TrimSpace(args.RootCauseAnalysis), strings.TrimSpace(args.LocalReachabilityAnalysis))
	if netAnalysis := strings.TrimSpace(args.NetReachabilityAnalysis); netAnalysis != "" {
		fmt.Fprintf(&sb, "\n\nNetwork Reachability Analysis:\n\n%s", netAnalysis)
	}
	if kvmAnalysis := strings.TrimSpace(args.KVMReachabilityAnalysis); kvmAnalysis != "" {
		fmt.Fprintf(&sb, "\n\nVirtualization Reachability Analysis:\n\n%s", kvmAnalysis)
	}
	fuzzingArtifact := args.RawFuzzingArtifact && !args.NetworkTrigger && !args.RemoteTrigger &&
		!args.VMGuestTrigger && !args.VMHostTrigger
	exploitable := !fuzzingArtifact && (args.MemoryCorruption || args.InfoLeak != ai.InfoLeakNone)
	dos := !fuzzingArtifact && args.RawDenialOfService
	return combineAssessmentResult{
		Explanation:     email.WordWrap(sb.String(), 80),
		Exploitable:     exploitable,
		DenialOfService: dos,
		FuzzingArtifact: fuzzingArtifact,
	}, nil
}

func init() {
	reachabilityTools := aflow.Tools(codesearcher.Tools, grepper.Tool, kernel.ToolConfigGrep)
	rootCauseTools := aflow.Tools(reachabilityTools, gitlog.Tools)
	aflow.Register[assessmentSecurityInputs, ai.AssessmentSecurityOutputs](
		ai.WorkflowAssessmentSecurity,
		"assess if a syzkaller bug is exploitable and what attack surfaces can reach it",
		&aflow.Flow{
			Root: aflow.Pipeline(
				actionsyzlang.CreateSimplifiedCRepro,
				kernel.Checkout,
				kernel.Build,
				codesearcher.PrepareIndex,
				&aflow.LLMAgent{
					Name:        "root-cause",
					Model:       aflow.DeepReasoningModel,
					Reply:       "RootCauseAnalysis",
					Outputs:     aflow.ValidatedLLMOutputs(validateRootCauseOutputs),
					Instruction: common.Prompt(prompts, "prompts/root_cause_instruction.md"),
					Prompt:      rootCausePrompt,
					Tools:       rootCauseTools,
				},
				&aflow.LLMAgent{
					Name:        "local-reachability",
					Model:       aflow.DeepReasoningModel,
					Reply:       "LocalReachabilityAnalysis",
					Outputs:     aflow.ValidatedLLMOutputs(validateLocalReachabilityOutputs),
					Instruction: common.Prompt(prompts, "prompts/local_reachability_instruction.md"),
					Prompt:      reachabilityPrompt,
					Tools:       reachabilityTools,
				},
				&aflow.If{
					Condition: "IsNetCandidate",
					Do: &aflow.LLMAgent{
						Name:        "net-reachability",
						Model:       aflow.DeepReasoningModel,
						Reply:       "NetReachabilityAnalysis",
						Outputs:     aflow.ValidatedLLMOutputs(validateNetReachabilityOutputs),
						Instruction: common.Prompt(prompts, "prompts/net_reachability_instruction.md"),
						Prompt:      reachabilityPrompt,
						Tools:       reachabilityTools,
					},
				},
				&aflow.If{
					Condition: "IsKVMCandidate",
					Do: &aflow.LLMAgent{
						Name:        "kvm-reachability",
						Model:       aflow.DeepReasoningModel,
						Reply:       "KVMReachabilityAnalysis",
						Outputs:     aflow.LLMOutputs[kvmReachabilityOutputs](),
						Instruction: common.Prompt(prompts, "prompts/kvm_reachability_instruction.md"),
						Prompt:      reachabilityPrompt,
						Tools:       reachabilityTools,
					},
				},
				combineAssessment,
			),
		},
	)
}

const rootCausePrompt = `
The kernel bug report is:

{{.CrashReport}}

{{if .SimplifiedCRepro}}

It is reproducible with the following program.
Keep in mind that it may lack the precise threading, sandboxing, and some arguments of a working reproducer.
But it should give an idea of the involved syscalls.

{{.SimplifiedCRepro}}
{{end}}
`

const reachabilityPrompt = rootCausePrompt + `
The root-cause analysis of the bug is:

{{.RootCauseAnalysis}}
`
